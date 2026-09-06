#!/usr/bin/env node
// splitNSP progress must be byte-weighted (a 2 MiB title and a 256 KiB title do not
// get equal 1/2 slots), monotonic, end at exactly 1.0, and skipped groups must
// still advance the bar. Also guards the copy: output members byte-identical to input.
import { PFS0, PFS0Writer } from '../fs/pfs0.js';
import { BufferReader } from '../fs/ncz.js';
import { splitNSP } from '../fs/split.js';
import { AesCtr } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';

function hexToBytes(hex) {
    const b = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
    return b;
}

function bytesToHex(bytes) {
    const r = [];
    for (const b of bytes) r.push(b.toString(16).padStart(2, '0'));
    return r.join('');
}

function tweakBytesFor(sector) {
    const buf = new Uint8Array(16);
    for (let i = 15; i >= 0; i--) {
        buf[i] = sector & 0xFF;
        sector = Math.floor(sector / 256);
    }
    return buf;
}

function gf128MulIn(tweak) {
    let carry = 0;
    for (let i = 0; i < 16; i++) {
        const newCarry = (tweak[i] >>> 7) & 1;
        const shifted = ((tweak[i] << 1) | carry) & 0xff;
        carry = newCarry;
        tweak[i] = shifted;
    }
    if (carry) tweak[0] ^= 0x87;
    return tweak;
}

function xtsEncrypt(data, key) {
    const k1 = key.subarray(0, 16);
    const k2 = key.subarray(16, 32);
    const aesEncData = new AesEcb(k1);
    const aesEncTweak = new AesEcb(k2);
    const result = new Uint8Array(data.length);
    const xored = new Uint8Array(16);
    let sector = 0;
    for (let offset = 0; offset < data.length; offset += 0x200) {
        const chunkSize = Math.min(0x200, data.length - offset);
        const tweak = aesEncTweak.encryptBlock(tweakBytesFor(sector));
        for (let i = 0; i + 16 <= chunkSize; i += 16) {
            const block = data.subarray(offset + i, offset + i + 16);
            for (let j = 0; j < 16; j++) xored[j] = block[j] ^ tweak[j];
            const enc = aesEncData.encryptBlock(xored);
            for (let j = 0; j < 16; j++) result[offset + i + j] = enc[j] ^ tweak[j];
            gf128MulIn(tweak);
        }
        sector++;
    }
    return result;
}

async function buildNcaFile({ titleId, contentIndex, contentType, titleKeyDec, kak, headerKey, section }) {
    const h = new Uint8Array(0xC00);
    const v = new DataView(h.buffer);
    h[0x200] = 0x4E; h[0x201] = 0x43; h[0x202] = 0x41; h[0x203] = 0x33;
    h[0x205] = contentType;
    h[0x206] = 1;
    h[0x207] = 0;
    const sectionSize = section ? Math.ceil(section.data.length / 0x200) * 0x200 : 0;
    v.setBigUint64(0x208, section ? BigInt(section.offset + sectionSize) : 0x1000n, true);
    const tid = hexToBytes(titleId);
    for (let i = 0; i < 8; i++) h[0x210 + i] = tid[7 - i];
    v.setUint32(0x218, contentIndex, true);
    h[0x220] = 1;
    const plain = new Uint8Array(0x40);
    plain.set(titleKeyDec, 0x20);
    const aesEnc = new AesEcb(kak);
    h.set(aesEnc.encrypt(plain), 0x300);
    if (section) {
        const mediaOffset = section.offset / 0x200;
        v.setUint32(0x240, mediaOffset, true);
        v.setUint32(0x244, mediaOffset + sectionSize / 0x200, true);
        h[0x403] = 2; // fsType PFS0
        h[0x404] = 3; // cryptoType AES-CTR
        v.setBigUint64(0x440, 0n, true);
        v.setBigUint64(0x448, BigInt(section.data.length), true);
        h.set(section.nonce.slice(0, 8).reverse(), 0x540);
    }
    const enc = xtsEncrypt(h, headerKey);
    if (!section) return enc.slice(0, 0x1000);
    const padded = new Uint8Array(sectionSize);
    padded.set(section.data, 0);
    const file = new Uint8Array(section.offset + sectionSize);
    file.set(enc, 0);
    const ctr = new AesCtr(titleKeyDec, section.nonce);
    ctr.seek(section.offset);
    file.set(await ctr.encrypt(padded), section.offset);
    return file;
}

function buildCnmt({ titleId, version, titleType, contentEntries }) {
    const n = contentEntries.length;
    const tableOffset = 0x40;
    const total = 0x20 + tableOffset + n * 0x38;
    const d = new Uint8Array(total);
    const v = new DataView(d.buffer);
    const tid = hexToBytes(titleId);
    for (let i = 0; i < 8; i++) d[i] = tid[7 - i];
    v.setUint32(8, version, true);
    d[12] = titleType;
    v.setUint16(0x0E, tableOffset, true);
    v.setUint16(0x10, n, true);
    const cs = 0x20 + tableOffset;
    for (let i = 0; i < n; i++) {
        const off = cs + i * 0x38;
        const entry = contentEntries[i];
        const id = typeof entry === 'string' ? entry : entry.id;
        const type = typeof entry === 'string' ? 1 : (entry.type !== undefined ? entry.type : 1);
        d.set(hexToBytes(id), off + 32);
        v.setUint32(off + 48, 0x1000, true);
        d[off + 54] = type;
    }
    return d;
}

function buildCnmtSection(titleId, version, titleType, contentEntries, nonce) {
    const cnmtBin = buildCnmt({ titleId, version, titleType, contentEntries });
    const pfs0 = buildPfs0([{ name: 'cnmt.bin', data: cnmtBin }]);
    return { data: pfs0, nonce, offset: 0x1000 };
}

function buildPfs0(files) {
    const writer = new PFS0Writer();
    for (const f of files) writer.add(f.name, f.data.length);
    const header = writer.buildHeader();
    const buf = new Uint8Array(header.headerSize + files.reduce((s, f) => s + f.data.length, 0));
    buf.set(header.buffer, 0);
    for (let i = 0; i < files.length; i++) {
        buf.set(files[i].data, header.headerSize + writer.files[i].offset);
    }
    return buf;
}

function makeReader(data) {
    return new BufferReader(data);
}

let failures = 0;
function assert(cond, msg) {
    if (cond) console.log(`  ok - ${msg}`);
    else { failures++; console.log(`  FAIL - ${msg}`); }
}

function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

// --- Synthetic merged NSP: two title groups of very different sizes ---

const headerKey = new Uint8Array(32);
const kak = new Uint8Array(16);
const titleKeyDec = new Uint8Array(16);
for (let i = 0; i < 16; i++) {
    headerKey[i] = (i * 7 + 1) & 0xFF;
    headerKey[i + 16] = (i * 3 + 5) & 0xFF;
    kak[i] = (i * 5 + 2) & 0xFF;
    titleKeyDec[i] = (i * 11 + 9) & 0xFF;
}
const keys = {
    header_key: bytesToHex(headerKey),
    keyAreaKeys: [[bytesToHex(kak), null, null]],
};
const nonce = new Uint8Array(16);
for (let i = 0; i < 16; i++) nonce[i] = (i * 13 + 3) & 0xFF;

const progA = 'aaa10000000000000000000000000001';
const progB = 'bbb20000000000000000000000000002';

const progAData = await buildNcaFile({
    titleId: '0100AAA100000001', contentIndex: 0, contentType: 0,
    titleKeyDec, kak, headerKey,
    section: { data: new Uint8Array(0x200000).fill(0xA5), nonce, offset: 0x1000 },
});
const metaAData = await buildNcaFile({
    titleId: '0100AAA100000080', contentIndex: 0, contentType: 1,
    titleKeyDec, kak, headerKey,
    section: buildCnmtSection('0100AAA100000001', 0, 0x80, [progA], nonce),
});
const progBData = await buildNcaFile({
    titleId: '0100BBB200000002', contentIndex: 0, contentType: 0,
    titleKeyDec, kak, headerKey,
    section: { data: new Uint8Array(0x40000).fill(0x5A), nonce, offset: 0x1000 },
});
const metaBData = await buildNcaFile({
    titleId: '0100BBB200000081', contentIndex: 0, contentType: 1,
    titleKeyDec, kak, headerKey,
    section: buildCnmtSection('0100BBB200000002', 1, 0x81, [progB], nonce),
});

const input = buildPfs0([
    { name: `0100aaa100000080.cnmt.nca`, data: metaAData },
    { name: `${progA}.nca`, data: progAData },
    { name: `0100bbb200000081.cnmt.nca`, data: metaBData },
    { name: `${progB}.nca`, data: progBData },
]);

const grandTotal = metaAData.length + progAData.length + metaBData.length + progBData.length;
const shareA = (metaAData.length + progAData.length) / grandTotal;
console.log(`sizes: groupA=${metaAData.length + progAData.length} groupB=${metaBData.length + progBData.length} grand=${grandTotal} shareA=${shareA.toFixed(4)}`);

async function runSplit(skipFirst) {
    const events = [];
    const result = await splitNSP(makeReader(input), keys, async (g, i, name) => {
        if (skipFirst && i === 0) return null;
        return { memory: true, name };
    }, {
        log: () => {},
        progress: (p, label) => events.push({ p, label }),
    });
    return { events, result };
}

// --- Normal run: both groups written ---
{
    const { events, result } = await runSplit(false);
    console.log(`\n== normal run (${events.length} progress events) ==`);
    assert(events.length >= 4, 'progress fired for all 4 member files');
    assert(events.every((e, i, a) => i === 0 || a[i - 1].p <= e.p + 1e-12), 'progress monotonically non-decreasing');
    assert(events[0].p > 0 && events[0].p < 0.1, `first progress small and >0 (got ${events[0].p.toFixed(5)})`);
    assert(events[events.length - 1].p === 1, `last progress exactly 1.0 (got ${events[events.length - 1].p})`);

    const lastA = [...events].reverse().find((e) => e.label.includes('0100aaa100000001'));
    const firstB = events.find((e) => e.label.includes('0100bbb200000002'));
    assert(lastA && firstB, 'both group labels observed');
    assert(events.filter((e) => e.label.includes('(1/2)')).length === 2, 'group A label shows (1/2)');
    assert(events.filter((e) => e.label.includes('(2/2)')).length === 2, 'group B label shows (2/2)');
    assert(lastA.p <= shareA + 1e-12, `group A ends at or below its byte share (${lastA.p.toFixed(5)} <= ${shareA.toFixed(5)})`);
    assert(firstB.p >= shareA - 1e-12, `group B starts at or above the byte share (${firstB.p.toFixed(5)} >= ${shareA.toFixed(5)})`);
    assert(shareA > 0.8, `boundary is byte-weighted, not count-weighted (shareA=${shareA.toFixed(4)}, count-based would be 0.5)`);

    assert(result.outputs.length === 2, 'two title outputs');
    for (const [out, metaRef, progRef, progName] of [
        [result.outputs[0], metaAData, progAData, progA],
        [result.outputs[1], metaBData, progBData, progB],
    ]) {
        const buf = new Uint8Array(await out.blob.arrayBuffer());
        const pfs0 = new PFS0(buf);
        const files = pfs0.getFiles();
        const metaFile = files.find((f) => f.name.endsWith('.cnmt.nca'));
        const progFile = files.find((f) => f.name === `${progName}.nca`);
        assert(metaFile && progFile, `${out.name}: output has meta + program members`);
        assert(bytesEqual(buf.subarray(metaFile.offset, metaFile.offset + metaFile.size), metaRef), `${out.name}: meta NCA byte-identical to input`);
        assert(bytesEqual(buf.subarray(progFile.offset, progFile.offset + progFile.size), progRef), `${out.name}: program NCA byte-identical to input`);
    }
}

// --- Skip run: group A already exists (factory returns null) ---
{
    const { events, result } = await runSplit(true);
    console.log(`\n== skip run (${events.length} progress events) ==`);
    assert(result.outputs.length === 1 && result.outputs[0].name.includes('0100bbb200000002'), 'only group B produced');
    assert(events.every((e, i, a) => i === 0 || a[i - 1].p <= e.p + 1e-12), 'progress monotonically non-decreasing');
    assert(events.length > 0 && events[0].p >= shareA - 1e-12, `skipped group advances the bar (first=${events[0].p.toFixed(5)} >= shareA=${shareA.toFixed(5)})`);
    assert(events[events.length - 1].p === 1, `last progress exactly 1.0 (got ${events[events.length - 1].p})`);
}

console.log(failures === 0 ? '\nALL PASSED' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
