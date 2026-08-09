#!/usr/bin/env node
import { zstdCompressSync } from 'node:zlib';
import { randomBytes } from 'node:crypto';
import { PFS0Writer, PFS0 } from './fs/pfs0.js';
import { BufferReader } from './fs/ncz.js';
import { mergeNSP } from './fs/merge.js';
import { AesCtr } from './crypto/aes-ops.mjs';
import { AesEcb } from './crypto/aes128.js';

function ascii(str) {
    return new TextEncoder().encode(str);
}

function u64le(view, bytes, offset, value) {
    view.setBigUint64(offset, BigInt(value), true);
}

function buildNcz(header, payload) {
    const compressed = zstdCompressSync(Buffer.from(payload));
    const sectionCount = 1;
    const headerSize = 0x4000;
    const entrySize = 64;
    const sectionsOff = headerSize + 8 + 8;
    const dataOff = sectionsOff + entrySize;
    const buf = new Uint8Array(dataOff + compressed.length);
    buf.set(header, 0);
    buf.set(ascii('NCZSECTN'), 0x4000);
    const view = new DataView(buf.buffer);
    u64le(view, buf, 0x4008, sectionCount);
    u64le(view, buf, sectionsOff + 0, 0x4000);
    u64le(view, buf, sectionsOff + 8, payload.length);
    u64le(view, buf, sectionsOff + 16, 1);
    buf.set(compressed, dataOff);
    return buf;
}

function buildNczSections(header, sections) {
    // sections: [{ offset, size, cryptoType, key, counter, data }], sorted by offset, contiguous
    const sectionCount = sections.length;
    const headerSize = 0x4000;
    const entrySize = 64;
    const sectionsOff = headerSize + 8 + 8;
    const dataOff = sectionsOff + entrySize * sectionCount;
    const payload = [];
    for (const s of sections) payload.push(s.data);
    const compressed = zstdCompressSync(Buffer.concat(payload));
    const buf = new Uint8Array(dataOff + compressed.length);
    buf.set(header, 0);
    buf.set(ascii('NCZSECTN'), 0x4000);
    const view = new DataView(buf.buffer);
    u64le(view, buf, 0x4008, sectionCount);
    for (let i = 0; i < sectionCount; i++) {
        const s = sections[i];
        const off = sectionsOff + i * entrySize;
        u64le(view, buf, off + 0, s.offset);
        u64le(view, buf, off + 8, s.size);
        u64le(view, buf, off + 16, s.cryptoType);
        buf.set(s.key ?? new Uint8Array(16), off + 32);
        buf.set(s.counter ?? new Uint8Array(16), off + 48);
    }
    buf.set(compressed, dataOff);
    return buf;
}

function buildNczBlock(header, payload) {
    const blockSizeExponent = 14;
    const blockSize = 1 << blockSizeExponent;
    const compressed = zstdCompressSync(Buffer.from(payload));
    const numberOfBlocks = Math.ceil(payload.length / blockSize);
    const blockHeaderOff = 0x4000 + 8 + 8 + 64;
    const sizeListOff = blockHeaderOff + 24;
    const blockDataOff = sizeListOff + numberOfBlocks * 4;
    const buf = new Uint8Array(blockDataOff + compressed.length);
    buf.set(header, 0);
    buf.set(ascii('NCZSECTN'), 0x4000);
    const view = new DataView(buf.buffer);
    u64le(view, buf, 0x4008, 1);
    u64le(view, buf, 0x4010 + 0, 0x4000);
    u64le(view, buf, 0x4010 + 8, payload.length);
    u64le(view, buf, 0x4010 + 16, 1);
    buf.set(ascii('NCZBLOCK'), blockHeaderOff);
    view.setUint8(blockHeaderOff + 8, 0);
    view.setUint8(blockHeaderOff + 9, 0);
    view.setUint8(blockHeaderOff + 10, 0);
    view.setUint8(blockHeaderOff + 11, blockSizeExponent);
    view.setUint32(blockHeaderOff + 12, numberOfBlocks, true);
    u64le(view, buf, blockHeaderOff + 16, payload.length);
    view.setUint32(sizeListOff, compressed.length, true);
    buf.set(compressed, blockDataOff);
    return buf;
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

let failures = 0;
function assert(cond, msg) {
    if (cond) console.log(`  ✅ ${msg}`);
    else { failures++; console.log(`  ❌ ${msg}`); }
}

function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

function makeReader(data) {
    return new BufferReader(data);
}

async function main() {
    const header = new Uint8Array(0x4000).fill(0xAB);
    const payload = new Uint8Array(0x8000);
    for (let i = 0; i < payload.length; i++) payload[i] = (i * 7 + 3) & 0xFF;
    const ncz = buildNcz(header, payload);

    const tik = new TextEncoder().encode('fake ticket bytes for dedup test\n');
    const extraNca = new Uint8Array(0x2000).fill(0xCD);

    const nszData = buildPfs0([
        { name: '01000000000000000000000000000000.ncz', data: ncz },
        { name: 'blob.tik', data: tik },
    ]);
    const nspData = buildPfs0([
        { name: '01000000000000000000000000000001.nca', data: extraNca },
        { name: '01000000000000000000000000000001.cnmt.nca', data: extraNca.slice(0, 0x1000) },
    ]);

    const logs = [];
    const result = await mergeNSP(
        [
            { name: 'synthetic.nsz', reader: makeReader(nszData) },
            { name: 'synthetic.nsp', reader: makeReader(nspData) },
        ],
        { memory: true },
        { log: (l, m) => logs.push(m), progress: () => {} },
    );

    console.log('Merge log:');
    for (const l of logs) console.log(`  ${l}`);

    const merged = new PFS0(new Uint8Array(await result.blob.arrayBuffer()));
    const files = merged.getFiles();
    console.log(`Members (${files.length}):`, files.map(f => `${f.name} (${f.size})`).join(', '));

    const nczOut = files.find(f => f.name === '01000000000000000000000000000000.nca');
    assert(nczOut !== undefined, 'NCZ member decompressed to .nca in output');
    const tikOut = files.find(f => f.name === 'blob.tik');
    assert(tikOut !== undefined, 'plain .tik member copied');
    const extraOut = files.find(f => f.name === '01000000000000000000000000000001.nca');
    assert(extraOut !== undefined, 'plain .nca member copied');

    if (nczOut) {
        const data = new Uint8Array(await result.blob.arrayBuffer());
        const out = data.subarray(nczOut.offset, nczOut.offset + nczOut.size);
        const expected = new Uint8Array(0x4000 + payload.length);
        expected.set(header, 0);
        expected.set(payload, 0x4000);
        assert(out.length === expected.length, `decompressed size correct (${out.length} == ${expected.length})`);
        assert(bytesEqual(out, expected), 'decompressed NCZ bytes match expected NCA');
    }

    const dupNcz = buildNcz(header, payload);
    const dupNca = new Uint8Array(0x3000).fill(0xEF);
    const nszDup = buildPfs0([{ name: '01000000000000000000000000000000.ncz', data: dupNcz }]);
    const nspDup = buildPfs0([{ name: '01000000000000000000000000000000.nca', data: dupNca }]);

    const dupLogs = [];
    const dupResult = await mergeNSP(
        [
            { name: 'dup.nsp', reader: makeReader(nspDup) },
            { name: 'dup.nsz', reader: makeReader(nszDup) },
        ],
        { memory: true },
        { log: (l, m) => dupLogs.push(m), progress: () => {} },
    );
    const dupMerged = new PFS0(new Uint8Array(await dupResult.blob.arrayBuffer()));
    const dupFiles = dupMerged.getFiles();
    console.log(`Dedup members (${dupFiles.length}):`, dupFiles.map(f => `${f.name} (${f.size})`).join(', '));
    assert(dupFiles.length === 1, 'duplicate stem across .nca/.ncz deduped to a single member');
    assert(dupFiles[0].name === '01000000000000000000000000000000.nca', 'dedup keeps first input (uncompressed .nca)');
    const dupData = new Uint8Array(await dupResult.blob.arrayBuffer());
    const dupOut = dupData.subarray(dupFiles[0].offset, dupFiles[0].offset + dupFiles[0].size);
    assert(bytesEqual(dupOut, dupNca), 'first-wins member data byte-identical');

    const blockPayload = new Uint8Array(0x4000);
    for (let i = 0; i < blockPayload.length; i++) blockPayload[i] = (i * 13 + 7) & 0xFF;
    const nczBlock = buildNczBlock(header, blockPayload);
    const nszBlock = buildPfs0([{ name: 'block-test.ncz', data: nczBlock }]);
    const nspBlock = buildPfs0([{ name: 'other.nca', data: extraNca }]);

    const blockLogs = [];
    const blockResult = await mergeNSP(
        [
            { name: 'block.nsz', reader: makeReader(nszBlock) },
            { name: 'block.nsp', reader: makeReader(nspBlock) },
        ],
        { memory: true },
        { log: (l, m) => blockLogs.push(m), progress: () => {} },
    );
    const blockMerged = new PFS0(new Uint8Array(await blockResult.blob.arrayBuffer()));
    const blockOut = blockMerged.getFiles().find(f => f.name === 'block-test.nca');
    assert(blockOut !== undefined, 'NCZBLOCK member decompressed to .nca in output');
    if (blockOut) {
        const bd = new Uint8Array(await blockResult.blob.arrayBuffer());
        const bout = bd.subarray(blockOut.offset, blockOut.offset + blockOut.size);
        const expected = new Uint8Array(0x4000 + blockPayload.length);
        expected.set(header, 0);
        expected.set(blockPayload, 0x4000);
        assert(bytesEqual(bout, expected), 'NCZBLOCK member decompressed bytes match expected NCA');
    }

    // High-entropy (random) streaming payload: exercises the write-backpressure path
    // in _decompressStream on incompressible data (large single write past the zstd
    // transform's highWaterMark). Guards against re-entrant/'drain'-style write loops
    // that corrupt zstd streaming output on random frames.
    const randomPayload = new Uint8Array(0xC00000);
    for (let i = 0; i < randomPayload.length; i += 4096) {
        randomPayload.set(randomBytes(Math.min(4096, randomPayload.length - i)), i);
    }
    const nczRand = buildNcz(header, randomPayload);
    const nszRand = buildPfs0([{ name: 'rand-test.ncz', data: nczRand }]);
    const nspRand = buildPfs0([{ name: 'rand-other.nca', data: extraNca }]);
    const randLogs = [];
    const randResult = await mergeNSP(
        [
            { name: 'rand.nsz', reader: makeReader(nszRand) },
            { name: 'rand.nsp', reader: makeReader(nspRand) },
        ],
        { memory: true },
        { log: (l, m) => randLogs.push(m), progress: () => {} },
    );
    const randMerged = new PFS0(new Uint8Array(await randResult.blob.arrayBuffer()));
    const randOut = randMerged.getFiles().find(f => f.name === 'rand-test.nca');
    assert(randOut !== undefined, 'high-entropy NCZ member decompressed to .nca in output');
    if (randOut) {
        const rd = new Uint8Array(await randResult.blob.arrayBuffer());
        const rout = rd.subarray(randOut.offset, randOut.offset + randOut.size);
        const expected = new Uint8Array(0x4000 + randomPayload.length);
        expected.set(header, 0);
        expected.set(randomPayload, 0x4000);
        assert(rout.length === expected.length, `high-entropy decompressed size correct (${rout.length} == ${expected.length})`);
        assert(bytesEqual(rout, expected), 'high-entropy decompressed bytes match expected NCA');
    }

    // AES-CTR section (cryptoType 3): regresses the decrypt continuity bug where
    // re-seeding the cipher on unaligned chunk boundaries corrupted output.
    // The section is ~16MB of random bytes, deliberately NOT a multiple of 16:
    // with the 16MB input-feeding pattern, node's streaming zstd emits at least
    // one output chunk starting at a non-16-aligned position inside the section,
    // so the old code (which re-seeded the cipher at every chunk) produced a
    // shifted keystream for that whole chunk. Verified: this exact case corrupts
    // on the pre-fix code (788 wrong bytes), passes byte-identical on the fix.
    const ctrSecSize = 0x1000001;
    const ctrKey = new Uint8Array(16);
    const ctrCounter = new Uint8Array(16);
    for (let i = 0; i < 16; i++) ctrKey[i] = (i * 11 + 5) & 0xFF;
    const { AesCtr } = await import('./crypto/aes-ops.mjs');
    const ctrPayload = randomBytes(ctrSecSize);
    const encrypted = new Uint8Array(ctrPayload);
    const ctr = new AesCtr(ctrKey, ctrCounter, 0x4000 + 0x2000);
    encrypted.set(await ctr.decrypt(ctrPayload), 0);
    const nczCtr = buildNczSections(header, [
        { offset: 0x4000, size: 0x2000, cryptoType: 1, data: new Uint8Array(0x2000).fill(0x11) },
        { offset: 0x6000, size: ctrSecSize, cryptoType: 3, key: ctrKey, counter: ctrCounter, data: encrypted },
    ]);
    const nszCtr = buildPfs0([{ name: 'ctr-test.ncz', data: nczCtr }]);
    const nspCtr = buildPfs0([{ name: 'ctr-other.nca', data: extraNca }]);
    const ctrLogs = [];
    const ctrResult = await mergeNSP(
        [
            { name: 'ctr.nsz', reader: makeReader(nszCtr) },
            { name: 'ctr.nsp', reader: makeReader(nspCtr) },
        ],
        { memory: true },
        { log: (l, m) => ctrLogs.push(m), progress: () => {} },
    );
    const ctrMerged = new PFS0(new Uint8Array(await ctrResult.blob.arrayBuffer()));
    const ctrOut = ctrMerged.getFiles().find(f => f.name === 'ctr-test.nca');
    assert(ctrOut !== undefined, 'AES-CTR NCZ member decompressed to .nca in output');
    if (ctrOut) {
        const cd = new Uint8Array(await ctrResult.blob.arrayBuffer());
        const cout = cd.subarray(ctrOut.offset, ctrOut.offset + ctrOut.size);
        const expected = new Uint8Array(0x4000 + 0x2000 + ctrSecSize);
        expected.set(header, 0);
        expected.set(new Uint8Array(0x2000).fill(0x11), 0x4000);
        expected.set(ctrPayload, 0x6000);
        assert(bytesEqual(cout, expected), 'AES-CTR section decrypted bytes match expected NCA');
    }

    // Stateless AES-CTR mid-block regression (regresses the webcrypto / JS-fallback
    // bug where decrypt in non-16-aligned chunks corrupted the keystream).
    const midChunk = 1000; // not a multiple of 16
    const midPlain = new Uint8Array(ctrSecSize);
    for (let i = 0; i < ctrSecSize; i++) midPlain[i] = (i * 17 + 3) & 0xFF;
    const midEnc = new Uint8Array(ctrSecSize);
    const midCtr = new AesCtr(ctrKey, ctrCounter, 0x6000);
    midEnc.set(await midCtr.encrypt(midPlain), 0);
    for (const backend of ['js', 'webcrypto']) {
        const dec = new AesCtr(ctrKey, ctrCounter, 0x6000, backend);
        const midOut = new Uint8Array(ctrSecSize);
        for (let off = 0; off < ctrSecSize; off += midChunk) {
            const n = Math.min(midChunk, ctrSecSize - off);
            midOut.set(await dec.decrypt(midEnc.subarray(off, off + n)), off);
        }
        assert(bytesEqual(midOut, midPlain), `AES-CTR ${backend} backend decrypt in mid-block chunks matches reference`);
    }

// Stateless seek() continuity: re-seeding a single cipher to nonlocal offsets
    // (forward jump, unaligned rewind, tail) must reproduce byte-for-byte the
    // keystream an independent node cipher yields for those absolute positions.
    // node's createCipheriv cannot itself begin mid-block, so the reference for an
    // unaligned start `off` is derived from a cipher aligned to the containing
    // block and sliced `off%16` bytes in.
    async function nodeKeystreamSlice(off, n) {
        const tail = off & 15;
        const z = new Uint8Array(tail + n);
        const refCtr = new AesCtr(ctrKey, ctrCounter);
        refCtr.seek(off - tail);
        const ks = await refCtr.encrypt(z); // zeroes -> raw keystream
        const plain = midPlain.subarray(off, off + n);
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) out[i] = plain[i] ^ ks[tail + i];
        return out;
    }

    // --- Synthetic encrypted NCA header + CNMT builders (for --nodelta test) ---

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
            d.set(randomBytes(32), off);
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

    const progUpdate = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const nonce = new Uint8Array(16);
    for (let i = 0; i < 16; i++) nonce[i] = (i * 13 + 3) & 0xFF;

    const programUpdateData = await buildNcaFile({
        titleId: '0100E65002BB8000', contentIndex: 0, contentType: 0,
        titleKeyDec, kak, headerKey,
    });
    const metaUpdateData = await buildNcaFile({
        titleId: '0100E65002BB8800', contentIndex: 0, contentType: 1,
        titleKeyDec, kak, headerKey,
        section: buildCnmtSection('0100E65002BB8800', 786432, 0x81, [progUpdate], nonce),
    });

    const nszBase = buildPfs0([
        { name: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.nca', data: await buildNcaFile({
            titleId: '0100E65002BB8000', contentIndex: 0, contentType: 0,
            titleKeyDec, kak, headerKey,
        }) },
        { name: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.cnmt.nca', data: await buildNcaFile({
            titleId: '0100E65002BB8000', contentIndex: 0, contentType: 1,
            titleKeyDec, kak, headerKey,
            section: buildCnmtSection('0100E65002BB8000', 0, 0x80, ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], nonce),
        }) },
    ]);
    const nszUpdate = buildPfs0([
        { name: `${progUpdate}.nca`, data: programUpdateData },
        { name: `${progUpdate}.cnmt.nca`, data: metaUpdateData },
    ]);

    const plan = [
        { off: 0x0000, n: 0x2000 },             // aligned start
        { off: 0x9000, n: 0x1000 },             // forward jump (block-aligned)
        { off: 0x1e042, n: 0x800 },             // unaligned rewind to a live block
        { off: ctrSecSize - 0x300, n: 0x300 },  // tail (partial run into next block)
    ];
    for (const backend of ['js', 'webcrypto']) {
        const seekCtr = new AesCtr(ctrKey, ctrCounter, 0, backend);
        for (const { off, n } of plan) {
            const expected = await nodeKeystreamSlice(off, n);
            seekCtr.seek(off);
            const out = new Uint8Array(n);
            for (let s = 0; s < n; s += midChunk) {
                const c = Math.min(midChunk, n - s);
                out.set(await seekCtr.encrypt(midPlain.subarray(off + s, off + s + c)), s);
            }
            assert(bytesEqual(out, expected),
                `AES-CTR ${backend} seek 0x${off.toString(16)} chunked encrypt matches node`);
        }
    }

    // --nodelta (opt-in): an update whose CNMT references a DeltaFragment
    // (ContentInfo type 6) and ships the fragment file. With nodelta + keys the
    // fragment is dropped; without nodelta it is kept; nodelta without keys
    // throws.
    const deltaFragId = 'dddddddddddddddddddddddddddddddd';
    const metaUpdateDeltaData = await buildNcaFile({
        titleId: '0100E65002BB9900', contentIndex: 0, contentType: 1,
        titleKeyDec, kak, headerKey,
        section: buildCnmtSection('0100E65002BB9900', 786432, 0x81,
            [{ id: progUpdate, type: 1 }, { id: deltaFragId, type: 6 }], nonce),
    });
    const fragData = new Uint8Array(0x1000).fill(0xEE);
    const nszUpdateDelta = buildPfs0([
        { name: `${progUpdate}.nca`, data: programUpdateData },
        { name: `${deltaFragId}.nca`, data: fragData },
        { name: `${progUpdate}.cnmt.nca`, data: metaUpdateDeltaData },
    ]);

    // Default (nodelta off): the fragment is kept.
    const defaultResult = await mergeNSP(
        [
            { name: 'base.nsp', reader: makeReader(nszBase) },
            { name: 'update.nsp', reader: makeReader(nszUpdateDelta) },
        ],
        { memory: true },
        { log: () => {}, progress: () => {}, keys },
    );
    const defaultNames = new PFS0(new Uint8Array(await defaultResult.blob.arrayBuffer())).getFiles().map(f => f.name);
    assert(defaultNames.includes(`${deltaFragId}.nca`), 'without --nodelta the delta fragment is kept');

    // nodelta on + keys: the fragment is dropped, program + CNMT stay.
    const nodeltaLogs = [];
    const nodeltaResult = await mergeNSP(
        [
            { name: 'base.nsp', reader: makeReader(nszBase) },
            { name: 'update.nsp', reader: makeReader(nszUpdateDelta) },
        ],
        { memory: true },
        { log: (l, m) => nodeltaLogs.push(m), progress: () => {}, keys, nodelta: true },
    );
    const nodeltaMerged = new PFS0(new Uint8Array(await nodeltaResult.blob.arrayBuffer()));
    const nodeltaNames = nodeltaMerged.getFiles().map(f => f.name);
    console.log('Nodelta log:');
    for (const l of nodeltaLogs) console.log(`  ${l}`);
    assert(!nodeltaNames.includes(`${deltaFragId}.nca`), 'nodelta drops the delta fragment');
    assert(nodeltaNames.includes(`${progUpdate}.nca`), 'nodelta keeps the program NCA');
    assert(nodeltaNames.includes(`${progUpdate}.cnmt.nca`), 'nodelta keeps the CNMT');

    // nodelta without keys is a hard error.
    let threw = false;
    try {
        await mergeNSP(
            [
                { name: 'base.nsp', reader: makeReader(nszBase) },
                { name: 'update.nsp', reader: makeReader(nszUpdateDelta) },
            ],
            { memory: true },
            { log: () => {}, progress: () => {}, nodelta: true },
        );
    } catch (e) {
        threw = /nodelta requires keys/.test(e.message);
    }
    assert(threw, 'nodelta without keys throws');

    console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} TEST(S) FAILED`);
    process.exit(failures === 0 ? 0 : 1);
}

main().catch(e => { console.error('Error:', e); process.exit(1); });
