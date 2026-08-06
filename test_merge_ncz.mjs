#!/usr/bin/env node
import { execFileSync, spawnSync } from 'node:child_process';
import { PFS0Writer, PFS0 } from './fs/pfs0.js';
import { BufferReader } from './fs/ncz.js';
import { mergeNSP } from './fs/merge.js';

const hasZstd = spawnSync('zstd', ['--version']).status === 0;
if (!hasZstd) {
    console.log('  ⊘ Skipping - zstd CLI not found (needed to synthesize test NCZ files)');
    process.exit(0);
}

function ascii(str) {
    return new TextEncoder().encode(str);
}

function u64le(view, bytes, offset, value) {
    view.setBigUint64(offset, BigInt(value), true);
}

function buildNcz(header, payload) {
    const compressed = execFileSync('zstd', ['-q', '-c'], { input: Buffer.from(payload) });
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

function buildNczBlock(header, payload) {
    const blockSizeExponent = 14;
    const blockSize = 1 << blockSizeExponent;
    const compressed = execFileSync('zstd', ['-q', '-c'], { input: Buffer.from(payload) });
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
        { keys: null, log: (l, m) => logs.push(m), progress: () => {} },
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
        { keys: null, log: (l, m) => dupLogs.push(m), progress: () => {} },
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
        { keys: null, log: (l, m) => blockLogs.push(m), progress: () => {} },
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

    console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} TEST(S) FAILED`);
    process.exit(failures === 0 ? 0 : 1);
}

main().catch(e => { console.error('Error:', e); process.exit(1); });
