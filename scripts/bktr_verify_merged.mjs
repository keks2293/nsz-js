import fs from 'fs';
import { createHash } from 'crypto';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { mergeRomFS } from '../fs/bktr-merge.js';
import { AesEcb } from '../crypto/aes128.js';

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp`;
const updatePath = `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsp`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const sh = b => createHash('sha256').update(b).digest('hex');

function extractTitlekeyFromTik(tikData, keys) {
    const kekRaw = keys.titlekek_02 || keys.titlekek_source;
    const kek = typeof kekRaw === 'string' ? Buffer.from(kekRaw, 'hex') : Buffer.from(kekRaw);
    return new AesEcb(kek).decrypt(Buffer.from(tikData.subarray(0x180, 0x190)));
}

function members(path) {
    const d = fs.readFileSync(path);
    return { d, entries: new PFS0(d).getFiles() };
}
function getProgram(d, entries) {
    const e = entries.find(x => x.name.toLowerCase().endsWith('.nca') && !x.name.toLowerCase().endsWith('.cnmt.nca'));
    return d.subarray(e.offset, e.offset + e.size);
}
function readTik(d, entries) {
    const t = entries.find(x => x.name.toLowerCase().endsWith('.tik'));
    return d.subarray(t.offset, t.offset + t.size);
}

const base = members(basePath);
const upd = members(updatePath);
const baseNca = getProgram(base.d, base.entries);
const updNca = getProgram(upd.d, upd.entries);
const baseTik = readTik(base.d, base.entries);
const updTik = readTik(upd.d, upd.entries);
const baseTitlekey = extractTitlekeyFromTik(baseTik, keys);
const updateTitlekey = extractTitlekeyFromTik(updTik, keys);

const { merged, mergedData, relocEntries, subsectionEntries } = await mergeRomFS(baseNca, updNca, { keys, baseTitlekey, updateTitlekey });
const mergedBuf = Buffer.from(merged.buffer, merged.byteOffset, merged.length);
const mergedDataBuf = Buffer.from(mergedData.buffer, mergedData.byteOffset, mergedData.length);
console.log(`merged size = 0x${merged.length.toString(16)} (${merged.length})`);
console.log(`mergedData size = 0x${mergedData.length.toString(16)} (${mergedData.length})`);
console.log(`reloc=${relocEntries} sub=${subsectionEntries}`);

// Levels from the update FsHeader (empirically confirmed at 0x18, stride 0x18, master hash at 0xC8)
const { AesXts } = await import('../crypto/aes-ops.mjs');
const updHdr = decryptNcaHeader(updNca.subarray(0, 0xC00), keys);
const updRomfsIdx = updHdr.sections.findIndex(s => s.fsType === 3);
const updDec = Buffer.from(new AesXts(Buffer.from(keys.header_key, 'hex')).decrypt(updNca.subarray(0, 0xC00), 0));
const updFh = updDec.subarray(0x400 + updRomfsIdx * 0x200, 0x400 + updRomfsIdx * 0x200 + 0x200);

function u64(b, o) { return Number(b.readBigUInt64LE(o)); }
const levels = [];
for (let i = 0; i < 7; i++) {
    levels.push({ offset: u64(updFh, 0x18 + i * 0x18), size: u64(updFh, 0x18 + i * 0x18 + 8) });
}
console.log('update levels:');
levels.forEach((l, i) => console.log(`  level[${i}] = {0x${l.offset.toString(16)}, 0x${l.size.toString(16)}}`));
const updMasterHash = updFh.subarray(0xC8, 0xC8 + 0x20).toString('hex');
console.log(`update masterHash = ${updMasterHash}`);

// level5 = the romfs data at [0x134000, ...)
const l5 = levels[5];
const dataStart = l5.offset;
const dataEnd = dataStart + l5.size;
console.log(`\nlevel5 region: 0x${dataStart.toString(16)}..0x${dataEnd.toString(16)} (size 0x${l5.size.toString(16)})`);
const mb = Buffer.from(merged.buffer, merged.byteOffset, merged.length);
if (dataEnd > merged.length) {
    console.log(`WARN: level5 region exceeds merged size 0x${merged.length.toString(16)}`);
} else {
    console.log(`merged magic at level5: '${mb.toString('ascii', dataStart, dataStart + 4)}'`);
    console.log(`merged[0x134000:0x134000+0x40] = ${mb.subarray(dataStart, dataStart + 0x40).toString('hex')}`);
}

// Verify level4 hashes level5
const l4 = levels[4];
console.log(`\nlevel4 region: 0x${l4.offset.toString(16)} size 0x${l4.size.toString(16)}`);
const l4Bytes = 0x4000; // block_size 0xe -> 0x4000
let bad = 0;
let checked = 0;
const nHashes = Math.floor(l4.size / 0x20);
for (let i = 0; i < nHashes; i++) {
    const a = dataStart + i * l4Bytes;
    if (a >= merged.length) break;
    const b = Math.min(a + l4Bytes, merged.length);
    // level-4 hashes 0x4000 blocks; the last block is zero-padded to 0x4000 (the virtual
    // image may end mid-block, see cmp_romfs_size_tmp.mjs — bytes past merged.length are 0)
    const block = Buffer.alloc(l4Bytes);
    mergedBuf.copy(block, 0, a, b);
    const h = sh(block);
    const stored = mergedBuf.subarray(l4.offset + i * 0x20, l4.offset + i * 0x20 + 0x20).toString('hex');
    checked++;
    if (h !== stored) {
        if (bad < 5) console.log(`  level4[${i}] MISMATCH: stored=${stored.slice(0, 16)}... calc=${h.slice(0, 16)}... (region 0x${a.toString(16)}..0x${b.toString(16)})`);
        bad++;
    }
}
console.log(`level4 hash check: ${checked - bad}/${checked} match (bad=${bad})`);

// Master hash
const mh = sh(mb.subarray(dataStart, dataStart + 0x4000));
console.log(`\nsha256(level5[0:0x4000]) = ${mh}`);
console.log(`matches update masterHash: ${mh === updMasterHash}`);

// For a plaintext section we write cryptoType=0, but the level layout is identical.
// Dump what the merged image's first 0x200 bytes at 0 look like (small data level).
console.log(`\nmerged[0x00000:0x100] = ${mb.subarray(0, 0x100).toString('hex')}`);
console.log(`merged[0x00000:0x4] ascii = '${mb.toString('ascii', 0, 4)}'`);
// is level[0] (small data) all zeros?
const l0 = mb.subarray(0, levels[0].size);
let nz = 0;
for (let i = 0; i < l0.length; i++) if (l0[i]) nz++;
console.log(`level0 region: ${l0.length} bytes, ${nz} non-zero`);
const l6s = levels[6].size;
console.log(`level6 region: size=${l6s}`);
if (l6s > 0) {
    const l6r = mb.subarray(levels[6].offset, levels[6].offset + l6s);
    let nz6 = 0;
    for (let i = 0; i < l6r.length; i++) if (l6r[i]) nz6++;
    console.log(`level6 region non-zero: ${nz6}`);
}
