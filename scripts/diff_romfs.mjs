import fs from 'fs';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesXts } from '../crypto/aes-ops.mjs';

// Byte-level diff of the level-5 (RomFS) data region between two Program NCAs.
// Prints the first N differences and a summary of differing byte ranges.
//
// Reference (source-first): the level-5 slice is the RomFS blob used by
// hactool/hac2l/hacPack — hactool nca.c:1240 ("romfs_offset =
// ivfc_levels[IVFC_MAX_LEVEL-1].data_offset"); yanu extracts it via hac2l
// (`--basenca base update --romfsdir`, crates/hac/src/vfs/nca.rs unpack_all).
// For the documented 4-byte vs-yanu gap (pad alignment 8 vs 4, see DOC-REPACK.md),
// this script is the tool that localizes the differing byte ranges.
//
// Usage: node diff_romfs.mjs <nspA> <nspB> [maxDiffRanges]
// Requires ../static/prod.keys.

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const keyBuf = Buffer.from(keys.header_key, 'hex');

function readNsp(path) {
    const buf = fs.readFileSync(path);
    const files = new PFS0(buf).getFiles();
    return { buf, files };
}
function progNca(nsp) {
    const e = nsp.files.find(f => f.name.endsWith('.nca') && !f.name.endsWith('.cnmt.nca') && f.size > 100000000);
    const data = nsp.buf.subarray(e.offset, e.offset + e.size);
    const hdr = Buffer.from(new AesXts(keyBuf).decrypt(data.subarray(0, 0xC00), 0));
    return { e, data, hdr };
}
function level5(n) {
    const si = n.hdr.readUInt32LE(0x240 + 1 * 0x10) * 0x200;
    const fh = n.hdr.subarray(0x600, 0x800);
    const lo = Number(fh.readBigUInt64LE(0x18 + 5 * 0x18));
    const hds = Number(fh.readBigUInt64LE(0x18 + 5 * 0x18 + 8));
    return { data: n.data.subarray(si + lo, si + lo + hds), hds };
}

const [aPath, bPath] = process.argv.slice(2);
const maxRanges = Number(process.argv[4] || 0) || Infinity;

const a = level5(progNca(readNsp(aPath)));
const b = level5(progNca(readNsp(bPath)));
console.log(`A: ${a.hds} B: ${b.hds} (diff ${a.hds - b.hds})`);

const maxLen = Math.max(a.data.length, b.data.length);
let first = 0;
for (let i = 0; i < maxLen; i++) {
    const x = i < a.data.length ? a.data[i] : -1;
    const y = i < b.data.length ? b.data[i] : -1;
    if (x !== y) { first = i; break; }
}
if (first !== 0) {
    console.log(`first diff @0x${first.toString(16)}`);
    console.log(`  A: ${Buffer.from(a.data.subarray(first, first + 32)).toString('hex')}`);
    console.log(`  B: ${Buffer.from(b.data.subarray(first, first + 32)).toString('hex')}`);
}

const ranges = [];
let start = -1;
for (let i = 0; i < maxLen; i++) {
    const x = i < a.data.length ? a.data[i] : -1;
    const y = i < b.data.length ? b.data[i] : -1;
    if (x !== y) {
        if (start < 0) start = i;
    } else if (start >= 0) {
        ranges.push([start, i - 1]);
        start = -1;
    }
}
if (start >= 0) ranges.push([start, maxLen - 1]);
const diffBytes = ranges.reduce((s, [f, t]) => s + (t - f + 1), 0);
console.log(`${ranges.length} differing ranges, ${diffBytes} differing bytes`);
for (const [s, e] of ranges.slice(0, maxRanges)) {
    console.log(`  [0x${s.toString(16)}, 0x${e.toString(16)}) len=${e - s + 1}`);
}
