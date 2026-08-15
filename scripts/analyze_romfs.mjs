import fs from 'fs';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesXts } from '../crypto/aes-ops.mjs';

// Analyze the level-5 (RomFS) data region of a Program NCA inside an NSP:
//   - romfs_header fields
//   - file table walk (entries, last file, blob geometry)
//   - blob area summary + trailing gap (blob end .. file_table start)
//
// Reference (source-first): RomFS structures per hacPack sources/hacPack/romfs.h —
// romfs_header_t = 10 u64 (header_size, dir_hash_table_ofs/size, dir_table_ofs/size,
// file_hash_table_ofs/size, file_table_ofs/size, file_partition_ofs) and
// romfs_fentry_t = parent(4) sibling(4) offset(8) size(8) hash(4) name_size(4)
// name[0x20+name_size, padded to 4). The level-5 slice (data_offset..data_size) is
// what hactool/hac2l/hacPack use as the RomFS blob: hactool nca.c:1240
// ("romfs_offset = ivfc_levels[IVFC_MAX_LEVEL-1].data_offset"); yanu's unpack_all
// (crates/hac/src/vfs/nca.rs) extracts the same slice via hac2l.
//
// Usage: node analyze_romfs.mjs <nsp> [outputJson]
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
function romfsHeader(data) {
    const g = o => Number(data.readBigUInt64LE(o));
    return {
        header_size: g(0x00), dir_hash_table_ofs: g(0x08), dir_hash_table_size: g(0x10),
        dir_table_ofs: g(0x18), dir_table_size: g(0x20), file_hash_table_ofs: g(0x28),
        file_hash_table_size: g(0x30), file_table_ofs: g(0x38), file_table_size: g(0x40),
        file_partition_ofs: g(0x48),
    };
}
// romfs_fentry_t: parent(4) sibling(4) offset(8) size(8) hash(4) name_size(4) name[]
function walkFileTable(data, h) {
    let off = h.file_table_ofs;
    const end = off + h.file_table_size;
    const entries = [];
    while (off + 0x20 <= end) {
        const nameSize = data.readUInt32LE(off + 0x1C);
        const blobOfs = Number(data.readBigUInt64LE(off + 0x8));
        const blobSize = Number(data.readBigUInt64LE(off + 0x10));
        const name = Buffer.from(data.subarray(off + 0x20, off + 0x20 + nameSize)).toString('utf8');
        entries.push({ name, blobOfs, blobSize });
        off += (0x20 + nameSize + 3) & ~3;
    }
    return entries;
}

const input = process.argv[2];
const outJson = process.argv[3];
const n = progNca(readNsp(input));
const { data, hds } = level5(n);
const h = romfsHeader(data);
const files = walkFileTable(data, h);
const sumBlobs = files.reduce((a, f) => a + f.blobSize, 0);
const minOfs = Math.min(...files.map(f => f.blobOfs));
const maxEnd = Math.max(...files.map(f => f.blobOfs + f.blobSize));
const last = files[files.length - 1];

const result = {
    nca: n.e.name,
    ncaSize: n.e.size,
    level5Size: hds,
    header: h,
    fileCount: files.length,
    sumBlobs,
    blobArea: { from: minOfs, to: maxEnd, len: maxEnd - minOfs },
    gapAfterBlobs: h.file_table_ofs - maxEnd,
    lastFile: last,
};

console.log(`nca: ${result.nca} (${result.ncaSize})`);
console.log(`level-5 data: ${result.level5Size} bytes`);
console.log(`files: ${result.fileCount}, sum blob sizes: ${result.sumBlobs}`);
console.log(`blob area: [0x${result.blobArea.from.toString(16)}, 0x${result.blobArea.to.toString(16)}) len 0x${result.blobArea.len.toString(16)}`);
console.log(`gap blob-end..file_table: ${result.gapAfterBlobs} bytes`);
console.log(`last file: "${result.lastFile.name}" (${result.lastFile.name.length} B name) blob=0x${result.lastFile.blobOfs.toString(16)} size=${result.lastFile.blobSize}`);
for (const [k, v] of Object.entries(h)) console.log(`  ${k}: 0x${v.toString(16)}`);

if (outJson) fs.writeFileSync(outJson, JSON.stringify(result, null, 2));
