#!/usr/bin/env node
// Dump the RomFS superblock (romfs_header_t) of the Program NCA in one or more
// NSP files, for base (plain romfs, CRYPT_CTR) and update (BKTR, CRYPT_BKTR)
// NCAs alike, and report dir_hash_table_ofs alignment in each original.
//
// NCA layout reference (sources/hactool/nca.h):
//   - The 0xC00 NCA header is XTS-AES-128 (header_key, tweak 0). Magic "NCA3"
//     sits at 0x200 (after the two 0x100 RSA sigs). Section table at 0x240.
//   - FsHeader[i] at 0x400 + i*0x200: partition_type@0x2, fs_type@0x3
//     (FS_TYPE_PFS0=2, FS_TYPE_ROMFS=3), crypt_type@0x4 (CRYPT_CTR=3,
//     CRYPT_BKTR=4), then the embedded superblock area at +0x08 (0x138): for
//     IVFC-hashed romfs it is the ivfc_hdr_t (0xE0); for BKTR additionally
//     reloc_header@0x100 + subsection_header@0x120. section_ctr@0x140.
//   - ivfc_level_hdr_t = { logical_offset, hash_data_size, block_size(log2),
//     reserved } (0x18), entries at ivfc+0x10 + i*0x18. Level 5 = the romfs
//     data: logical_offset = its offset within the section, hash_data_size =
//     its size. hactool nca.c:1051-1053.
//   - The romfs superblock is the first 0x200 bytes of the level-5 data; the
//     section is AesCtr-encrypted with the titlekey (nonce = section_ctr
//     byte-reversed, @FsHeader+0x140).
//
// Usage: node check_romfs_alignment.mjs <nsp> [nsp ...]
// Requires ../static/prod.keys.

import fs from 'fs';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesXts, AesCtr } from '../crypto/aes-ops.mjs';
import { NCZDecompressor, AdapterNCZReader, parseNczSections } from '../fs/ncz.js';
import { extractTitlekeyFromTik, deriveTitlekeyFromKeyArea } from '../fs/bktr.js';

const paths = process.argv.slice(2);
if (!paths.length) {
    console.error('Usage: node check_romfs_alignment.mjs <nsp|nsz> [nsp|nsz ...]');
    process.exit(1);
}

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const keyBuf = Buffer.from(keys.header_key, 'hex');

// Load an .nsz: decompress the program NCA in memory, return { nca, tik, nspEntries }.
async function loadNsz(path) {
    const buf = new Uint8Array(fs.readFileSync(path));
    const reader = {
        get length() { return buf.length; },
        read: (o, s) => Promise.resolve(buf.subarray(o, o + s)),
    };
    const pfs0 = await PFS0.open(reader);
    const files = pfs0.getFiles();
    const prog = files.find(f => /\.ncz$/i.test(f.name) && !f.name.endsWith('.cnmt.ncz') && f.size > 10000000)
        || files.find(f => /\.ncz$/i.test(f.name) && !f.name.endsWith('.cnmt.ncz'));
    const tik = files.find(f => /\.tik$/i.test(f.name));
    if (!prog) throw new Error(`no program NCZ in ${path}`);
    const parsed = await parseNczSections(new AdapterNCZReader(reader, prog.offset, Math.min(prog.size, 0x10000)));
    const nca = new Uint8Array(parsed.ncaSize);
    const decomp = new NCZDecompressor(new AdapterNCZReader(reader, prog.offset, prog.size));
    await decomp.decompress(() => {}, (chunk, offset) => {
        nca.set(chunk, offset);
    }, parsed);
    return { nca: Buffer.from(nca), tik: tik ? buf.subarray(tik.offset, tik.offset + tik.size) : null, progName: prog.name };
}

function u32(b, o) { return new DataView(b.buffer, b.byteOffset + o, 4).getUint32(0, true); }
function u64(b, o) { return Number(new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, true)); }

const FIELDS = [
    ['header_size', 0x00],
    ['dir_hash_table_ofs', 0x08], ['dir_hash_table_size', 0x10],
    ['dir_table_ofs', 0x18], ['dir_table_size', 0x20],
    ['file_hash_table_ofs', 0x28], ['file_hash_table_size', 0x30],
    ['file_table_ofs', 0x38], ['file_table_size', 0x40],
    ['file_partition_ofs', 0x48],
];

function printSuperblock(sb, label) {
    const g = o => Number(sb.readBigUInt64LE(o));
    console.log(`  ${label}`);
    for (const [name, o] of FIELDS) {
        const v = g(o);
        console.log(`    ${name}: 0x${v.toString(16).padStart(8, '0')}  (mod4=${v % 4}, mod8=${v % 8})`);
    }
}

for (const path of paths) {
    let nca, tik, progName;
    if (/\.nsz$/i.test(path)) {
        const r = await loadNsz(path);
        nca = r.nca; tik = r.tik; progName = r.progName + ' (decompressed)';
    } else {
        const nsp = fs.readFileSync(path);
        const entries = new PFS0(nsp).getFiles();
        const prog = entries.find(f => f.name.endsWith('.nca') && !f.name.endsWith('.cnmt.nca') && f.size > 100000000);
        const tikEntry = entries.find(f => f.name.endsWith('.tik'));
        if (!prog) { console.error(`no program NCA in ${path}`); continue; }
        nca = nsp.subarray(prog.offset, prog.offset + prog.size);
        tik = tikEntry ? nsp.subarray(tikEntry.offset, tikEntry.offset + tikEntry.size) : null;
        progName = prog.name;
    }
    const dec = Buffer.from(new AesXts(keyBuf).decrypt(nca.subarray(0, 0xC00), 0));

    console.log(`\n=== ${path.split('/').pop()} ===`);
    console.log(`  program: ${progName} (${nca.length} B)`);

    for (let i = 0; i < 4; i++) {
        const fh = dec.subarray(0x400 + i * 0x200, 0x600 + i * 0x200);
        const fsType = fh[0x03];
        if (fsType !== 3) continue; // FS_TYPE_ROMFS

        const cryptType = fh[0x04];
        const si = u32(dec, 0x240 + i * 0x10) * 0x200;
        const se = u32(dec, 0x240 + i * 0x10 + 4) * 0x200;
        const ivfc = fh.subarray(0x08);
        const magic = String.fromCharCode(ivfc[0], ivfc[1], ivfc[2], ivfc[3]);
        const l5 = 5 * 0x18;
        const dataOfs = u64(ivfc, 0x10 + l5);
        const dataSize = u64(ivfc, 0x10 + l5 + 8);
        console.log(`  sec[${i}] fsType=ROMFS cryptType=${cryptType} section=[0x${si.toString(16)}, 0x${se.toString(16)}) ivfc='${magic}' level5 @0x${dataOfs.toString(16)} size 0x${dataSize.toString(16)}`);

        const rightsId = dec.subarray(0x230, 0x240).toString('hex');
        const tikData = tik;
        const titlekey = (tikData && extractTitlekeyFromTik(tikData, keys, rightsId)) || deriveTitlekeyFromKeyArea(dec, keys);
        if (!titlekey) { console.error('    cannot derive titlekey'); continue; }
        const raw = fh.subarray(0x140, 0x148);
        const nonce = new Uint8Array(8);
        for (let j = 0; j < 8; j++) nonce[j] = raw[7 - j];
        const c = new AesCtr(titlekey, nonce);
        c.seek(si + dataOfs);
        const sb = Buffer.from(await c.decrypt(nca.subarray(si + dataOfs, si + dataOfs + 0x200)));
        printSuperblock(sb, `romfs superblock @section+0x${dataOfs.toString(16)} (AesCtr-decrypted)`);
    }
}
