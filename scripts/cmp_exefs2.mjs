// Part 2: compare ExeFS FILE CONTENTS (ignoring the 16 B PFS0 header padding
// difference) and classify the RomFS section diff between the two outputs.
// Usage: node scripts/cmp_exefs2.mjs <our.nsp> <yanu.nsp> <update.nsz>
import fs from 'node:fs';
import { KeysParser } from '../keys.js';
import { AesEcb } from '../crypto/aes128.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesXts } from '../crypto/aes-ops.mjs';
import { decryptNcaHeader } from '../fs/nca.js';
import { extractExefs } from '../fs/nca-pack.js';
import { AdapterNCZReader, BufferReader, parseNczSections, NCZDecompressor } from '../fs/ncz.js';

const [,, ourPath, yanuPath, updateNszPath] = process.argv;
const keys = KeysParser.parse(fs.readFileSync('static/prod.keys', 'utf8'));
const NCA_HDR = 0xC00;

class FilePfs0Reader {
    constructor(p) { this.fd = fs.openSync(p, 'r'); }
    async read(off, len) {
        const buf = new Uint8Array(len);
        fs.readSync(this.fd, Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength), 0, len, off);
        return buf;
    }
    close() { fs.closeSync(this.fd); }
}

function diffRegions(a, b) {
    const regions = [];
    let d = 0, rs = -1;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            d++;
            if (rs < 0) rs = i;
        } else if (rs >= 0) {
            regions.push([rs, i - 1]);
            rs = -1;
        }
    }
    if (rs >= 0) regions.push([rs, a.length - 1]);
    return { d, regions };
}

function show(label, diff, base) {
    if (diff.d === 0) { console.log(`${label}: IDENTICAL`); return; }
    console.log(`${label}: ${diff.d} B in ${diff.regions.length} regions`);
    for (const [s, e] of diff.regions.slice(0, 12)) console.log(`    0x${(base + s).toString(16)}..0x${(base + e).toString(16)} (file-rel 0x${s.toString(16)}, ${e - s + 1} B)`);
    if (diff.regions.length > 12) console.log(`    ... +${diff.regions.length - 12} more`);
}

// ── Update ExeFS (original, from .nsz) ───────────────────────────────────────
const ur = new FilePfs0Reader(updateNszPath);
const uPfs0 = await PFS0.open(ur);
const uTik = uPfs0.files.find(f => f.name.toLowerCase().endsWith('.tik'));
const uProg = uPfs0.files.filter(f => /\.nca$|\.ncz$/i.test(f.name)).sort((a, b) => b.size - a.size)[0];
const tikData = await ur.read(uTik.offset, uTik.size);
const titlekek = typeof keys.titlekek_02 === 'string' ? (() => { const b = new Uint8Array(keys.titlekek_02.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(keys.titlekek_02.substr(i * 2, 2), 16); return b; })() : new Uint8Array(keys.titlekek_02);
const nczReader = new AdapterNCZReader(ur, uProg.offset, uProg.size);
const parsed = await parseNczSections(nczReader);
const fullNca = new Uint8Array(parsed.ncaSize);
await new NCZDecompressor(nczReader).decompress(() => {}, (chunk, offset) => {
    fullNca.set(chunk.subarray(0, Math.min(chunk.length, parsed.ncaSize - offset)), offset);
}, parsed);
const updateExefs = await extractExefs({ headerRaw: fullNca.subarray(0, NCA_HDR), source: new BufferReader(fullNca) }, keys, tikData);
const up = new PFS0(updateExefs);
ur.close();

function fileSlices(exefs) {
    const p = new PFS0(exefs);
    return p.files.map(f => {
        const rel = f.offset; // PFS0._parse already adds headerSize → absolute in exefs
        return { name: f.name, size: f.size, data: exefs.subarray(rel, rel + f.size) };
    });
}

const updFiles = fileSlices(updateExefs);

async function outFiles(path) {
    const r = new FilePfs0Reader(path);
    const p = await PFS0.open(r);
    const prog = p.files.filter(f => /\.nca$/i.test(f.name) && !/cnmt/i.test(f.name)).sort((a, b) => b.size - a.size)[0];
    const hdr = decryptNcaHeader(new Uint8Array(await r.read(prog.offset, NCA_HDR)), keys);
    const exeSec = hdr.sections.find(s => s.fsType === 2);
    const raw = new Uint8Array(await r.read(prog.offset + exeSec.offset, exeSec.endOffset - exeSec.offset));
    const exefs = raw.subarray(exeSec.sectionStart, exeSec.sectionStart + exeSec.sectionSize);
    r.close();
    return { files: fileSlices(exefs), exefs, exeSec };
}

const our = await outFiles(ourPath);
const yanu = await outFiles(yanuPath);

// ── ExeFS file-content comparison (update = ground truth) ───────────────────
console.log('=== ExeFS file contents vs original update ===');
for (const uf of updFiles) {
    const o = our.files.find(f => f.name === uf.name);
    const y = yanu.files.find(f => f.name === uf.name);
    show(`ours  ${uf.name} (vs update)`, diffRegions(o.data, uf.data), 0);
    show(`yanu  ${uf.name} (vs update)`, diffRegions(y.data, uf.data), 0);
}

// ── RomFS section comparison ─────────────────────────────────────────────────
async function romSec(path) {
    const r = new FilePfs0Reader(path);
    const p = await PFS0.open(r);
    const prog = p.files.filter(f => /\.nca$/i.test(f.name) && !/cnmt/i.test(f.name)).sort((a, b) => b.size - a.size)[0];
    const hdrRaw = new Uint8Array(await r.read(prog.offset, NCA_HDR));
    const hdr = decryptNcaHeader(hdrRaw, keys);
    const romSec = hdr.sections.find(s => s.fsType === 3);
    const raw = new Uint8Array(await r.read(prog.offset + romSec.offset, romSec.endOffset - romSec.offset));
    r.close();
    // IVFC header sits at NCA hdr 0x608; per-level {logical_offset, hash_data_size, block_size}
    // at +0x10 + i*0x18; level #5 is the data level.
    const hk = typeof keys.header_key === 'string' ? (() => { const b = new Uint8Array(keys.header_key.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(keys.header_key.substr(i * 2, 2), 16); return b; })() : new Uint8Array(keys.header_key);
    const dec = new AesXts(hk).decrypt(hdrRaw.subarray(0, NCA_HDR), 0);
    const ivfc = dec.subarray(0x608, 0x608 + 0x100);
    const u64 = (b, o) => Number(new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, true));
    let dataOff = 0;
    for (let i = 0; i < 6; i++) {
        const off = u64(ivfc, 0x10 + i * 0x18);
        const sz = u64(ivfc, 0x10 + i * 0x18 + 8);
        if (i === 5) dataOff = off;
    }
    return { raw, romSec, dataOff };
}

console.log('\n=== RomFS section ===');
const ro = await romSec(ourPath);
const ry = await romSec(yanuPath);
console.log(`ours: 0x${ro.romSec.offset.toString(16)}..0x${ro.romSec.endOffset.toString(16)} size=${ro.raw.length}, dataOff=0x${ro.dataOff.toString(16)}`);
console.log(`yanu: 0x${ry.romSec.offset.toString(16)}..0x${ry.romSec.endOffset.toString(16)} size=${ry.raw.length}, dataOff=0x${ry.dataOff.toString(16)}`);
const n = Math.min(ro.raw.length, ry.raw.length);
const rd = diffRegions(ro.raw.subarray(0, n), ry.raw.subarray(0, n));
show('RomFS section', rd, ro.romSec.offset);

// The section is [IVFC level files][data level]; the IVFC header lives in the
const dataOff = ro.dataOff;
// RFS0 superblock (data+0x0..0x5F): file_table@0x18, file_hash_table@0x28, dir_table@0x38, dir_hash_table@0x48
function sbDump(raw, label) {
    const d = new DataView(raw.buffer, raw.byteOffset + dataOff, 0x200);
    const g = (o) => Number(d.getBigUint64(o, true));
    console.log(`${label} RFS0: magic=${String.fromCharCode(raw[dataOff], raw[dataOff + 1], raw[dataOff + 2], raw[dataOff + 3])} file_count=${g(0x08)} dir_count=${g(0x10)}`);
    console.log(`  file_table_ofs=0x${g(0x18).toString(16)} size=0x${g(0x20).toString(16)}`);
    console.log(`  file_hash_table_ofs=0x${g(0x28).toString(16)} size=0x${g(0x30).toString(16)}`);
    console.log(`  dir_table_ofs=0x${g(0x38).toString(16)} size=0x${g(0x40).toString(16)}`);
    console.log(`  dir_hash_table_ofs=0x${g(0x48).toString(16)} size=0x${g(0x50).toString(16)}`);
}
sbDump(ro.raw, 'ours');
sbDump(ry.raw, 'yanu');

// Bucket the section diff (tables start at the smallest table offset in the data level)
{
    const d = new DataView(ro.raw.buffer, ro.raw.byteOffset + dataOff, 0x200);
    const g = (o) => Number(d.getBigUint64(o, true));
    const tablesStart = Math.min(g(0x18), g(0x28), g(0x38), g(0x48));
    const buckets = { 'IVFC hdr+levels [0,dataOff)': 0, 'RFS0 hdr [dataOff,+0x200)': 0, 'file data': 0, 'trailing tables': 0 };
    for (const [s, e] of rd.regions) {
        const len = e - s + 1;
        if (s < dataOff) buckets['IVFC hdr+levels [0,dataOff)'] += len;
        else if (s < dataOff + 0x200) buckets['RFS0 hdr [dataOff,+0x200)'] += len;
        else if (s < dataOff + tablesStart) buckets['file data'] += len;
        else buckets['trailing tables'] += len;
    }
    console.log(`\nDiff buckets (section-relative, tables start at data+0x${tablesStart.toString(16)}):`);
    for (const [k, v] of Object.entries(buckets)) console.log(`  ${k}: ${v} B`);
}
