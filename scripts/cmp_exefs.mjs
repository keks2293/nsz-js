// Compare the ExeFS PFS0 content of two output NSPs' Program NCAs against the
// original update NCA's ExeFS (extracted from the update .nsz).
// Usage: node scripts/cmp_exefs.mjs <our.nsp> <yanu.nsp> <update.nsz>
import fs from 'node:fs';
import { KeysParser } from '../keys.js';
import { AesEcb } from '../crypto/aes128.js';
import { AesCtr } from '../crypto/aes-ops.mjs';
import { PFS0 } from '../fs/pfs0.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { extractExefs } from '../fs/nca-pack.js';
import { AdapterNCZReader, BufferReader, parseNczSections, NCZDecompressor } from '../fs/ncz.js';

const [,, ourPath, yanuPath, updateNszPath] = process.argv;
if (!ourPath || !yanuPath || !updateNszPath) {
    console.log('Usage: node scripts/cmp_exefs.mjs <our.nsp> <yanu.nsp> <update.nsz>');
    process.exit(1);
}

const keys = KeysParser.parse(fs.readFileSync('static/prod.keys', 'utf8'));
const NCA_HDR = 0xC00;

class FilePfs0Reader {
    constructor(p) { this.fd = fs.openSync(p, 'r'); this.size = fs.statSync(p).size; }
    async read(off, len) {
        const buf = new Uint8Array(len);
        const b = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
        fs.readSync(this.fd, b, 0, len, off);
        return buf;
    }
    close() { fs.closeSync(this.fd); }
}

function pfs0Dump(label, exefs) {
    const p = new PFS0(exefs);
    console.log(`  ${label}: ${p.files.length} files, strtab=${p.stringTableSize}, hdr=${p.headerSize}`);
    for (const f of p.files) console.log(`    ${f.name}  size=${f.size}`);
    return p;
}

function diffBytes(a, b) {
    let d = 0, first = -1, last = -1;
    const regions = [];
    let rs = -1;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            if (first < 0) first = i;
            last = i;
            d++;
            if (rs < 0) rs = i;
        } else if (rs >= 0) {
            regions.push([rs, i - 1]);
            rs = -1;
        }
    }
    if (rs >= 0) regions.push([rs, a.length - 1]);
    return { d, first, last, regions };
}

function showDiff(label, x, y) {
    if (x.length !== y.length) {
        console.log(`${label}: SIZE differs ${x.length} vs ${y.length}`);
        return;
    }
    const diff = diffBytes(x, y);
    if (diff.d === 0) {
        console.log(`${label}: IDENTICAL (${x.length} B)`);
        return;
    }
    console.log(`${label}: ${diff.d} B differ in ${diff.regions.length} regions, first=0x${diff.first.toString(16)} last=0x${diff.last.toString(16)}`);
    for (const [s, e] of diff.regions.slice(0, 15)) console.log(`    0x${s.toString(16)}..0x${e.toString(16)} (${e - s + 1} B)`);
    if (diff.regions.length > 15) console.log(`    ... +${diff.regions.length - 15} more`);
}

// ── 1. Update NCA original ExeFS from the .nsz ───────────────────────────────
console.log(`\n=== Update .nsz: ${updateNszPath}`);
const ur = new FilePfs0Reader(updateNszPath);
const uPfs0 = await PFS0.open(ur);
const uTik = uPfs0.files.find(f => f.name.toLowerCase().endsWith('.tik'));
const uProg = uPfs0.files.filter(f => /\.nca$|\.ncz$/i.test(f.name)).sort((a, b) => b.size - a.size)[0];
console.log(`  tik: ${uTik.name} (${uTik.size} B), Program NCA: ${uProg.name} (${uProg.size} B)`);
const tikData = await ur.read(uTik.offset, uTik.size);
const titlekek = typeof keys.titlekek_02 === 'string' ? (() => { const b = new Uint8Array(keys.titlekek_02.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(keys.titlekek_02.substr(i * 2, 2), 16); return b; })() : new Uint8Array(keys.titlekek_02);
const titlekey = new AesEcb(titlekek).decrypt(tikData.subarray(0x180, 0x190));

const nczReader = new AdapterNCZReader(ur, uProg.offset, uProg.size);
const parsed = await parseNczSections(nczReader);
const decomp = new NCZDecompressor(nczReader);
const fullNca = new Uint8Array(parsed.ncaSize);
await decomp.decompress(() => {}, (chunk, offset) => {
    fullNca.set(chunk.subarray(0, Math.min(chunk.length, parsed.ncaSize - offset)), offset);
}, parsed);
const updateExefs = await extractExefs({ headerRaw: fullNca.subarray(0, NCA_HDR), source: new BufferReader(fullNca) }, keys, tikData);
console.log(`  update ExeFS: ${updateExefs.length} B`);
pfs0Dump('update ExeFS PFS0', updateExefs);
ur.close();

// ── 2. Each output NSP: Program NCA ExeFS, decrypted ─────────────────────────
async function outputExefs(path) {
    console.log(`\n=== Output: ${path}`);
    const r = new FilePfs0Reader(path);
    const p = await PFS0.open(r);
    const prog = p.files.filter(f => /\.nca$/i.test(f.name) && !/cnmt/i.test(f.name)).sort((a, b) => b.size - a.size)[0];
    console.log(`  Program NCA: ${prog.name} (${prog.size} B) at 0x${prog.offset.toString(16)}`);
    const hdrRaw = await r.read(prog.offset, NCA_HDR);
    const hdr = decryptNcaHeader(hdrRaw, keys);
    if (!hdr) throw new Error('cannot decrypt output Program NCA header');
    const exeSec = hdr.sections.find(s => s.fsType === 2);
    console.log(`  ExeFS section: 0x${exeSec.offset.toString(16)}..0x${exeSec.endOffset.toString(16)} (cryptoType=${exeSec.cryptoType}, start=0x${exeSec.sectionStart.toString(16)}, size=${exeSec.sectionSize})`);
    // Repacked NCA sections are plaintext (FsHeader crypt_type 1 = CRYPT_NONE per
    // hacpack nca.h section_crypt_type_t; only the NCA header is XTS-encrypted).
    const raw = await r.read(prog.offset + exeSec.offset, exeSec.endOffset - exeSec.offset);
    r.close();
    const exefs = raw;
    const pfs0Data = exefs.subarray(exeSec.sectionStart, exeSec.sectionStart + exeSec.sectionSize);
    pfs0Dump('output ExeFS PFS0', pfs0Data);
    return pfs0Data;
}

const ourExefs = await outputExefs(ourPath);
const yanuExefs = await outputExefs(yanuPath);

// ── 3. Compare ───────────────────────────────────────────────────────────────
console.log('\n=== Diffs (ExeFS PFS0 data) ===');
showDiff('ours  vs update', ourExefs, updateExefs);
showDiff('yanu  vs update', yanuExefs, updateExefs);
showDiff('ours  vs yanu  ', ourExefs, yanuExefs);
