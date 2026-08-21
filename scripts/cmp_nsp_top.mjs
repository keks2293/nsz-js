// Compare top-level NSP PFS0 tables of two output files.
// Usage: node scripts/cmp_nsp_top.mjs <a.nsp> <b.nsp>
import fs from 'node:fs';
import { PFS0 } from '../fs/pfs0.js';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';

class R {
    constructor(p) { this.p = p; this.fd = fs.openSync(p, 'r'); }
    async read(o, l) { const b = new Uint8Array(l); fs.readSync(this.fd, b, 0, l, o); return b; }
    close() { fs.closeSync(this.fd); }
}

async function dump(label, path) {
    console.log(`\n=== ${label}: ${path}`);
    const r = new R(path);
    const p = await PFS0.open(r);
    console.log(`  hdr=${p.headerSize} (0x${p.headerSize.toString(16)}) strtab=${p.stringTableSize}`);
    const out = {};
    for (const f of p.files) {
        out[f.name] = f;
        console.log(`  ${f.name}  ofs=0x${f.offset.toString(16)} size=${f.size} (0x${f.size.toString(16)})`);
    }
    const last = p.files[p.files.length - 1];
    const total = fs.statSync(path).size;
    console.log(`  end=0x${(last.offset + last.size).toString(16)} total=${total} (0x${total.toString(16)}) tail=${total - last.offset - last.size}`);
    r.close();
    return out;
}

const keys = KeysParser.parse(fs.readFileSync('static/prod.keys', 'utf8'));

async function dumpNcaSections(label, path, member) {
    console.log(`\n  NCA sections (${label}): ${member.name}`);
    const r = new R(path);
    const hdr = decryptNcaHeader(await r.read(member.offset, 0xC00), keys);
    for (const s of hdr.sections) {
        console.log(`    fs=${s.fsType} crypt=${s.cryptoType} ofs=0x${s.offset.toString(16)} start=0x${s.sectionStart.toString(16)} size=0x${s.sectionSize.toString(16)} end=0x${s.endOffset.toString(16)}`);
    }
    r.close();
}

const [,, aPath, bPath] = process.argv;
const a = await dump('A', aPath);
const b = await dump('B', bPath);

console.log('\n=== Member diff ===');
const names = [...new Set([...Object.keys(a), ...Object.keys(b)])];
for (const n of names) {
    const fa = a[n], fb = b[n];
    if (!fa || !fb) { console.log(`  ${n}: only in ${fa ? 'A' : 'B'}`); continue; }
    if (fa.size !== fb.size || fa.offset !== fb.offset) {
        console.log(`  ${n}: DIFF  A(size=0x${fa.size.toString(16)} ofs=0x${fa.offset.toString(16)})  B(size=0x${fb.size.toString(16)} ofs=0x${fb.offset.toString(16)})  dSize=${fb.size - fa.size}`);
        if (fa.size !== fb.size) {
            await dumpNcaSections('A', aPath, fa);
            await dumpNcaSections('B', bPath, fb);
        }
    } else {
        console.log(`  ${n}: same`);
    }
}
