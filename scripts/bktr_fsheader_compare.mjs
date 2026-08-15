import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesXts } from '../crypto/aes-ops.mjs';

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp`;
const updatePath = `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsp`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

function members(path) {
    const d = fs.readFileSync(path);
    return { d, entries: new PFS0(d).getFiles() };
}
function getProgram(d, entries) {
    const e = entries.find(x => x.name.toLowerCase().endsWith('.nca') && !x.name.toLowerCase().endsWith('.cnmt.nca'));
    return d.subarray(e.offset, e.offset + e.size);
}
function hex(b, o, n) {
    return Buffer.from(b.buffer, b.byteOffset, b.length).subarray(o, o + n).toString('hex').replace(/(..)/g, '$1 ').trim();
}
function dump(label, fh) {
    console.log(`\n=== ${label} ===`);
    for (let row = 0; row < 0x200; row += 0x10) {
        const b = fh.subarray(row, row + 0x10);
        let ascii = '';
        for (let i = 0; i < 0x10; i++) {
            const c = b[i];
            ascii += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
        }
        console.log(`${row.toString(16).padStart(3, '0')}: ${hex(b, 0, 0x10)}  ${ascii}`);
    }
}

const base = members(basePath);
const upd = members(updatePath);
const baseNca = getProgram(base.d, base.entries);
const updNca = getProgram(upd.d, upd.entries);

const xts = new AesXts(Buffer.from(keys.header_key, 'hex'));
const baseDec = Buffer.from(xts.decrypt(baseNca.subarray(0, 0xC00), 0));
const updDec = Buffer.from(xts.decrypt(updNca.subarray(0, 0xC00), 0));
const baseHdr = decryptNcaHeader(baseNca.subarray(0, 0xC00), keys);
const updHdr = decryptNcaHeader(updNca.subarray(0, 0xC00), keys);

for (const [label, hdr, dec] of [['BASE', baseHdr, baseDec], ['UPDATE', updHdr, updDec]]) {
    for (let i = 0; i < 4; i++) {
        const s = hdr.sections[i];
        if (!s || s.size === 0) continue;
        const fh = dec.subarray(0x400 + i * 0x200, 0x400 + i * 0x200 + 0x200);
        dump(`${label} FsHeader sec[${i}] (fs=${s.fsType} crypto=${s.cryptoType} offset=0x${s.offset.toString(16)})`, fh);
    }
}

// Also dump OUR current packed output FsHeader for comparison. Run the merge+pack.
const { mergeRomFS } = await import('./fs/bktr-merge.js');
const baseTik = base.entries.find(t => t.name.toLowerCase().endsWith('.tik'));
const updTik = upd.entries.find(t => t.name.toLowerCase().endsWith('.tik'));
const { merged } = await mergeRomFS(baseNca, updNca, {
    keys,
    baseTik: base.d.subarray(baseTik.offset, baseTik.offset + baseTik.size),
    updateTik: upd.d.subarray(updTik.offset, updTik.offset + updTik.size),
});
const { extractExefs, extractControl } = await import('./fs/nca-pack.js');
const exefsData = await extractExefs(updNca, keys, upd.d.subarray(updTik.offset, updTik.offset + updTik.size));
const controlData = await extractControl(baseNca, keys);
console.log(`\nexefs=${exefsData.length} mergedRomfs=${merged.length} control=${controlData?.length}`);
const { packPlaintextProgramNca } = await import('./fs/nca-pack.js');
const packed = await packPlaintextProgramNca(exefsData, merged, controlData, baseHdr.titleId.toString(16), keys);
const packedHdr = decryptNcaHeader(packed.subarray(0, 0xC00), keys);
const packedDec = Buffer.from(xts.decrypt(packed.subarray(0, 0xC00), 0));
for (let i = 0; i < 4; i++) {
    const s = packedHdr.sections[i];
    if (!s || s.size === 0) continue;
    const fh = packedDec.subarray(0x400 + i * 0x200, 0x400 + i * 0x200 + 0x200);
    dump(`OUR PACKED FsHeader sec[${i}] (fs=${s.fsType} crypto=${s.cryptoType})`, fh);
}
