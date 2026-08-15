// Full BKTR parse of the update Program NCA RomFS (cryptoType 4, AesCtrEx)
// Confirmed: section key = ticket titlekey; counter nonce = reversed FsHeader[0x140:0x148].
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { AesCtr, AesXts } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';

const NCA = '/tmp/bktr_probe.nca';
const NSZ = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz';
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const data = new Uint8Array(fs.readFileSync(NCA));
const header = decryptNcaHeader(data, keys);
const sec = header.sections.find(s => s.cryptoType === 4);
const secIdx = header.sections.indexOf(sec);
const hdrKey = typeof keys.header_key === 'string' ? Buffer.from(keys.header_key, 'hex') : keys.header_key;
const decHeader = new AesXts(hdrKey).decrypt(data.subarray(0, 0xC00), 0);
const fsHdr = decHeader.subarray(0x400 + secIdx * 0x200, 0x400 + secIdx * 0x200 + 0x200);
const dv = new DataView(fsHdr.buffer, fsHdr.byteOffset, fsHdr.byteLength);

const indirectOff = Number(dv.getBigUint64(0x100, true));
const indirectSize = Number(dv.getBigUint64(0x108, true));
const aesCtrExOff = Number(dv.getBigUint64(0x120, true));
const aesCtrExSize = Number(dv.getBigUint64(0x128, true));
console.log('section media offset 0x' + sec.offset.toString(16), 'size 0x' + sec.size.toString(16));
console.log('indirect:  off 0x' + indirectOff.toString(16), 'size 0x' + indirectSize.toString(16));
console.log('aesctrex:  off 0x' + aesCtrExOff.toString(16), 'size 0x' + aesCtrExSize.toString(16));

// ticket titlekey
let titlekey = null;
const nsz = fs.readFileSync(NSZ);
const fc = nsz.readUInt32LE(4);
const hsz = 0x10 + fc * 0x18 + nsz.readUInt32LE(8);
const st = nsz.subarray(0x10 + fc * 0x18, hsz);
for (let i = 0; i < fc; i++) {
    const no = nsz.readUInt32LE(0x10 + i * 0x18 + 16);
    let n = ''; let j = no;
    while (st[j] !== 0) n += String.fromCharCode(st[j++]);
    if (!n.toLowerCase().endsWith('.tik')) continue;
    const off = Number(nsz.readBigUInt64LE(0x10 + i * 0x18)) + hsz;
    const size = Number(nsz.readBigUInt64LE(0x10 + i * 0x18 + 8));
    const tik = nsz.subarray(off, off + size);
    const kek = Buffer.from(keys.titlekek_02 || keys.titleKeks[2], 'hex');
    titlekey = new AesEcb(kek).decrypt(Buffer.from(tik.subarray(0x180, 0x190)));
    break;
}
const nonce = new Uint8Array(fsHdr.subarray(0x140, 0x148)).reverse();
console.log('section key:', Buffer.from(titlekey).toString('hex'));
console.log('nonce:', Buffer.from(nonce).toString('hex'));

async function decryptRange(abs, size) {
    const aes = new AesCtr(titlekey, nonce);
    aes.seek(abs);
    return await aes.decrypt(data.subarray(abs, abs + size));
}

// ---- indirect (virtual) block ----
const ind = await decryptRange(sec.offset + indirectOff, indirectSize);
const idv = new DataView(ind.buffer, ind.byteOffset, ind.byteLength);
const nBuckets = idv.getUint32(4, true);
const virtualSize = idv.getBigUint64(8, true);
console.log('\n=== INDIRECT === buckets', nBuckets, 'virtualSize', virtualSize.toString());
const baseVOffsets = [];
for (let i = 0; i < nBuckets; i++) baseVOffsets.push(idv.getBigUint64(0x10 + i * 8, true));
console.log('baseVirtualOffsets:', baseVOffsets.map(b => b.toString()).join(', '));

let totalEntries = 0;
let totalPatch = 0, totalBase = 0;
let minPhys = 0n, maxEnd = 0n;
for (let b = 0; b < nBuckets; b++) {
    const bo = 0x4000 + b * 0x4000;
    const bd = new DataView(ind.buffer, ind.byteOffset + bo, 0x4000);
    const nEntries = bd.getUint32(4, true);
    const endOff = bd.getBigUint64(8, true);
    console.log(`bucket ${b}: nEntries=${nEntries} endOffset=${endOff}`);
    totalEntries += nEntries;
    for (let e = 0; e < Math.min(nEntries, 8); e++) {
        const o = 0x10 + e * 0x18;
        const v = bd.getBigUint64(o, true);
        const s = bd.getBigUint64(o + 8, true);
        const isP = bd.getUint32(o + 0x10, true);
        if (isP) totalPatch++; else totalBase++;
        if (e < 8) console.log(`  [${e}] virt=${v} phys=${s} ${isP ? 'PATCH' : 'base'}`);
    }
    if (b === 0) {
        for (let e = 0; e < nEntries; e++) {
            const o = 0x10 + e * 0x18;
            const s = bd.getBigUint64(o + 8, true);
            const v = bd.getBigUint64(o, true);
            if (e === 0) minPhys = s;
            maxEnd = v;
        }
    }
    console.log('  ... (last entries)');
    for (let e = Math.max(0, nEntries - 3); e < nEntries; e++) {
        const o = 0x10 + e * 0x18;
        console.log(`  [${e}] virt=${bd.getBigUint64(o, true)} phys=${bd.getBigUint64(o + 8, true)} ${bd.getUint32(o + 0x10, true) ? 'PATCH' : 'base'}`);
    }
}
console.log(`entries total=${totalEntries} patch=${totalPatch} base=${totalBase}`);

// ---- AesCtrEx (subsection) block ----
const aes = await decryptRange(sec.offset + aesCtrExOff, aesCtrExSize);
const adv = new DataView(aes.buffer, aes.byteOffset, aes.byteLength);
const anBuckets = adv.getUint32(4, true);
const physicalSize = adv.getBigUint64(8, true);
console.log('\n=== AESCTREX === buckets', anBuckets, 'physicalSize', physicalSize.toString());
const basePOffsets = [];
for (let i = 0; i < anBuckets; i++) basePOffsets.push(adv.getBigUint64(0x10 + i * 8, true));
console.log('basePhysicalOffsets:', basePOffsets.map(b => b.toString()).join(', '));

let aTotal = 0, minAesCtr = 0xFFFFFFFF, maxAesCtr = 0;
for (let b = 0; b < anBuckets; b++) {
    const bo = 0x4000 + b * 0x4000;
    const bd = new DataView(aes.buffer, aes.byteOffset + bo, 0x4000);
    const nEntries = bd.getUint32(4, true);
    const endOff = bd.getBigUint64(8, true);
    console.log(`bucket ${b}: nEntries=${nEntries} endOffset=${endOff}`);
    aTotal += nEntries;
    for (let e = 0; e < Math.min(nEntries, 8); e++) {
        const o = 0x10 + e * 0x10;
        const off = bd.getBigUint64(o, true);
        const ctr = bd.getUint32(o + 0xC, true);
        if (e < 8) console.log(`  [${e}] offset=${off} ctr=${ctr.toString(16)}`);
        if (ctr < minAesCtr) minAesCtr = ctr;
        if (ctr > maxAesCtr) maxAesCtr = ctr;
    }
    console.log('  ... last:');
    for (let e = Math.max(0, nEntries - 2); e < nEntries; e++) {
        const o = 0x10 + e * 0x10;
        console.log(`  [${e}] offset=${bd.getBigUint64(o, true)} ctr=${bd.getUint32(o + 0xC, true).toString(16)}`);
    }
}
console.log(`aesctrex entries total=${aTotal} ctr range 0x${minAesCtr.toString(16)}..0x${maxAesCtr.toString(16)}`);
