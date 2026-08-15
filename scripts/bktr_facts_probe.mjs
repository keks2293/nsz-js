// Find which key decrypts the BASE Program NCA RomFS section (known plaintext: IVFC/RomFS magic)
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { AesCtr, AesXts } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const baseNsp = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsz';
const updateNsp = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz';

function members(path) {
    const d = fs.readFileSync(path);
    const fc = d.readUInt32LE(4);
    const hs = 0x10 + fc * 0x18 + d.readUInt32LE(8);
    const st = d.subarray(0x10 + fc * 0x18, hs);
    const out = [];
    for (let i = 0; i < fc; i++) {
        const no = d.readUInt32LE(0x10 + i * 0x18 + 16);
        let n = ''; let j = no;
        while (st[j] !== 0) n += String.fromCharCode(st[j++]);
        const off = Number(d.readBigUInt64LE(0x10 + i * 0x18)) + hs;
        const size = Number(d.readBigUInt64LE(0x10 + i * 0x18 + 8));
        out.push({ name: n, data: d.subarray(off, off + size) });
    }
    return out;
}

function titlekeyFromTik(tikData) {
    const block = Buffer.from(tikData.subarray(0x180, 0x190));
    const tk = Buffer.from(keys.titlekek_02, 'hex');
    return { block, titlekey: Buffer.from(new AesEcb(tk).decrypt(block)) };
}

const updTik = members(updateNsp).find(m => m.name.toLowerCase().endsWith('.tik'));
const { titlekey: updTitlekey } = titlekeyFromTik(updTik.data);
console.log('update titlekey:', updTitlekey.toString('hex'));

// base program nca
const baseNca = members(baseNsp).find(m => m.name.toLowerCase().endsWith('.nca'));
const header = decryptNcaHeader(baseNca.data, keys);
console.log('base masterKey', header.masterKey);
const sections = header.sections;
console.log('base sections:', sections.map(s => ({ type: s.type, cryptoType: s.cryptoType, off: '0x' + s.offset.toString(16) })));

const sec = sections.find(s => s.cryptoType === 3 || s.cryptoType === 4);
const secIdx = sections.indexOf(sec);
console.log('romfs section idx', secIdx, 'cryptoType', sec.cryptoType, 'abs', '0x' + sec.offset.toString(16));

const hdrKey = typeof keys.header_key === 'string' ? Buffer.from(keys.header_key, 'hex') : keys.header_key;
const decHdr = new AesXts(hdrKey).decrypt(baseNca.data.subarray(0, 0xC00), 0);
const fsHdr = decHdr.subarray(0x400 + secIdx * 0x200, 0x400 + secIdx * 0x200 + 0x200);
const dv = new DataView(fsHdr.buffer, fsHdr.byteOffset, fsHdr.byteLength);
const rawUpper = new Uint8Array(fsHdr.subarray(0x140, 0x148));
const gen = dv.getUint32(0x140, true);
const secVal = dv.getUint32(0x144, true);
const nonce = new Uint8Array(8);
new DataView(nonce.buffer).setUint32(0, gen, false);
new DataView(nonce.buffer).setUint32(4, secVal, false);
console.log('base gen', gen.toString(16), 'secVal', secVal.toString(16), 'nonce', Buffer.from(nonce).toString('hex'));

console.log('base decrypted keyBlock:', Buffer.from(header.keyBlock).toString('hex'));

const kak2 = Buffer.from(keys.keyAreaKeys[2][0], 'hex');
const titleKeyDec = Buffer.from(new AesEcb(kak2).decrypt(new Uint8Array(0x10)));

async function tryDec(name, key, off) {
    const aes = new AesCtr(key, nonce);
    aes.seek(off);
    const dec = await aes.decrypt(new Uint8Array(baseNca.data.subarray(off, off + 0x10000)));
    let mag = '';
    for (let i = 0; i < 4; i++) mag += String.fromCharCode(dec[i]);
    const looks = mag === 'IVFC' || mag === 'PFS0' || mag === 'HFС0' || mag === 'HFS0';
    console.log((looks ? '  *** ' : '  ') + name + '  first4=' + JSON.stringify(mag) + ' next=' + dec.subarray(0x100, 0x104).reduce((a, b) => a + b.toString(16).padStart(2, '0'), ''));
    return looks ? dec : null;
}

// key candidates
const entryKeys = [];
const ecb = new AesEcb(kak2);
const decKA = ecb.decrypt(header.keyBlock);
for (let i = 0; i < 4; i++) entryKeys.push(decKA.subarray(i * 0x10, i * 0x10 + 0x10));
// base titlekey (its own ticket in base nsp if any)
let baseTitlekey = null;
const baseTik = members(baseNsp).find(m => m.name.toLowerCase().endsWith('.tik'));
if (baseTik) baseTitlekey = titlekeyFromTik(baseTik.data).titlekey;

const off = sec.offset;
let hit = await tryDec('titleKeyDec(kak2/zeros)', titleKeyDec, off);
if (!hit && baseTitlekey) hit = await tryDec('base ticket titlekey', baseTitlekey, off);
if (!hit) hit = await tryDec('update ticket titlekey', updTitlekey, off);
if (!hit) for (let i = 0; i < 4; i++) { hit = await tryDec('kak-decrypted keyArea entry' + i, entryKeys[i], off); if (hit) break; }

if (hit) {
    // also test which keys decrypt the update's BKTR meta
    console.log('\nBase decrypts with a working key! Now test update meta:');
}
