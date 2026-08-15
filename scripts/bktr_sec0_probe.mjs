// Verify section 0 (ExeFS, cryptoType 3) decryption of the update NCA — known plaintext PFS0
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { AesCtr, AesXts } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const data = new Uint8Array(fs.readFileSync('/tmp/bktr_probe.nca'));
const header = decryptNcaHeader(data, keys);
const sec = header.sections.find(s => s.cryptoType === 3);
const secIdx = header.sections.indexOf(sec);
console.log('sec', secIdx, 'ft', sec.fsType, 'ct', sec.cryptoType, 'abs', '0x' + sec.offset.toString(16), 'size', '0x' + sec.size.toString(16));

const hdrKey = Buffer.from(keys.header_key, 'hex');
const decHdr = new AesXts(hdrKey).decrypt(data.subarray(0, 0xC00), 0);
const fsHdr = decHdr.subarray(0x400 + secIdx * 0x200, 0x400 + secIdx * 0x200 + 0x200);
const dv = new DataView(fsHdr.buffer, fsHdr.byteOffset, fsHdr.byteLength);
const gen = dv.getUint32(0x140, true);
const secVal = dv.getUint32(0x144, true);
console.log('sec0 gen', gen.toString(16), 'secVal', secVal.toString(16));

const nonceGenSec = new Uint8Array(8);
new DataView(nonceGenSec.buffer).setUint32(0, gen, false);
new DataView(nonceGenSec.buffer).setUint32(4, secVal, false);
const nonceRaw = new Uint8Array(fsHdr.subarray(0x140, 0x148));
const nonceZeros = new Uint8Array(8);

const kak2 = Buffer.from(keys.keyAreaKeys[2][0], 'hex');
const titleKeyDec = Buffer.from(new AesEcb(kak2).decrypt(new Uint8Array(0x10)));
console.log('titleKeyDec:', titleKeyDec.toString('hex'));

async function tryDec(name, key, n) {
    const aes = new AesCtr(key, n);
    aes.seek(sec.offset);
    const dec = await aes.decrypt(data.subarray(sec.offset, sec.offset + 0x200));
    let mag = '';
    for (let i = 0; i < 4; i++) mag += String.fromCharCode(dec[i]);
    console.log(name, '->', JSON.stringify(mag));
    return mag;
}

await tryDec('titleKeyDec/genSec', titleKeyDec, nonceGenSec);
await tryDec('titleKeyDec/raw', titleKeyDec, nonceRaw);
await tryDec('titleKeyDec/zeros', titleKeyDec, nonceZeros);

// also try different offsets for the counter (some tools use offset relative to section)
const aes = new AesCtr(titleKeyDec, nonceGenSec);
aes.seek(0);
const dec0 = await aes.decrypt(data.subarray(sec.offset, sec.offset + 0x200));
let mag0 = ''; for (let i = 0; i < 4; i++) mag0 += String.fromCharCode(dec0[i]);
console.log('titleKeyDec/genSec/seek0 ->', JSON.stringify(mag0));
