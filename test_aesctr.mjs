import { AESCTR } from './crypto/aesctr.mjs';
import { readFileSync } from 'fs';

(async () => {
const key = new Uint8Array(Buffer.from('c0f2ce05ba73bcf5777f58f94e919b01', 'hex'));
const nonce = new Uint8Array(Buffer.from('00000002000000020000000000000000', 'hex'));

console.log('Key:', Buffer.from(key).toString('hex'));
console.log('Nonce:', Buffer.from(nonce).toString('hex'));

const aesCtr = new AESCTR(key, nonce);
aesCtr.seek(0x4000);

const test = new Uint8Array(Buffer.from('28b52ffd', 'hex'));
const encrypted = await aesCtr.encrypt(test);

console.log('Encrypted zstd magic:', Buffer.from(encrypted).toString('hex'));
console.log('Expected:                874786d3');
})();
