// Test AES-CTR in Node.js using aes-js library
// This should match Python PyCryptodome output

const aesjs = require('./browser/crypto/aes-js.js');

const key = new Uint8Array([
    0x3c, 0x83, 0x58, 0xe3, 0x7c, 0x54, 0xac, 0xa5,
    0xbb, 0x20, 0xfc, 0x36, 0x74, 0x1c, 0x17, 0x27
]);

const nonce = new Uint8Array([
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
]);

const offset = 131072; // 0x20000
const blockIndex = Math.floor(offset / 16);

console.log('Key:', Buffer.from(key).toString('hex'));
console.log('Nonce:', Buffer.from(nonce).toString('hex'));
console.log('Offset:', offset, '(0x' + offset.toString(16) + ')');
console.log('Block Index:', blockIndex);
console.log('');

// Build counter block: nonce[0:8] + LE64(blockIndex)
const ctr = new Uint8Array(16);
for (let j = 0; j < 8; j++) {
    ctr[j] = nonce[j];
}
let tmp = blockIndex;
for (let j = 8; j < 16; j++) {
    ctr[j] = tmp & 0xff;
    tmp >>= 8;
}

console.log('Counter block:', Buffer.from(ctr).toString('hex'));
console.log('Expected counter: 0000000200000000' + blockIndex.toString(16).padStart(16, '0'));
console.log('');

// Encrypt counter with AES-ECB
const aes = new aesjs.AES(key);
const encryptedCtr = aes.encrypt(ctr);

console.log('Encrypted counter (keystream block):', Buffer.from(encryptedCtr).toString('hex'));
console.log('Expected (from Python):           4d101641764aa9f1c...');
console.log('');

// Now test with full CTR mode from aes-js
const counter = new aesjs.Counter(blockIndex);
const aesCtr = new aesjs.ModeOfOperation.ctr(key, counter);

// Encrypt zeros to get keystream
const zeros = new Uint8Array(48);
const keystream = aesCtr.encrypt(zeros);

console.log('Keystream from aes-js CTR (first 48 bytes):');
console.log(Buffer.from(keystream).toString('hex'));
console.log('');

// Compare first 8 bytes
const expectedStart = '4d101641764aa9f1c';
const actualStart = Buffer.from(keystream.slice(0, 8)).toString('hex');
console.log('Match:', actualStart === expectedStart ? 'YES!' : 'NO');
console.log('Expected:', expectedStart);
console.log('Actual:  ', actualStart);
