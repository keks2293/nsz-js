#!/usr/bin/env node
// Manual AES-CTR test - standalone, no dependencies
// Test if our counter construction matches PyCryptodome

const crypto = require('crypto');

// Test parameters from the debug output
const key = Buffer.from('3c8358e37c54aca5bb20fc36741c1727', 'hex');
const nonce = Buffer.from('00000002000000000000000000000000', 'hex');
const offset = 131072; // 0x20000
const blockIndex = Math.floor(offset / 16);

console.log('Key:', key.toString('hex'));
console.log('Nonce:', nonce.toString('hex'));
console.log('Offset:', offset, '(0x' + offset.toString(16) + ')');
console.log('Block Index:', blockIndex);
console.log();

// Build counter block: nonce[0:8] + BE64(blockIndex) - matching PyCryptodome
const ctr = Buffer.alloc(16);
nonce.copy(ctr, 0, 0, 8);

// Write blockIndex as BIG-endian uint64 in bytes 8-15 (matching PyCryptodome default)
ctr.writeBigUInt64BE(BigInt(blockIndex), 8);

console.log('Counter block:', ctr.toString('hex'));
console.log('Expected:     00000002000000000000000000002000');
console.log();

// Encrypt counter with AES-ECB using Node.js crypto
const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
cipher.setAutoPadding(false);
let encryptedCtr = cipher.update(ctr);
encryptedCtr = Buffer.concat([encryptedCtr, cipher.final()]);

console.log('Encrypted counter (keystream block):', encryptedCtr.toString('hex'));
console.log('Expected (from Python):               4d101641764aa9f1c...');
console.log();

// Now test full CTR mode
// In Node.js crypto, CTR mode uses IV (which is the initial counter block)
const counterIV = Buffer.alloc(16);
nonce.copy(counterIV, 0, 0, 8);
counterIV.writeBigUInt64BE(BigInt(blockIndex), 8);

// For CTR, we need to use aes-128-ctr with the counter as IV
const ctrCipher = crypto.createCipheriv('aes-128-ctr', key, counterIV);
const plaintext = Buffer.alloc(48, 0); // zeros
const keystream = ctrCipher.update(plaintext);
// CTR doesn't need final

console.log('Keystream from Node.js CTR (first 48 bytes):');
console.log(keystream.toString('hex'));
console.log();

// Check first 8 bytes
const expectedStart = '4d101641764aa9f1c';
const actualStart = keystream.slice(0, 8).toString('hex');
console.log('Match:', actualStart === expectedStart ? 'YES!' : 'NO');
console.log('Expected:', expectedStart);
console.log('Actual:  ', actualStart);
