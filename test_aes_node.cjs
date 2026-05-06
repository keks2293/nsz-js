const { AESCTR } = require('./crypto/aesctr.cjs');

// Test data from Python output
const key = Buffer.from('3c8358e37c54aca5bb20fc36741c1727', 'hex');
const nonce = Buffer.from('00000002000000000000000000000000', 'hex');
const offset = 131072; // 0x20000

console.log('Key:', key.toString('hex'));
console.log('Nonce:', nonce.toString('hex'));
console.log('Offset:', offset, '(0x' + offset.toString(16) + ')');
console.log('Block Index:', offset >> 4);
console.log();

// Create AESCTR instance
const aesctr = new AESCTR(key, nonce);

// Generate keystream at offset
const zeros = Buffer.alloc(48, 0);
const keystream = aesctr.decrypt(zeros, offset);

console.log('Keystream (first 48 bytes):');
console.log(Buffer.from(keystream).toString('hex'));
console.log();

// Expected from Python
const expected = 'e95fed2b7d0afca982d145a0ddea1c84799cd6049be13c145365e02e7c0cd67c7dda265086d308349093deb0c56bd1e5';
console.log('Expected:', expected);
console.log('Match:', Buffer.from(keystream).toString('hex') === expected);
