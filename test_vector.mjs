import { AESCTR } from './crypto/aesctr.mjs';

// Section 5: AES-CTR Test Vector from Python nsz
// Run: node test_vector.mjs

const key = new Uint8Array(Buffer.from('3c8358e37c54aca5bb20fc36741c1727', 'hex'));
const nonce = new Uint8Array(Buffer.from('00000002000000000000000000000000', 'hex'));
const offset = 131072;

console.log('Key:', Buffer.from(key).toString('hex'));
console.log('Nonce:', Buffer.from(nonce).toString('hex'));
console.log('Offset:', offset, '(0x' + offset.toString(16) + ')');
console.log('BlockIdx:', offset >> 4);
console.log();

(async () => {
const aesctr = new AESCTR(key, nonce);
aesctr.seek(offset);
const keystream = await aesctr.decrypt(new Uint8Array(48));

console.log('Counter block (BE64):', '00000002000000000000000000002000');
console.log('Keystream:');
console.log(Buffer.from(keystream).toString('hex'));
console.log();

const expected = 'e95fed2b7d0afca982d145a0ddea1c84799cd6049be13c145365e02e7c0cd67c7dda265086d308349093deb0c56bd1e5';
console.log('Expected:');
console.log(expected);
console.log();
console.log('Result:', Buffer.from(keystream).toString('hex') === expected ? '✅ PASS' : '❌ FAIL');
})();
