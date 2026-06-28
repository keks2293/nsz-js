import { AesCtr } from './crypto/aesctr.mjs';

const key = new Uint8Array(16).fill(0xAB);
const nonce = new Uint8Array(8).fill(0x01);
const MB = 1024 * 1024;
const CHUNK = 16 * MB;

// Warmup
for (let i = 0; i < 5; i++) {
    const w = new AesCtr(key, nonce);
    w.encrypt(new Uint8Array(CHUNK));
}

// Encrypt benchmark: 500MB
const aes = new AesCtr(key, nonce);
const data = new Uint8Array(CHUNK);
const totalMB = 500;
const iterations = Math.ceil(totalMB / 16);

let start = performance.now();
for (let i = 0; i < iterations; i++) {
    await aes.encrypt(data);
}
let elapsed = performance.now() - start;
console.log(`AES-CTR encrypt ${totalMB}MB: ${elapsed.toFixed(0)}ms (${(totalMB / (elapsed / 1000)).toFixed(0)} MB/s)`);

// Decrypt benchmark
const aes2 = new AesCtr(key, nonce);
start = performance.now();
for (let i = 0; i < iterations; i++) {
    await aes2.decrypt(data);
}
elapsed = performance.now() - start;
console.log(`AES-CTR decrypt ${totalMB}MB: ${elapsed.toFixed(0)}ms (${(totalMB / (elapsed / 1000)).toFixed(0)} MB/s)`);

// Seek+decrypt: 500MB with 1MB chunks + seeks (NCZ pattern)
const aes3 = new AesCtr(key, nonce);
const smallChunk = new Uint8Array(MB);
const seekIters = 500;
start = performance.now();
for (let i = 0; i < seekIters; i++) {
    aes3.seek(i * MB);
    await aes3.decrypt(smallChunk);
}
elapsed = performance.now() - start;
console.log(`AES-CTR seek+decrypt ${seekIters}MB (500 seeks): ${elapsed.toFixed(0)}ms (${(seekIters / (elapsed / 1000)).toFixed(0)} MB/s)`);
