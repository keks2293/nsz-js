// Micro-benchmark: StreamingIvfcHasher + StreamingPfs0Hasher
// 128 MB of random data — measures the per-block hash hot path.

import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Load SHA256 from crypto/sha256.js
const { sha256, SHA256 } = require('../crypto/sha256.js');

// Inline the old implementation for comparison
const HEXES = new Array(256).fill().map((_, i) => i.toString(16).padStart(2, '0'));
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i >> 1] = parseInt(hex.substring(i, i + 2), 16);
    return bytes;
}
function oldDigest32(data) {
    return hexToBytes(sha256(data));
}
function newDigest32(data) {
    const h = new SHA256();
    h.update(data);
    return h.digest();
}

// ── Benchmark digest32 itself ──
const BLOCK = new Uint8Array(0x4000);
crypto.getRandomValues(BLOCK);
const ROUNDS = 65536; // 1 GB total

function benchDigest(label, fn) {
    // warm up
    for (let i = 0; i < 1000; i++) fn(BLOCK);
    const t0 = performance.now();
    for (let i = 0; i < ROUNDS; i++) fn(BLOCK);
    const ms = performance.now() - t0;
    const mb = (ROUNDS * 0x4000) / (1024 * 1024);
    console.log(`  ${label}: ${ms.toFixed(0)} ms  (${(mb / ms * 1000).toFixed(0)} MB/s)`);
    return ms;
}

console.log('digest32 (16 KB blocks × 65536 = 1 GB):');
const oldMs = benchDigest('hexToBytes(sha256())', oldDigest32);
const newMs = benchDigest('SHA256.digest()', newDigest32);
console.log(`  speedup: ${(oldMs / newMs).toFixed(2)}×`);

// ── Benchmark StreamingIvfcHasher: fill(0) vs no-fill ──
// Simulate the old vs new update loop
function benchIvfc(label, doFill) {
    const blockSize = 0x4000;
    const hashSize = 0x20;
    const numBlocks = ROUNDS;
    const h1 = new Uint8Array(numBlocks * hashSize);
    const buf = new Uint8Array(blockSize);
    let bufLen = 0, blockIdx = 0;

    // warm up
    for (let i = 0; i < 1000; i++) {
        const h = new SHA256(); h.update(BLOCK); h.digest();
    }

    const t0 = performance.now();
    for (let round = 0; round < ROUNDS; round++) {
        const chunk = BLOCK;
        let off = 0;
        while (off < chunk.length) {
            const space = blockSize - bufLen;
            const n = Math.min(space, chunk.length - off);
            buf.set(chunk.subarray(off, off + n), bufLen);
            bufLen += n;
            off += n;
            if (bufLen === blockSize) {
                const h = new SHA256(); h.update(buf);
                h1.set(h.digest(), blockIdx * hashSize);
                blockIdx++;
                if (doFill) buf.fill(0);
                bufLen = 0;
            }
        }
    }
    const ms = performance.now() - t0;
    console.log(`  ${label}: ${ms.toFixed(0)} ms`);
    return ms;
}

console.log('\nStreamingIvfcHasher update loop (1 GB):');
const oldIvfc = benchIvfc('with fill(0)', true);
const newIvfc = benchIvfc('without fill(0)', false);
console.log(`  speedup: ${(oldIvfc / newIvfc).toFixed(2)}×`);
