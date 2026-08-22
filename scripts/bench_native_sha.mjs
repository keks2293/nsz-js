// Benchmark: native vs pure-JS SHA256 at realistic sizes
// Typical Switch update: 100-300 MB RomFS, 10-50 MB ExeFS

import { createHash, randomBytes } from 'node:crypto';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { sha256, SHA256 } = require('../crypto/sha256.js');

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i >> 1] = parseInt(hex.substring(i, i + 2), 16);
    return bytes;
}

function bench(label, fn, rounds) {
    for (let i = 0; i < 500; i++) fn(); // warmup
    const t0 = performance.now();
    for (let i = 0; i < rounds; i++) fn();
    const ms = performance.now() - t0;
    return ms;
}

function makeBlock(size) {
    const buf = new Uint8Array(size);
    randomBytes(size).copy(Buffer.from(buf.buffer));
    return buf;
}

const scenarios = [
    { name: 'IVFC 16KB blocks (RomFS 100 MB)', blockSize: 0x4000, blocks: Math.ceil(100e6 / 0x4000) },
    { name: 'IVFC 16KB blocks (RomFS 300 MB)', blockSize: 0x4000, blocks: Math.ceil(300e6 / 0x4000) },
    { name: 'PFS0 64KB blocks (ExeFS 20 MB)',  blockSize: 0x10000, blocks: Math.ceil(20e6 / 0x10000) },
];

for (const { name, blockSize, blocks } of scenarios) {
    const buf = makeBlock(blockSize);
    const totalMB = (blocks * blockSize / 1e6).toFixed(0);

    const jsMs = bench('JS', () => { const h = new SHA256(); h.update(buf); h.digest(); }, blocks);
    const nativeMs = bench('native', () => { createHash('sha256').update(buf).digest(); }, blocks);

    console.log(`${name}:`);
    console.log(`  pure JS:  ${jsMs.toFixed(0)} ms  (${totalMB} MB, ${blocks} blocks)`);
    console.log(`  native:   ${nativeMs.toFixed(0)} ms`);
    console.log(`  speedup:  ${(jsMs / nativeMs).toFixed(1)}×\n`);
}
