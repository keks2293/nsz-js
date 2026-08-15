import { randomFillSync } from 'node:crypto';
import { createDecipheriv } from 'node:crypto';
import { AesEcb, AesCtrJS, AesXts } from '../crypto/aes128.js';

// Micro-benchmark of the software AES primitives (in-memory, NO disk I/O).
// Run: node bench_aes128.mjs [mib]

const MIB = Number(process.argv[2] || 64);
const NIB = 1024 * 1024 * MIB;
const RUNS = 5;

const key16 = new Uint8Array(16).fill(0x11);
const key32 = new Uint8Array(32).fill(0x22);
const nonce = new Uint8Array(16).fill(0x07);

function mbps(mib, ms) { return ((mib) / (ms / 1000)).toFixed(1); }
function best(fn, runs = RUNS) {
    let best = Infinity;
    for (let i = 0; i < runs; i++) best = Math.min(best, fn());
    return best;
}

const data = new Uint8Array(NIB);
randomFillSync(data);

// 1. Software AES-CTR (js-fallback, per-chunk keystream XOR) — browser path.
const ecb = new AesEcb(key16);
const t1 = best(() => {
    const st = performance.now();
    const ctr = new Uint8Array(16).fill(0);
    for (let off = 0; off < NIB; off += (256 * 1024)) {
        AesCtrJS(ecb, ctr, data.subarray(off, off + 256 * 1024));
    }
    return performance.now() - st;
});
console.log(`AES-CTR software (js-fallback) ${MIB} MiB: ${mbps(MIB, t1)} MB/s (best of ${RUNS})`);

// 2. AES-XTS (software).
const xts = new AesXts(key32);
const t2 = best(() => {
    const st = process.hrtime.bigint();
    for (let off = 0; off < NIB; off += (4 * 1024 * 1024)) {
        xts.decrypt(data.subarray(off, off + 4 * 1024 * 1024), off / 0x200);
    }
    return Number(process.hrtime.bigint() - st) / 1e6;
});
console.log(`AES-XTS software             : ${mbps(MIB, t2)} MB/s (best of ${RUNS})`);

// 3. Native AES-128-CTR via node:crypto (reference for the Node path).
const t3 = best(() => {
    const c = createDecipheriv('aes-128-ctr', Buffer.from(key16), Buffer.from(nonce));
    const st = process.hrtime.bigint();
    let written = 0;
    for (let off = 0; off < NIB; off += (4 * 1024 * 1024)) {
        written += c.update(data.subarray(off, off + 4 * 1024 * 1024)).length;
    }
    return Number(process.hrtime.bigint() - st) / 1e6;
});
console.log(`AES-CTR native  (reference)  : ${mbps(MIB, t3)} MB/s (${RUNS})`);