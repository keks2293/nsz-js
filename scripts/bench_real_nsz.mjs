import { openSync, fstatSync, readSync, readFileSync } from 'node:fs';
import { PFS0 } from '../fs/pfs0.js';
import { NCZDecompressor, AdapterNCZReader, parseNczSections } from '../fs/ncz.js';

// Real-pipeline benchmark: decompress a real .nsz (all NCZ members) with the
// output DISCARDED (dev-null semantics) — no decompressed bytes hit the disk,
// so the SSD is not worn. Run: node bench_real_nsz.mjs path/to/file.nsz [runs]
//
// Prints total decompressed MiB, wall time, and MB/s (best of N).

const NSZ_PATH = process.argv[2];
const RUNS = Number(process.argv[3] || 3);
if (!NSZ_PATH) {
    console.error('usage: node bench_real_nsz.mjs path/to/file.nsz [runs]');
    process.exit(1);
}

const fd = openSync(NSZ_PATH, 'r');
const fstat = fstatSync(fd);
const stat = { read };

async function read(offset, size) {
    const buf = Buffer.alloc(size);
    readSync(fd, buf, 0, size, offset);
    return new Uint8Array(buf);
}

const pfs0 = await PFS0.open(stat);
const files = pfs0.getFiles();
const nczs = files.filter((f) => f.name.toLowerCase().endsWith('.ncz'));
console.log(`[NSZ] ${NSZ_PATH}`);
console.log(`[NSZ] files: ${files.length}, NCZ: ${nczs.length}`);
if (!nczs.length) { console.error('no NCZ found'); process.exit(1); }
console.log(`[NSZ] NCZ total bytes: ${nczs.reduce((s, f) => s + f.size, 0).toLocaleString()}`);

const parsed = [];
for (const f of nczs) {
    const nczReader = new AdapterNCZReader(stat, f.offset, f.size);
    parsed.push(await parseNczSections(nczReader));
}

let best = Infinity;
let bestMiB = 0;
for (let run = 0; run < RUNS; run++) {
    const st = process.hrtime.bigint();
    let total = 0;
    for (let i = 0; i < nczs.length; i++) {
        const f = nczs[i];
        const nczReader = new AdapterNCZReader(stat, f.offset, f.size);
        const decomp = new NCZDecompressor(nczReader);
        await decomp.decompress(
            (p) => {},
            async (chunk, offset) => { total += chunk.length; }, // DEV-NULL: drop output
            parsed[i]);
    }
    const ms = Number(process.hrtime.bigint() - st) / 1e6;
    const mib = total / (1024 * 1024);
    const mbps = (mib / (ms / 1000)).toFixed(1);
    console.log(`run ${run + 1}: ${mib.toFixed(1)} MiB in ${ms.toFixed(0)} ms → ${mbps} MB/s`);
    if (ms < best) { best = ms; bestMiB = mib; }
}

console.log(`\nbest: ${bestMiB.toFixed(1)} MiB decompressed in ${best.toFixed(0)} ms → ${(bestMiB / (best / 1000)).toFixed(1)} MB/s (best of ${RUNS})`);
