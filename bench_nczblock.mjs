#!/usr/bin/env node
// In-memory NCZBLOCK real-pipeline benchmark: builds a synthetic NCZ image in
// RAM, decompresses it through the full pipeline (parseNczSections ->
// parseBlockSchedule -> AsyncBlockDecompressorReader -> decompressBlock),
// output DISCARDED (dev-null) so no bytes hit the SSD. Reports best of N runs
// in MB/s. Run: node bench_nczblock.mjs [runs]
import { zstdCompressSync } from 'node:zlib';
import { NCZDecompressor, BufferReader } from './fs/ncz.js';

const RUNS = Number(process.argv[2] || 5);
const BLOCK_EXP = 14;           // 16 KiB per block
const BLOCK_SIZE = 1 << BLOCK_EXP;
const N_BLOCKS = 2048;          // 32 MiB decompressed NCA
const NCA_SIZE = N_BLOCKS * BLOCK_SIZE;
const NCA_HEADER = 0x4000;

// compressible-ish payload (LCG; zstd -12 makes ~50% ratio)
const payload = new Uint8Array(NCA_SIZE);
for (let i = 0; i < NCA_SIZE; i++) payload[i] = ((i * 1103515245 + 12345) >>> 16) & 0xFF;

function u32le(view, bytes, offset, value) { view.setUint32(offset, value >>> 0, true); }
function u64le(view, bytes, offset, value) { view.setBigUint64(offset, BigInt(value), true); }
function ascii(s) { return new TextEncoder().encode(s); }

function buildNczBlock() {
    // NCZ staging: magic 'NCZSECTN' at 0x4000, then sectionCount u64,
    // then 1 section entry (64 B), then NCZBLOCK header + size list + data at headerEnd.
    const headerEnd = NCA_HEADER + 8 + 8 + 64;   // = 0x4050
    const sizeListOff = headerEnd + 24;
    const blockDataOff = sizeListOff + N_BLOCKS * 4;

    const blocks = [];
    let total = 0;
    for (let b = 0; b < N_BLOCKS; b++) {
        const piece = payload.subarray(b * BLOCK_SIZE, (b + 1) * BLOCK_SIZE);
        const c = zstdCompressSync(Buffer.from(piece), { level: 12 });
        if (c.length < piece.length) { blocks.push(c); total += c.length; }
        else { blocks.push(null); total += piece.length; }  // raw
    }

    const img = new Uint8Array(blockDataOff + total);
    const view = new DataView(img.buffer);

    img.set(ascii('NCZSECTN'), NCA_HEADER);
    u64le(view, img, NCA_HEADER + 8, 1);                    // sectionCount
    u64le(view, img, NCA_HEADER + 16, NCA_HEADER);          // sec offset
    u64le(view, img, NCA_HEADER + 24, NCA_SIZE);            // sec size
    u64le(view, img, NCA_HEADER + 32, 1);                   // cryptoType

    img.set(ascii('NCZBLOCK'), headerEnd);
    img[headerEnd + 11] = BLOCK_EXP;                       // blockSizeExponent
    u32le(view, img, headerEnd + 12, N_BLOCKS);
    u64le(view, img, headerEnd + 16, NCA_SIZE);            // decompressedSize

    let o = blockDataOff;
    for (let b = 0; b < N_BLOCKS; b++) {
        const dat = blocks[b];
        const len = dat ? dat.length : BLOCK_SIZE;
        u32le(view, img, sizeListOff + b * 4, len);
        if (dat) img.set(dat, o);
        o += len;
    }
    return img;
}

const image = buildNczBlock();
const imgMiB = image.length / 1048576;
console.log(`[NCZBLOCK] blocks: ${N_BLOCKS}, nca ${(NCA_SIZE / 1048576).toFixed(1)} MiB, img ${imgMiB.toFixed(1)} MiB (ratio ${(image.length / NCA_SIZE * 100).toFixed(0)}%)`);

let best = Infinity;
let bestMiB = 0;
for (let run = 0; run < RUNS; run++) {
    const t0 = process.hrtime.bigint();
    let bytes = 0;
    const decomp = new NCZDecompressor(new BufferReader(image));
    await decomp.decompress(
        () => {},
        (chunk) => { bytes += chunk.length; },   // DEV-NULL sink
    );
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    const mib = bytes / 1048576;
    const mbps = mib / (ms / 1000);
    console.log(`run ${run + 1}: ${ms.toFixed(1)} ms, ${mib.toFixed(1)} MiB, ${mbps.toFixed(0)} MB/s`);
    if (ms < best) { best = ms; bestMiB = mib; }
}
console.log(`best: ${(bestMiB / (best / 1000)).toFixed(0)} MB/s (${best.toFixed(1)} ms)`);