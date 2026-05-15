// Wraps zstddec WASM exports directly (ZSTD_createDCtx / ZSTD_decompressStream)
// to stream-decompress without pre-buffering all compressed data.
// Unlike ZstdDecompressor.decompressBuffer() which needs the full input at once,
// this feeds chunks lazily via an async readChunk function.

import { ZstdDecompressor } from './zstd.js';

export async function initZstddec() {
    await ZstdDecompressor.load();
}

function memView(instance) {
    return new DataView(instance.exports.memory.buffer);
}

export async function* decodeStream(readChunk) {
    const instance = ZstdDecompressor.instance;
    if (!instance) throw new Error('Call initZstddec() first');
    const $ = instance.exports;
    const dctx = $.ZSTD_createDCtx();
    const outSize = $.ZSTD_DStreamOutSize();
    const outBuf = $.malloc(outSize);
    const SZ_P = 4, SZ_T = 4, offPos = SZ_P + SZ_T, offSize = SZ_P + SZ_T * 2;
    const inP = $.malloc(offSize);
    const outP = $.malloc(offSize);
    let ret = 0;
    try {
        while (true) {
            const array = await readChunk();
            if (!array || !array.byteLength) break;
            const cp = $.malloc(array.byteLength);
            new Uint8Array(instance.exports.memory.buffer).set(array, cp);
            let mv = memView(instance);
            mv.setInt32(inP, cp, true);
            mv.setInt32(inP + SZ_P, array.byteLength, true);
            mv.setInt32(inP + offPos, 0, true);
            while (mv.getUint32(inP + offPos, true) < mv.getUint32(inP + SZ_P, true)) {
                mv.setInt32(outP, outBuf, true);
                mv.setInt32(outP + SZ_P, outSize, true);
                mv.setInt32(outP + offPos, 0, true);
                ret = $.ZSTD_decompressStream(dctx, outP, inP);
                mv = memView(instance);
                const outputPos = mv.getUint32(outP + offPos, true);
                yield new Uint8Array(instance.exports.memory.buffer, outBuf, outputPos);
            }
            $.free(cp);
        }
    } finally {
        $.ZSTD_freeDCtx(dctx);
        $.free(outBuf);
        $.free(inP);
        $.free(outP);
    }
    if (ret !== 0) throw new Error('Incomplete zstd stream, more data expected.');
}
