import { ZSTDDecoder } from '../static/zstddec.mjs';
import { isNode } from './platform.js';

let ready = false;
let sharedDecoder = null;
let wasmInstance = null;

class ZstdDecompressor {
    static async load() {
        if (ready) return;

        class CapturingDecoder extends ZSTDDecoder {
            _init(result) {
                wasmInstance = result.instance;
                return super._init(result);
            }
        }

        sharedDecoder = new CapturingDecoder();
        await sharedDecoder.init();
        ready = true;
    }

    static get instance() {
        return wasmInstance;
    }

    static get wasmBuffer() {
        return wasmInstance ? wasmInstance.exports.memory.buffer : null;
    }

    static async decompressBuffer(data) {
        await ZstdDecompressor.load();
        if (!sharedDecoder) throw new Error('zstddec not loaded');
        return sharedDecoder.decode(data, 0);
    }

}

let nodeZlibPromise = null;
function decompressNode(data) {
    if (!nodeZlibPromise) nodeZlibPromise = import('node:zlib');
    return nodeZlibPromise.then(m => new Uint8Array(m.zstdDecompressSync(data)));
}

// Decompress one NCZBLOCK block (returns a Promise). Node uses in-process
// node:zlib; browser uses the zstddec WASM decoder. Whether a block is stored
// raw (incompressible) vs compressed is container-level knowledge kept in
// fs/ncz.js, not here.
function decompressBlock(data) {
    if (isNode) return decompressNode(data);
    return ZstdDecompressor.decompressBuffer(data);
}

// Node streaming backend: push-compressed model (write/end + backpressure),
// output consumed concurrently via the async iterator so the zlib transform
// stream never deadlocks on a full readable buffer.
async function* decompressNodeStream(readChunk) {
    const { createZstdDecompress } = await import('node:zlib');
    const decompressor = createZstdDecompress({ highWaterMark: 1024 * 1024 });
    const outIt = decompressor[Symbol.asyncIterator]();
    const feed = (async () => {
        while (true) {
            const chunk = await readChunk();
            if (!chunk || !chunk.byteLength) break;
            if (!decompressor.write(chunk)) {
                await new Promise(res => decompressor.once('drain', res));
            }
        }
        decompressor.end();
    })();
    try {
        while (true) {
            const { value, done } = await outIt.next();
            if (done) break;
            if (value && value.byteLength) {
                yield new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
            }
        }
    } finally {
        await feed;
    }
}

// Stream-decompress lazily from an async readChunk() source, yielding
// decompressed chunks. Single platform dispatch: Node uses in-process
// node:zlib, browser uses the zstddec WASM streaming wrapper. Consumers don't
// import platform-specific modules nor branch on isNode.
async function* decompressStream(readChunk) {
    if (isNode) {
        yield* decompressNodeStream(readChunk);
        return;
    }
    const { initZstddec, decodeStream } = await import('./zstddec-stream-wrapper.js');
    await initZstddec();
    yield* decodeStream(readChunk);
}

export { ZstdDecompressor, decompressBlock, decompressStream };
