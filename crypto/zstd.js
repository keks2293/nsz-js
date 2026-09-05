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
    let feedError = null;
    let aborted = false;
    // 'drain' wait must also resolve when the stream is destroyed (consumer
    // exited early) or errors out, otherwise feed deadlocks on backpressure
    // and nobody is consuming output anymore.
    const waitDrain = () => new Promise((resolve, reject) => {
        if (aborted) return resolve();
        const onDrain = () => { cleanup(); resolve(); };
        const onError = (e) => { cleanup(); reject(e); };
        const onClose = () => { cleanup(); resolve(); };
        const cleanup = () => {
            decompressor.removeListener('drain', onDrain);
            decompressor.removeListener('error', onError);
            decompressor.removeListener('close', onClose);
        };
        decompressor.once('drain', onDrain);
        decompressor.once('error', onError);
        decompressor.once('close', onClose);
    });
    const feed = (async () => {
        try {
            while (!aborted) {
                const chunk = await readChunk();
                if (!chunk || !chunk.byteLength) break;
                if (!decompressor.write(chunk)) {
                    await waitDrain();
                    if (aborted) return;
                }
            }
            if (!aborted) decompressor.end();
        } catch (e) {
            feedError = e;
            decompressor.destroy(e);
        }
    })();
    try {
        while (true) {
            const { value, done } = await outIt.next();
            if (done) break;
            if (value && value.byteLength) {
                yield new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
            }
        }
        await feed;
        if (feedError) throw feedError;
    } finally {
        aborted = true;
        if (!decompressor.destroyed) decompressor.destroy();
        await feed.catch(() => {});
    }
}

// Stream-decompress lazily from an async readChunk() source, yielding
// decompressed chunks. Single platform dispatch: Node uses in-process
// node:zlib, browser uses the zstddec WASM streaming wrapper. Consumers don't
// import platform-specific modules nor branch on isNode.
// Test/bench override: force the zstddec WASM path even under Node. node:zlib
// silently tolerates trailing garbage after a frame (which is why the NCZ
// reader-length bug sailed through the Node test suite), while the WASM wrapper
// throws (-10, prefix_unknown). The override lets tests hit the strict path and
// Node-side benchmarks AB node:zlib vs the WASM decoder.
let forceWasm = false;
function setZstdStreamForcedWasm(v = false) { forceWasm = v; }

async function* decompressStream(readChunk) {
    if (isNode && !forceWasm) {
        yield* decompressNodeStream(readChunk);
        return;
    }
    const { initZstddec, decodeStream } = await import('./zstddec-stream-wrapper.js');
    await initZstddec();
    yield* decodeStream(readChunk);
}

export { ZstdDecompressor, decompressBlock, decompressStream, setZstdStreamForcedWasm };
