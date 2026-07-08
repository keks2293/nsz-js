import { ZSTDDecoder } from '../static/zstddec.mjs';

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

export { ZstdDecompressor };
