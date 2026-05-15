let ready = false;
let sharedDecoder = null;
let wasmInstance = null;

class ZstdDecompressor {
    static async load() {
        if (ready) return;
        const module = await import('../static/zstddec.mjs');

        const OrigDecoder = module.ZSTDDecoder;
        class CapturingDecoder extends OrigDecoder {
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

    static async decompressStreaming(data, callback) {
        await ZstdDecompressor.load();
        if (!sharedDecoder) throw new Error('zstddec not loaded');
        const decompressed = sharedDecoder.decode(data, 0);
        callback(decompressed);
    }
}

export { ZstdDecompressor };
