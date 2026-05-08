let ready = false;
let zstddecModule = null;

class ZstdDecompressor {
    constructor() {
    }

    static async load() {
        if (ready) return;
        const module = await import('../static/zstddec.mjs');
        zstddecModule = module;
        ready = true;
    }

    async decompress(data) {
        await ZstdDecompressor.load();
        if (!zstddecModule) throw new Error('zstddec not loaded');
        const decoder = new zstddecModule.ZSTDDecoder();
        await decoder.init();
        return decoder.decode(data, 0);
    }

    static async decompressStreaming(data, callback) {
        await ZstdDecompressor.load();
        if (!zstddecModule) throw new Error('zstddec not loaded');
        const decoder = new zstddecModule.ZSTDDecoder();
        await decoder.init();
        const decompressed = decoder.decode(data, 0);
        callback(decompressed);
    }
}

export { ZstdDecompressor };
