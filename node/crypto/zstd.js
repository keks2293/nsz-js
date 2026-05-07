let globalReady = false;
let fzstdLib = null;

class ZstdDecompressor {
    constructor() {
    }

    static async load() {
        if (globalReady) return;

        try {
            // ESM version - import directly (path relative to crypto/ folder)
            const module = await import('../static/fzstd.mjs');
            fzstdLib = module;
            globalReady = true;
        } catch(error) {
            console.error('[ZSTD] Failed to load fzstd:', error);
            throw error;
        }
    }

    async decompress(data) {
        await ZstdDecompressor.load();

        try {
            if (fzstdLib && fzstdLib.Decompress) {
                // fzstd ESM exports Decompress class
                const chunks = [];
                const decompressor = new fzstdLib.Decompress((chunk) => {
                    chunks.push(chunk);
                });
                decompressor.push(data, true); // true = final chunk
                const result = new Uint8Array(chunks.reduce((acc, chunk) => acc + chunk.length, 0));
                let offset = 0;
                for (const chunk of chunks) {
                    result.set(chunk, offset);
                    offset += chunk.length;
                }
                return result;
            }
        } catch(e) {
            console.log('[ZSTD] fzstd error:', e.message);
        }

        return new Uint8Array(0);
    }

    static async decompressStreaming(data, callback) {
        await ZstdDecompressor.load();

        try {
            if (fzstdLib && fzstdLib.Decompress) {
                const decompressor = new fzstdLib.Decompress(callback);
                decompressor.push(data, true);
            }
        } catch(e) {
            console.log('[ZSTD] fzstd streaming error:', e.message);
        }
    }
}

export { ZstdDecompressor };
