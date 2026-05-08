let globalReady = false;
let fzstdLib = null;

class ZstdDecompressor {
    constructor() {
    }

    static async load() {
        if (globalReady) return;

        try {
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
                if (chunks.length === 0) {
                    throw new Error('fzstd Decompress produced no output');
                }
                const result = new Uint8Array(chunks.reduce((acc, chunk) => acc + chunk.length, 0));
                let offset = 0;
                for (const chunk of chunks) {
                    result.set(chunk, offset);
                    offset += chunk.length;
                }
                return result;
            }
        } catch(e) {
            console.error('[ZSTD] fzstd error:', e.message);
            throw e;
        }

        throw new Error('fzstd not loaded or Decompress not available');
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
