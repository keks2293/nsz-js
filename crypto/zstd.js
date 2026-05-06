let globalReady = false;
let fzstdLib = null;

class ZstdDecompressor {
    constructor() {
    }

    static async load() {
        if (globalReady) return;

        try {
            console.log('[ZSTD] Loading fzstd from static (ESM)...');

            // ESM version - import directly (path relative to crypto/ folder)
            const module = await import('../static/fzstd.mjs');
            fzstdLib = module;
            globalReady = true;

            console.log('[ZSTD] fzstd loaded:', typeof fzstdLib.decompress);
        } catch(error) {
            console.error('[ZSTD] Failed to load fzstd:', error);
            throw error;
        }
    }

    async decompress(data) {
        await ZstdDecompressor.load();

        console.log('[ZSTD] fzstd decompress input:', data.length, 'bytes');
        console.log('[ZSTD] first bytes:', Array.from(data.slice(0, 8)));

        try {
            if (fzstdLib && fzstdLib.decompress) {
                const result = fzstdLib.decompress(data);
                console.log('[ZSTD] fzstd result:', result ? result.length + ' bytes' : 'null');
                return result || new Uint8Array(0);
            }
        } catch(e) {
            console.log('[ZSTD] fzstd error:', e.message);
        }

        return new Uint8Array(0);
    }
}

export { ZstdDecompressor };
