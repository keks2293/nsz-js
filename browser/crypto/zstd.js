let globalReady = false;

class ZstdDecompressor {
    constructor() {
    }

    static async load() {
        if (globalReady) return;
        
        await new Promise((resolve, reject) => {
            console.log('[ZSTD] Loading fzstd from CDN...');
            
            const script = document.createElement('script');
            script.src = 'https://unpkg.com/fzstd@0.1.1';
            script.crossOrigin = 'anonymous';
            script.onload = () => {
                console.log('[ZSTD] fzstd loaded:', typeof fzstd);
                globalReady = true;
                resolve();
            };
            script.onerror = () => {
                console.error('[ZSTD] Failed to load fzstd');
                reject(new Error('Failed to load fzstd'));
            };
            document.head.appendChild(script);
        });
    }

    decompress(data) {
        console.log('[ZSTD] fzstd decompress input:', data.length, 'bytes');
        console.log('[ZSTD] first bytes:', Array.from(data.slice(0, 8)));
        
        try {
            if (typeof fzstd !== 'undefined' && fzstd.decompress) {
                const result = fzstd.decompress(data);
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