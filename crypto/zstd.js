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

    // Decompress using fzstd streaming API (Decompress class)
    decompressStreaming(data) {
        if (typeof fzstd !== 'undefined' && fzstd.Decompress) {
            const chunks = [];
            const stream = new fzstd.Decompress((chunk, isLast) => {
                chunks.push(chunk);
            });
            stream.push(data, true);
            
            if (chunks.length === 0) return new Uint8Array(0);
            
            const totalLen = chunks.reduce((a, b) => a + b.length, 0);
            const result = new Uint8Array(totalLen);
            let pos = 0;
            for (const chunk of chunks) {
                result.set(chunk, pos);
                pos += chunk.length;
            }
            return result;
        }
        return new Uint8Array(0);
    }
}

export { ZstdDecompressor };