// Sequential-only SW download writer. The SW exposes a ReadableStream that is
// consumed by the browser's download mechanism (iframe navigation) — it can
// only APPEND bytes, never seek. SWDownloader tracks the absolute stream
// position and fills gaps between out-of-order writes with zeros.
//
// Kept in a separate module (no DOM at module scope) so the logic is
// unit-testable in Node (scripts/test_sw_chunk.mjs).

export class SWDownloader {
    #streamError = '';
    #swMsgHandler = null;
    #pos = 0;

    constructor(outputName, iframe) {
        const base = location.pathname.substring(0, location.pathname.lastIndexOf('/') + 1) || '/';
        this.streamUrl = (base + 'download/' + crypto.randomUUID()).replace(/\/+/g, '/');
        this.outputName = outputName;
        this.sw = null;
        this.iframe = iframe || null;
    }

    async start() {
        const reg = await navigator.serviceWorker.ready;
        this.sw = reg.active;
        if (!this.sw) throw new Error('No active service worker');

        this.#swMsgHandler = e => this.#onSWMsg(e);
        navigator.serviceWorker.addEventListener('message', this.#swMsgHandler);

        return new Promise((resolve) => {
            const onMessage = (e) => {
                if (e.data.type === 'ready' && e.data.url === this.streamUrl) {
                    navigator.serviceWorker.removeEventListener('message', onMessage);
                    resolve();
                }
            };

            navigator.serviceWorker.addEventListener('message', onMessage);
            this.sw.postMessage({ type: 'start', url: this.streamUrl, fileName: this.outputName });
        });
    }

    #onSWMsg(e) {
        if (e.data.type === 'error' && e.data.url === this.streamUrl) {
            this.#streamError = e.data.message;
        }
    }

    #postChunk(bytes) {
        this.sw.postMessage({ type: 'data', url: this.streamUrl, chunk: bytes.buffer }, [bytes.buffer]);
    }

    triggerDownload() {
        const url = this.streamUrl + '?name=' + encodeURIComponent(this.outputName);
        if (/iPhone|iPad|iPod/i.test(navigator.userAgent)) {
            window.open(url, '_blank');
            return;
        }
        this.iframe.src = url;
    }

    get bytesWritten() { return this.#pos; }

    async write(position, data) {
        if (!this.sw) return;
        if (this.#streamError) throw new Error('SW stream lost (' + this.#streamError + ')');

        const view = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
        const len = view.byteLength;

        // Fill any gap with zeros.
        const gap = position - this.#pos;
        if (gap < 0) {
            throw new Error(`SWDownloader: backward write at 0x${position.toString(16)} (current=0x${this.#pos.toString(16)}, gap=${gap})`);
        }
        if (gap > 0) {
            this.#postChunk(new Uint8Array(gap));
            this.#pos += gap;
        }

        if (len === 0) return;

        // Zero-copy where possible: a FULL-buffer view is transferred as-is
        // (no memcpy). Subarray views ALWAYS go through a copy.
        const chunk = (view.byteLength !== view.buffer.byteLength) ? view.slice(0) : view;
        this.#postChunk(chunk);
        this.#pos = position + len;
    }

    async close() {
        if (this.#swMsgHandler) {
            navigator.serviceWorker.removeEventListener('message', this.#swMsgHandler);
            this.#swMsgHandler = null;
        }
        if (this.sw) this.sw.postMessage({ type: 'end', url: this.streamUrl });
    }
}
