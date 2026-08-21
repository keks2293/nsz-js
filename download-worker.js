const streams = new Map();
const reasons = new Map();

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('message', e => {
    const { type, url } = e.data;

    if (type === 'start') {
        let resolveController;
        const controllerReady = new Promise(resolve => resolveController = resolve);

        const stream = new ReadableStream({
            start(controller) {
                resolveController(controller);
            },
            cancel() {
                reasons.set(url, 'cancelled');
                streams.delete(url);
            }
        }, { highWaterMark: 1 });

        const entry = {
            stream, controllerReady,
            fileName: e.data.fileName,
            client: e.source,
        };
        streams.set(url, entry);
        reasons.delete(url);
        e.source.postMessage({ type: 'ready', url });
        return;
    }

    const entry = streams.get(url);
    if (!entry) {
        const reason = reasons.get(url) || 'not-registered';
        e.source.postMessage({ type: 'error', url, message: reason });
        return;
    }

    if (type === 'data') {
        const chunkCopy = new Uint8Array(e.data.chunk);
        entry.controllerReady.then(c => {
            c.enqueue(chunkCopy);
        });
    } else if (type === 'end') {
        reasons.set(url, 'closed');
        entry.controllerReady.then(c => { c.close(); streams.delete(url); });
    } else if (type === 'error') {
        reasons.set(url, 'error');
        entry.controllerReady.then(c => { c.error(new Error(e.data.message)); streams.delete(url); });
    }
});

self.addEventListener('fetch', e => {
    const url = new URL(e.request.url);
    const match = url.pathname.match(/\/download\/([^/]+)$/);
    if (match) {
        const entry = streams.get(url.pathname);
        if (entry) {
            e.respondWith(new Response(entry.stream, {
                headers: {
                    'Content-Type': 'application/octet-stream',
                    'Content-Disposition': `attachment; filename="${(url.searchParams.get('name') || 'download').replace(/[\x00-\x1f\x7f"\\]/g, '_')}"`
                }
            }));
        }
    }
});
