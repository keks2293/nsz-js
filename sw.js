const streams = new Map();

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
                streams.delete(url);
            }
        });

        streams.set(url, { stream, controllerReady, fileName: e.data.fileName });
        e.source.postMessage({ type: 'ready', url });
        return;
    }

    const entry = streams.get(url);
    if (!entry) return;

    if (type === 'data') {
        entry.controllerReady.then(c => c.enqueue(new Uint8Array(e.data.chunk)));
    } else if (type === 'end') {
        entry.controllerReady.then(c => { c.close(); streams.delete(url); });
    } else if (type === 'error') {
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
                    'Content-Disposition': `attachment; filename="${url.searchParams.get('name') || 'download'}"`
                }
            }));
        }
    }
});
