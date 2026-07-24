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
        });

        streams.set(url, { stream, controllerReady, fileName: e.data.fileName });
        reasons.delete(url);
        console.log('[SW] registered stream for', url);
        e.source.postMessage({ type: 'ready', url });
        return;
    }

    const entry = streams.get(url);
    if (!entry) {
        const reason = reasons.get(url) || 'not-registered';
        console.warn('[SW] no stream for', url, 'reason:', reason);
        e.source.postMessage({ type: 'error', url, message: reason });
        return;
    }

    if (type === 'data') {
        entry.controllerReady.then(c => {
            c.enqueue(new Uint8Array(e.data.chunk));
        });
    } else if (type === 'end') {
        console.log('[SW] close stream for', url);
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
        console.log('[SW] fetch', url.pathname, 'found:', !!entry);
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
