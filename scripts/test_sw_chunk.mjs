// Unit test for SWDownloader (sw-downloader.js). Simulates the SW with a
// fake postMessage sink and verifies:
//   1. concatenated posted bytes equal the logical output byte-for-byte
//   2. bytesWritten tracks the expected final size
//   3. subarray views over a large buffer are posted as copies
//   4. small full-buffer views are transferred zero-copy
//   5. negative gap throws
// Run from scripts/: node test_sw_chunk.mjs
import { SWDownloader } from '../sw-downloader.js';

class MockSWContainer extends EventTarget {
    ready = Promise.resolve({ active: null });
}

globalThis.location = { pathname: '/app/' };

let failures = 0;
function check(cond, msg) {
    if (cond) { console.log('  ok: ' + msg); }
    else { console.log('  FAIL: ' + msg); failures++; }
}

function makeData(len, seed) {
    const b = new Uint8Array(len);
    let s = (seed >>> 0) || 1;
    for (let i = 0; i < len; i++) {
        s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
        b[i] = s & 0xff;
    }
    return b;
}

class FakeSW {
    posts = [];
    postMessage(msg) {
        this.posts.push(msg);
        if (msg.type === 'start') {
            queueMicrotask(() => {
                const ev = new MessageEvent('message', { data: { type: 'ready', url: msg.url } });
                navigator.serviceWorker.dispatchEvent(ev);
            });
        }
    }
    stream() {
        const parts = this.posts.filter(p => p.type === 'data').map(p => new Uint8Array(p.chunk));
        let total = 0;
        for (const p of parts) total += p.byteLength;
        const out = new Uint8Array(total);
        let off = 0;
        for (const p of parts) { out.set(p, off); off += p.byteLength; }
        return out;
    }
}

async function makeDL(name) {
    const sw = new FakeSW();
    const mockContainer = new MockSWContainer();
    mockContainer.ready = Promise.resolve({ active: sw });
    Object.defineProperty(globalThis, 'navigator', {
        value: { serviceWorker: mockContainer },
        writable: true, configurable: true,
    });
    const dl = new SWDownloader(name, null);
    await dl.start();
    return { dl, sw };
}

class Expected {
    constructor() { this.chunks = []; }
    write(position, data) {
        this.chunks.push({ position, bytes: new Uint8Array(data) });
    }
    build() {
        const last = this.chunks[this.chunks.length - 1];
        const total = last.position + last.bytes.byteLength;
        const out = new Uint8Array(total);
        for (const c of this.chunks) out.set(c.bytes, c.position);
        return out;
    }
}

const MB = 1024 * 1024;

// ── Case 1: the buffered-path write sequence (sizes scaled down) ────────────
console.log('Case 1: buffered-path write sequence');
{
    const { dl, sw } = await makeDL('test.nsp');
    const exp = new Expected();

    const exefs = 12 * MB, dataLevel = 20 * MB;
    let p = 0;
    const at = (len, gap = 0) => { p += gap; const pos = p; p += len; return pos; };
    const writes = [
        [at(0x110), makeData(0x110, 1)],
        [at(0xC00), makeData(0xC00, 2)],
        [at(0xB000), makeData(0xB000, 3)],
        [at(exefs), makeData(exefs, 4)],
        [at(0x4000, 288), makeData(0x4000, 5)],
        [at(0x4000), makeData(0x4000, 6)],
        [at(0x4000), makeData(0x4000, 7)],
        [at(0x4000), makeData(0x4000, 8)],
        [at(0x124000), makeData(0x124000, 9)],
        [at(dataLevel), makeData(dataLevel, 10)],
        [at(0xAB8), makeData(0xAB8, 11)],
        [at(0x28A00, 0x9000000 - p), makeData(0x28A00, 12)],
        [at(0x25C800), makeData(0x25C800, 13)],
        [at(0x1000), makeData(0x1000, 14)],
    ];
    for (const [pos, data] of writes) {
        await dl.write(pos, data);
        exp.write(pos, data);
    }
    const expected = exp.build();
    const stream = sw.stream();
    check(stream.byteLength === expected.byteLength, `stream length ${stream.byteLength} == expected ${expected.byteLength}`);
    check(stream.every((b, i) => b === expected[i]), 'stream bytes identical to expected layout');
    check(dl.bytesWritten === expected.byteLength, `bytesWritten ${dl.bytesWritten} == ${expected.byteLength}`);
    console.log(`  (info: ${sw.posts.length} posts, total ${stream.byteLength} bytes)`);
}

// ── Case 2: subarray view over large buffer ────────────────────────────────
console.log('Case 2: subarray view over large buffer');
{
    const { dl, sw } = await makeDL('test.nsp');
    const big = makeData(64 * MB, 31);
    const view = big.subarray(1000, 1000 + 12 * MB);
    await dl.write(0, view);
    const posts = sw.posts.filter(p => p.type === 'data');
    check(posts.length === 1, `12 MB subarray -> ${posts.length} posts (no chunking)`);
    let postsUseBigBuffer = false;
    for (const p of posts) if (p.chunk === big.buffer) postsUseBigBuffer = true;
    check(!postsUseBigBuffer, 'no post transfers the underlying 64 MB buffer');
    check(big.buffer.byteLength === 64 * MB, 'underlying buffer still intact (not detached)');
    const stream = sw.stream();
    check(stream.byteLength === view.byteLength && stream.every((x, i) => x === view[i]), 'subarray content delivered intact');
    check(dl.bytesWritten === view.byteLength, 'bytesWritten correct for subarray view');
}

// ── Case 3: small full-buffer write ─────────────────────────────────────────
console.log('Case 3: small full-buffer write transferred as-is');
{
    const { dl, sw } = await makeDL('test.nsp');
    const small = makeData(0x1000, 41);
    await dl.write(0, small);
    const p = sw.posts.find(x => x.type === 'data');
    check(p.chunk === small.buffer, 'small full-buffer view posts its own buffer (no copy)');
    check(p.chunk.byteLength === small.byteLength, 'posted buffer size exact');
}

// ── Case 4: gap fill + data ────────────────────────────────────────────────
console.log('Case 4: gap fill and data');
{
    const { dl, sw } = await makeDL('test.nsp');
    const d = makeData(4096, 51);
    await dl.write(100, d);
    const posts = sw.posts.filter(p => p.type === 'data');
    check(posts.length === 2, `gap + data -> ${posts.length} posts`);
    check(posts[0].chunk.byteLength === 100, 'gap post is 100 bytes');
    check(posts[1].chunk.byteLength === 4096, 'data post is 4096 bytes');
    const stream = sw.stream();
    let gapOk = true;
    for (let i = 0; i < 100; i++) if (stream[i] !== 0) gapOk = false;
    check(gapOk, 'gap bytes are zeros');
    check(stream.slice(100).every((x, i) => x === d[i]), 'data bytes match after gap');
    check(dl.bytesWritten === 100 + 4096, `bytesWritten ${dl.bytesWritten} == ${100 + 4096}`);
}

// ── Case 5: negative gap throws ────────────────────────────────────────────
console.log('Case 5: negative gap throws');
{
    const { dl } = await makeDL('test.nsp');
    await dl.write(1000, makeData(500, 61));
    let threw = false;
    try {
        await dl.write(500, makeData(100, 62));
    } catch (e) {
        threw = true;
        check(e.message.includes('backward'), 'error mentions backward write');
    }
    check(threw, 'backward write throws');
}

if (failures) {
    console.log(`\n${failures} FAILURES`);
    process.exit(1);
}
console.log('\nALL PASS');
