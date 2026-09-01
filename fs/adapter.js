async function buildAdapter(output, read, callbacks) {
    const { log = () => {}, progress = () => {}, createHash } = callbacks;

    if (output.fd !== undefined) {
        const fs = await import('node:fs');
        return {
            read,
            write: (offset, data) => fs.writeSync(output.fd, data, 0, data.byteLength, offset),
            log, progress, createHash,
        };
    }
    if (output.writable) {
        const w = output.writable;
        // FSA (FileSystemWritableFileStream) supports {type,position,data}; SWDownloader uses (pos, data).
        // Detect FSA by its seek() method (SWDownloader doesn't have it).
        const write = typeof w.seek === 'function'
            ? (offset, data) => w.write({ type: 'write', position: offset, data })
            : (offset, data) => w.write(offset, data);
        return { read, write, log, progress, createHash };
    }
    if (output.memory) {
        const chunks = output._chunks || (output._chunks = []);
        // Keep _chunks sorted by offset as writes arrive (seek-back writes land at
        // the head/middle). Chunks are disjoint — each write is a distinct region —
        // so insertion preserves order; the data itself is never copied, and Blob
        // references the chunks in place.
        const write = (offset, data) => {
            let lo = 0, hi = chunks.length;
            while (lo < hi) {
                const mid = (lo + hi) >> 1;
                if (chunks[mid].offset < offset) lo = mid + 1;
                else hi = mid;
            }
            chunks.splice(lo, 0, { offset, data });
        };
        return {
            read,
            write,
            log, progress, createHash,
            _chunks: chunks,
        };
    }
    throw new Error('convert: output must be { fd }, { writable }, or { memory: true }');
}

function collectBlob(adapter, totalSize) {
    // _chunks is kept sorted by offset at write time, so Blob can reference the
    // chunk buffers in place — zero copy, no extra flat buffer. Any overlap would
    // break this (doubled bytes), but writes are always into distinct regions.
    return new Blob(adapter._chunks.map(c => c.data), { type: 'application/octet-stream' });
}

// Build a seekable read(offset, length) for the output, or null if the output
// cannot be read back (e.g. sequential-only SW download, chunked memory). Used by
// the streaming update path to re-read the written Program NCA and compute its
// contentId (sha256) — mirroring hacpack's nca_calculate_hash reading the file.
async function buildRead(output) {
    if (output.fd !== undefined) {
        const fs = await import('node:fs');
        return (offset, length) => {
            const buf = Buffer.alloc(length);
            fs.readSync(output.fd, buf, 0, length, offset);
            return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
        };
    }
    // NOTE: the File System Access API's FileSystemWritableFileStream has seek()
    // but NO read() (MDN: only write/seek/truncate), so FSA outputs can't be read
    // back — they return null here and use the buffered path. Only a writable that
    // exposes BOTH seek() and read() is usable for the re-read contentId pass.
    if (output.writable && typeof output.writable.seek === 'function' && typeof output.writable.read === 'function') {
        return async (offset, length) => {
            await output.writable.seek(offset);
            const stream = await output.writable.read();
            const reader = stream.getReader();
            const out = new Uint8Array(length);
            let filled = 0;
            while (filled < length) {
                const { value, done } = await reader.read();
                if (done) break;
                const n = Math.min(value.length, length - filled);
                out.set(value.subarray(0, n), filled);
                filled += n;
            }
            reader.releaseLock();
            return out.subarray(0, filled);
        };
    }
    if (output.memory) {
        // Memory output buffers every write into output._chunks (kept sorted by
        // offset at write time, shared with buildAdapter). Read back by walking the
        // sorted chunks and copying only the requested range — no flat copy of the
        // whole output. Mirrors the fd read path and unlocks the streaming
        // single-decompression update path (contentId by re-read) for in-memory
        // browser outputs.
        return (offset, length) => {
            const chunks = output._chunks || [];
            const out = new Uint8Array(length);
            let filled = 0;
            for (const c of chunks) {
                if (c.offset >= offset + length) break;
                if (c.offset + c.data.length <= offset) continue;
                const s = Math.max(c.offset, offset);
                const e = Math.min(c.offset + c.data.length, offset + length);
                out.set(c.data.subarray(s - c.offset, e - c.offset), s - offset);
                filled += e - s;
            }
            return out.subarray(0, filled);
        };
    }
    return null;
}

const COPY_CHUNK = 8 * 1024 * 1024;

async function copyRange(reader, offset, size, write, onChunk) {
    for (let pos = 0; pos < size; pos += COPY_CHUNK) {
        const n = Math.min(COPY_CHUNK, size - pos);
        const data = await reader.read(offset + pos, n);
        await write(pos, data);
        if (onChunk) onChunk(n);
    }
}

export { buildAdapter, buildRead, collectBlob, copyRange };
