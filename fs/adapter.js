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
        return {
            read,
            write: (offset, data) => output.writable.write({ type: 'write', position: offset, data }),
            log, progress, createHash,
        };
    }
    if (output.memory) {
        const chunks = [];
        return {
            read,
            write: (offset, data) => { chunks.push({ offset, data }); },
            log, progress, createHash,
            _chunks: chunks,
        };
    }
    throw new Error('convert: output must be { fd }, { writable }, or { memory: true }');
}

function collectBlob(adapter, totalSize) {
    const chunks = adapter._chunks.sort((a, b) => a.offset - b.offset);
    const buf = new Uint8Array(totalSize);
    for (const c of chunks) buf.set(c.data, c.offset);
    return new Blob([buf], { type: 'application/octet-stream' });
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
    if (output.writable && typeof output.writable.seek === 'function') {
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
