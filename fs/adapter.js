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

export { buildAdapter, collectBlob };
