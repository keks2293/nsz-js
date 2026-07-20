import { ZstdDecompressor } from './crypto/zstd.js';
import { DataReader } from './fs/ncz.js';
import { KeysParser } from './keys.js';
import { SHA256 } from './crypto/sha256.js';
import { extractContentHashes } from './fs/cnmt-hashes.js';
import { PFS0 } from './fs/pfs0.js';
import { XCIReader } from './fs/xci.js';
import { convertNSZStreaming } from './fs/nsz-convert.js';
import { convertXCZStreaming } from './fs/xcz-convert.js';

class FileSliceReader extends DataReader {
    constructor(file, baseOffset = 0, totalLength = null) {
        super();
        this.file = file;
        this.baseOffset = baseOffset;
        this._length = totalLength !== null ? totalLength : file.size - baseOffset;
    }

    get length() {
        return this._length;
    }

    async read(offset, size) {
        const absOffset = this.baseOffset + offset;
        const buffer = await this.file.slice(absOffset, absOffset + size).arrayBuffer();
        return new Uint8Array(buffer);
    }
}

class NSZConverter {
    constructor(keys = null) {
        this.keys = keys;
        this.initialized = false;
    }

    async init() {
        if (this.initialized) return;
        await ZstdDecompressor.load();
        this.initialized = true;
    }

    setKeys(keyText) {
        try {
            this.keys = KeysParser.parse(keyText);
            return true;
        } catch (e) {
            console.error('Failed to parse keys:', e);
            return false;
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async decompressNSZtoNSP(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, fixPadding = false, verify = false } = options;
        onLog('info', `Processing: ${file.name} (${this.formatBytes(file.size)})`);
        await this.init();

        const fileReader = new FileSliceReader(file, 0, file.size);
        const createHash = () => {
            const h = new SHA256();
            return { update: (d) => h.update(d), digest: () => h.hexdigest() };
        };

        const result = await convertNSZ(fileReader, this.keys, writable ? { writable } : { memory: true }, {
            verify, fixPadding,
            log: onLog,
            progress: onProgress,
            createHash,
            extractCnmtHashes: (d) => extractContentHashes(d, this.keys),
        });

        onProgress(1.0, 'Done!');
        const outputName = file.name.replace(/\.nsz$/i, '.nsp');
        onLog('success', `Output: ${outputName} (${this.formatBytes(result.size)})`);
        return { blob: result.blob || null, name: outputName, size: result.size, writable: !!writable };
    }

    async decompressXCZtoXCI(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, verify = false } = options;
        onLog('info', 'Parsing XCI container...');
        const fileReader = new FileSliceReader(file);
        const createHash = () => {
            const h = new SHA256();
            return { update: (d) => h.update(d), digest: () => h.hexdigest() };
        };

        const result = await convertXCZ(fileReader, this.keys, writable ? { writable } : { memory: true }, {
            verify,
            log: onLog,
            progress: onProgress,
            createHash,
            extractCnmtHashes: (d) => extractContentHashes(d, this.keys),
        });

        onProgress(1.0, 'Done!');
        const outputName = file.name.replace(/\.xcz$/i, '.xci');
        onLog('success', `Output: ${outputName} (${this.formatBytes(result.size)})`);
        return { blob: result.blob || null, name: outputName, size: result.size, writable: !!writable };
    }

}

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

export async function convertNSZ(reader, keys, output, options = {}) {
    const { verify = false, fixPadding = false, log = () => {}, progress = () => {}, createHash, extractCnmtHashes } = options;

    const pfs0 = await PFS0.open(reader);

    const cnmtHashes = new Set();
    if (extractCnmtHashes) {
        for (const f of pfs0.getFiles()) {
            if (f.name.toLowerCase().endsWith('.cnmt.nca')) {
                const data = await reader.read(f.offset, f.size);
                const hashes = await extractCnmtHashes(data);
                hashes.forEach(h => cnmtHashes.add(h));
            }
        }
    }

    const read = (offset, size) => reader.read(offset, size);
    const adapter = await buildAdapter(output, read, { log, progress, createHash });
    const result = await convertNSZStreaming(pfs0, keys, adapter, {
        verify, fixPadding, log, progress, createHash,
    }, cnmtHashes);

    const totalSize = result.headerSize + result.totalDataSize;
    if (output.memory) return { size: totalSize, blob: collectBlob(adapter, totalSize) };
    return { size: totalSize };
}

export async function convertXCZ(reader, keys, output, options = {}) {
    const { verify = false, log = () => {}, progress = () => {}, createHash, extractCnmtHashes } = options;

    const xci = new XCIReader(reader);
    await xci.parse();

    const read = (offset, size) => reader.read(offset, size);
    const adapter = await buildAdapter(output, read, { log, progress, createHash });
    const totalSize = await convertXCZStreaming(xci, keys, adapter, {
        verify, log, progress, createHash,
    }, extractCnmtHashes);

    if (output.memory) return { size: totalSize, blob: collectBlob(adapter, totalSize) };
    return { size: totalSize };
}

export { NSZConverter };
