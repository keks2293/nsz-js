import { PFS0Writer } from './pfs0.js';
import { NCZDecompressor, AdapterNCZReader } from './ncz.js';
import { PFS0 } from './pfs0.js';
import { sha256 } from '../crypto/sha256.js';
import { extractContentHashMap } from './cnmt-hashes.js';

function verifyHashByNcaId(hash, ncaId, cnmtHashMap, onLog) {
    const log = onLog || ((level, msg) => console.log(`  ${msg}`));
    if (cnmtHashMap.size > 0) {
        const expected = cnmtHashMap.get(ncaId);
        if (expected && expected === hash) {
            log('success', `[VERIFIED]   ${ncaId} ${hash}`);
        } else {
            log('error', `[CORRUPTED]  ${ncaId} expected ${expected || 'none'}, got ${hash}`);
            throw new Error(`Verification detected hash mismatch: ${ncaId}`);
        }
    }
}

function verifyFileNameHash(hash, nczName, ncaName, onLog) {
    const log = onLog || ((level, msg) => console.log(`  ${msg}`));
    const fileNameHash = nczName.replace(/\.[^.]+$/, '').toLowerCase().slice(0, 32);
    if (hash.slice(0, 32) === fileNameHash) {
        log('success', `[VERIFIED]   ${ncaName} ${hash}`);
    } else {
        log('error', `[MISMATCH]   Filename starts with ${fileNameHash} but ${hash.slice(0, 32)} was expected`);
        throw new Error(`Verification detected hash mismatch: ${ncaName}`);
    }
}

async function convertNSZStreaming(pfs0, keys, adapter, options, cnmtHashes = new Set()) {
    const { verify = false, fixPadding = false } = options;
    const files = pfs0.getFiles();

    const outputMeta = await collectOutputMeta(files, adapter, keys);

    const writer = new PFS0Writer(fixPadding, pfs0.stringTableSize);
    for (const m of outputMeta) {
        options.log('info', `[ADDING]     ${m.name} 0x${m.size.toString(16)} bytes to PFS0 at 0x${(writer.addpos || 0).toString(16)}`);
        writer.add(m.name, m.size);
    }
    const pfs0Header = writer.buildHeader();
    const header = pfs0Header.buffer;
    await adapter.write(0, header);

    let dataWritten = 0;
    const totalDataSize = outputMeta.reduce((s, m) => s + m.size, 0);
    const pct = (bytes) => bytes / totalDataSize;

    for (let idx = 0; idx < files.length; idx++) {
        const meta = outputMeta[idx];
        const f = files[idx];
        const writePos = pfs0Header.headerSize + writer.files[idx].offset;

        if (meta.isNcz) {
            options.log('info', `[EXISTS]     ${f.name}`);
            const hasher = verify ? options.createHash() : null;
            const nczReader = new AdapterNCZReader(adapter, meta.offset, meta.nczLen);
            const decomp = new NCZDecompressor(nczReader, keys);
            await decomp.decompress(
                (p) => options.progress(pct(dataWritten + meta.size * p), `Decompressing ${f.name}...`),
                async (chunk, offset) => {
                    if (hasher) hasher.update(chunk);
                    await adapter.write(writePos + offset, chunk);
                });
            if (hasher) {
                const hash = hasher.hex();
                options.log('info', `[NCA HASH]   ${hash}`);
                if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                    const ncaId = meta.name.replace(/\.nca$/i, '');
                    if (cnmtHashes.size > 0) {
                        verifyHashByNcaId(hash, ncaId, cnmtHashes, options.log);
                    } else {
                        verifyFileNameHash(hash, f.name, meta.name, options.log);
                    }
                }
            }
        } else {
            options.log('info', `[EXISTS]     ${f.name}`);
            options.progress(pct(dataWritten), `Copying ${f.name}...`);
            const data = await adapter.read(meta.offset, meta.size);
            if (verify && meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                const hash = await sha256(data);
                options.log('info', `[NCA HASH]   ${hash}`);
                const ncaId = meta.name.replace(/\.nca$/i, '');
                if (cnmtHashes.size > 0) {
                    verifyHashByNcaId(hash, ncaId, cnmtHashes, options.log);
                } else {
                    verifyFileNameHash(hash, f.name, meta.name, options.log);
                }
            }
            await adapter.write(writePos, data);
        }

        dataWritten += meta.size;
        options.progress(pct(dataWritten), `File ${idx + 1}/${files.length} done`);
    }

    return { headerSize: pfs0Header.headerSize, totalDataSize };
}

async function collectOutputMeta(files, adapter, keys) {
    const outputMeta = [];
    for (const f of files) {
        const isNcz = f.name.toLowerCase().endsWith('.ncz');
        const outputName = isNcz ? f.name.slice(0, -4) + '.nca' : f.name;
        if (isNcz) {
            const headerReader = new AdapterNCZReader(adapter, f.offset, Math.min(f.size, 0x10000));
            const tmpDecomp = new NCZDecompressor(headerReader, keys);
            const { ncaSize } = await tmpDecomp.getSections();
            outputMeta.push({ name: outputName, size: ncaSize, isNcz: true, offset: f.offset, nczLen: f.size });
        } else {
            outputMeta.push({ name: outputName, size: f.size, isNcz: false, offset: f.offset });
        }
    }
    return outputMeta;
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
    const { verify = false, fixPadding = false, log = () => {}, progress = () => {}, createHash, extractCnmtHashMap } = options;

    const pfs0 = await PFS0.open(reader);

    const cnmtHashMap = new Map();
    if (extractCnmtHashMap) {
        for (const f of pfs0.getFiles()) {
            if (f.name.toLowerCase().endsWith('.cnmt.nca')) {
                const data = await reader.read(f.offset, f.size);
                const m = await extractCnmtHashMap(data);
                for (const [ncaId, hash] of m) cnmtHashMap.set(ncaId, hash);
            }
        }
    }

    const read = (offset, size) => reader.read(offset, size);
    const adapter = await buildAdapter(output, read, { log, progress, createHash });
    const result = await convertNSZStreaming(pfs0, keys, adapter, {
        verify, fixPadding, log, progress, createHash,
    }, cnmtHashMap);

    const totalSize = result.headerSize + result.totalDataSize;
    if (output.memory) return { size: totalSize, blob: collectBlob(adapter, totalSize) };
    return { size: totalSize };
}


