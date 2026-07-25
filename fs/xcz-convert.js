import { NCZDecompressor, AdapterNCZReader } from './ncz.js';
import { HFS0Writer } from './hfs0.js';
import { XCIReader } from './xci.js';
import { sha256 } from '../crypto/sha256.js';

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

const PARTITION_HEADER_SIZE = 0x8000;
const ROOT_HFS0_PADDED_SIZE = 0x8000;
const ROOT_HFS0_OFFSET = 0xF000;

async function buildPartitionMetas(xci, keys, verify, adapter, extractCnmtHashMap) {
    const partitions = xci.getPartitions();
    const partitionMetas = [];

    for (const partition of partitions) {
        if (partition.size === 0) {
            partitionMetas.push({ name: partition.name, files: [], totalSize: 0, hfs0BufferSize: 0, raw: false, cnmtHashMap: new Map() });
            continue;
        }

        let hfs0;
        try {
            hfs0 = await xci.readPartitionFiles(partition);
        } catch (e) {
            throw new Error(`Cannot parse partition ${partition.name} as HFS0: ${e.message}`);
        }

        const partitionFiles = hfs0.getFiles();

        const cnmtHashMap = new Map();
        if (verify && extractCnmtHashMap) {
            const cnmtFiles = partitionFiles.filter(f => f.name.toLowerCase().endsWith('.cnmt.nca'));
            for (const cnmtFile of cnmtFiles) {
                const cnmtData = await adapter.read(cnmtFile.offset, cnmtFile.size);
                const m = await extractCnmtHashMap(cnmtData);
                for (const [ncaId, hash] of m) cnmtHashMap.set(ncaId, hash);
            }
        }

        const fileMetas = [];
        for (const f of partitionFiles) {
            const isNcz = f.name.toLowerCase().endsWith('.ncz');
            const outputName = isNcz ? f.name.replace(/\.ncz$/i, '.nca') : f.name;
            if (isNcz) {
                const headerReader = new AdapterNCZReader(adapter, f.offset, Math.min(f.size, 0x10000));
                const tmpDecomp = new NCZDecompressor(headerReader, keys);
                const { ncaSize } = await tmpDecomp.getSections();
                fileMetas.push({ name: outputName, size: ncaSize, isNcz: true, offset: f.offset, nczLen: f.size, inputName: f.name });
            } else {
                fileMetas.push({ name: outputName, size: f.size, isNcz: false, offset: f.offset, inputName: f.name });
            }
        }

        const fileTotalSize = fileMetas.reduce((s, m) => s + m.size, 0);
        const tmpWriter = new HFS0Writer(PARTITION_HEADER_SIZE);
        for (const m of fileMetas) tmpWriter.addEntry(m.name, m.size);
        const hfs0BufferSize = tmpWriter.getHeaderSize();

        partitionMetas.push({
            name: partition.name,
            files: fileMetas,
            totalSize: fileTotalSize,
            hfs0BufferSize,
            raw: false,
            cnmtHashMap
        });
    }

    return partitionMetas;
}

function computeLayout(partitionMetas) {
    const rootWriter = new HFS0Writer(ROOT_HFS0_PADDED_SIZE);
    const partSizes = [];
    for (const pm of partitionMetas) {
        const partSize = pm.hfs0BufferSize + pm.totalSize;
        partSizes.push(partSize);
        rootWriter.addEntry(pm.name, partSize);
    }
    const rootHfs0 = rootWriter.buildHeader();
    const rootHeader = rootHfs0.buffer;
    const rootActualHeader = rootHfs0.actualHeader;

    let currentDataOffset = ROOT_HFS0_OFFSET + rootHfs0.headerSize;
    const partOffsets = [];
    for (let i = 0; i < partitionMetas.length; i++) {
        partOffsets.push({ name: partitionMetas[i].name, offset: currentDataOffset });
        currentDataOffset += partSizes[i];
    }
    const totalSize = currentDataOffset;

    return { rootWriter, rootHeader, rootActualHeader, partSizes, partOffsets, totalSize };
}

async function writeXciHeaders(adapter, xciHeaderBytes, layout) {
    const { rootHeader, rootActualHeader, totalSize } = layout;

    const xciOut = new Uint8Array(0x200);
    xciOut.set(xciHeaderBytes instanceof Uint8Array ? xciHeaderBytes : new Uint8Array(xciHeaderBytes), 0);
    const xciView = new DataView(xciOut.buffer);
    xciView.setBigUint64(0x118, BigInt(totalSize), true);
    xciView.setBigUint64(0x130, BigInt(ROOT_HFS0_OFFSET), true);
    xciView.setBigUint64(0x138, BigInt(rootActualHeader), true);

    await adapter.write(0, xciOut);
    await adapter.write(ROOT_HFS0_OFFSET, rootHeader);
}

async function writePartitions(adapter, partitionMetas, layout, keys, verify, options) {
    const { partOffsets, partSizes } = layout;
    const { log, progress } = options;
    const totalDataSize = partitionMetas.reduce((s, m) => s + m.totalSize, 0);
    let dataOverall = 0;
    const pct = (bytes) => bytes / totalDataSize;

    for (let pi = 0; pi < partitionMetas.length; pi++) {
        const pm = partitionMetas[pi];
        const po = partOffsets[pi];

        const pWriter = new HFS0Writer(PARTITION_HEADER_SIZE);
        for (const m of pm.files) pWriter.addEntry(m.name, m.size);
        const hfs0Header = pWriter.buildHeader();
        await adapter.write(po.offset, hfs0Header);

        let writePos = po.offset + PARTITION_HEADER_SIZE;
        for (let fi = 0; fi < pm.files.length; fi++) {
            const meta = pm.files[fi];
            if (meta.isNcz) {
                const hasher = verify ? options.createHash() : null;
                const nczReader = new AdapterNCZReader(adapter, meta.offset, meta.nczLen);
                const decomp = new NCZDecompressor(nczReader, keys);
                await decomp.decompress(
                    (p) => progress(pct(dataOverall + meta.size * p), `Decompressing ${meta.inputName}...`),
                    async (chunk, offset) => {
                        if (hasher) hasher.update(chunk);
                        await adapter.write(writePos + offset, chunk);
                    });
                if (hasher) {
                    const hash = hasher.hex();
                    log('info', `  [NCA HASH]   ${hash}`);
                    if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                        const ncaId = meta.name.replace(/\.nca$/i, '');
                        if (pm.cnmtHashMap.size > 0) {
                            verifyHashByNcaId(hash, ncaId, pm.cnmtHashMap, log);
                        } else {
                            verifyFileNameHash(hash, meta.inputName, meta.name, log);
                        }
                    }
                }
            } else {
                progress(pct(dataOverall), `Copying ${meta.inputName}...`);
                const data = await adapter.read(meta.offset, meta.size);
                if (verify && meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                    const hash = await sha256(data);
                    log('info', `  [NCA HASH]   ${hash}`);
                    const ncaId = meta.name.replace(/\.nca$/i, '');
                    if (pm.cnmtHashMap.size > 0) {
                        verifyHashByNcaId(hash, ncaId, pm.cnmtHashMap, log);
                    } else {
                        verifyFileNameHash(hash, meta.inputName, meta.name, log);
                    }
                }
                await adapter.write(writePos, data);
            }
            writePos += meta.size;
            dataOverall += meta.size;
            progress(pct(dataOverall), `${pm.name}/${meta.inputName} done`);
        }

        const paddedDataSize = Math.max(PARTITION_HEADER_SIZE, writePos - po.offset);
        if (paddedDataSize > writePos - po.offset) {
            const padSize = paddedDataSize - (writePos - po.offset);
            await adapter.write(writePos, new Uint8Array(padSize));
        }
    }
}

async function convertXCZStreaming(xci, keys, adapter, options, partitionMetas) {
    const { verify = false, log = () => {}, progress = () => {} } = options;

    if (!partitionMetas) {
        partitionMetas = await buildPartitionMetas(xci, keys, verify, adapter, options.extractCnmtHashMap);
    }
    const layout = computeLayout(partitionMetas);

    const xciHeaderBytes = await adapter.read(0, 0x200);
    await writeXciHeaders(adapter, xciHeaderBytes, layout);

    await writePartitions(adapter, partitionMetas, layout, keys, verify, { log, progress, createHash: options.createHash });

    return layout.totalSize;
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

export async function convertXCZ(reader, keys, output, options = {}) {
    const { verify = false, log = () => {}, progress = () => {}, createHash, extractCnmtHashMap } = options;

    const xci = new XCIReader(reader);
    await xci.parse();

    const read = (offset, size) => reader.read(offset, size);
    const adapter = await buildAdapter(output, read, { log, progress, createHash });

    const partitionMetas = await buildPartitionMetas(xci, keys, verify, adapter, extractCnmtHashMap);

    const totalSize = await convertXCZStreaming(xci, keys, adapter, {
        verify, log, progress, createHash,
    }, partitionMetas);

    if (output.memory) return { size: totalSize, blob: collectBlob(adapter, totalSize) };
    return { size: totalSize };
}


