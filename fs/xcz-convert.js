import { HFS0Writer } from './hfs0.js';
import { XCIReader } from './xci.js';
import { buildAdapter, collectBlob } from './adapter.js';
import { collectFileMetas, writeFromReader } from './convert-common.js';

const PARTITION_HEADER_SIZE = 0x8000;
const ROOT_HFS0_PADDED_SIZE = 0x8000;
const ROOT_HFS0_OFFSET = 0xF000;

async function buildPartitionMetas(xci, verify, adapter, extractCnmtHashMap) {
    const partitions = xci.getPartitions();
    const partitionMetas = [];

    for (const partition of partitions) {
        if (partition.size === 0) {
            partitionMetas.push({ name: partition.name, files: [], totalSize: 0, hfs0BufferSize: PARTITION_HEADER_SIZE, raw: false, cnmtHashMap: new Map() });
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

        const fileMetas = await collectFileMetas(partitionFiles, adapter);
        const fileTotalSize = fileMetas.reduce((s, m) => s + m.size, 0);

        partitionMetas.push({
            name: partition.name,
            files: fileMetas,
            totalSize: fileTotalSize,
            hfs0BufferSize: PARTITION_HEADER_SIZE,
            raw: false,
            cnmtHashMap
        });
    }

    return partitionMetas;
}

function computeLayout(partitionMetas, baseOffset = 0) {
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

    let currentDataOffset = baseOffset + ROOT_HFS0_OFFSET + rootHfs0.headerSize;
    const partOffsets = [];
    for (let i = 0; i < partitionMetas.length; i++) {
        partOffsets.push({ name: partitionMetas[i].name, offset: currentDataOffset });
        currentDataOffset += partSizes[i];
    }
    const totalSize = currentDataOffset;

    return { rootWriter, rootHeader, rootActualHeader, partSizes, partOffsets, totalSize };
}

async function writeXciHeaders(adapter, xciHeaderBytes, layout, baseOffset = 0, prefixData = null) {
    const { rootHeader, rootActualHeader, totalSize } = layout;

    const xciOut = new Uint8Array(0x200);
    xciOut.set(xciHeaderBytes instanceof Uint8Array ? xciHeaderBytes : new Uint8Array(xciHeaderBytes), 0);
    const xciView = new DataView(xciOut.buffer);
    xciView.setBigUint64(0x118, BigInt(totalSize), true);
    xciView.setBigUint64(0x130, BigInt(ROOT_HFS0_OFFSET), true);
    xciView.setBigUint64(0x138, BigInt(rootActualHeader), true);

    if (prefixData) await adapter.write(0, prefixData);
    await adapter.write(baseOffset, xciOut);
    await adapter.write(baseOffset + ROOT_HFS0_OFFSET, rootHeader);
}

async function writePartitions(adapter, partitionMetas, layout, verify, options) {
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
        await adapter.write(po.offset, hfs0Header.buffer);

        let writePos = po.offset + PARTITION_HEADER_SIZE;
        for (let fi = 0; fi < pm.files.length; fi++) {
            const meta = pm.files[fi];
            await writeFromReader(adapter, writePos,
                { ...meta, reader: adapter, outLen: meta.size },
                (p) => progress(pct(dataOverall + meta.size * p), `${meta.kind === 'ncz' ? 'Decompressing' : 'Copying'} ${meta.inputName}...`),
                { verify, createHash: options.createHash, cnmtHashMap: pm.cnmtHashMap, log });
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

async function convertXCZStreaming(xci, adapter, options, partitionMetas) {
    const { verify = false, log = () => {}, progress = () => {} } = options;

    if (!partitionMetas) {
        partitionMetas = await buildPartitionMetas(xci, verify, adapter, options.extractCnmtHashMap);
    }

    const baseOffset = xci.headOffset - 0x100;
    const layout = computeLayout(partitionMetas, baseOffset);

    let prefixData = null;
    if (baseOffset > 0) {
        prefixData = await adapter.read(0, baseOffset + ROOT_HFS0_OFFSET);
    }

    const xciHeaderBytes = await adapter.read(baseOffset, 0x200);
    await writeXciHeaders(adapter, xciHeaderBytes, layout, baseOffset, prefixData);

    await writePartitions(adapter, partitionMetas, layout, verify, { log, progress, createHash: options.createHash });

    return layout.totalSize;
}

export async function convertXCZ(reader, output, options = {}) {
    const { verify = false, log = () => {}, progress = () => {}, createHash, extractCnmtHashMap } = options;

    const xci = new XCIReader(reader);
    await xci.parse();

    const read = (offset, size) => reader.read(offset, size);
    const adapter = await buildAdapter(output, read, { log, progress, createHash });

    const partitionMetas = await buildPartitionMetas(xci, verify, adapter, extractCnmtHashMap);

    const totalSize = await convertXCZStreaming(xci, adapter, {
        verify, log, progress, createHash,
    }, partitionMetas);

    if (output.memory) return { size: totalSize, blob: collectBlob(adapter, totalSize) };
    return { size: totalSize };
}


