import { ZstdDecompressor } from './crypto/zstd.js';
import { PFS0, PFS0Writer } from './fs/pfs0.js';
import { NCZDecompressor, DataReader } from './fs/ncz.js';
import { KeysParser } from './keys.js';
import { SHA256, sha256 } from './crypto/sha256.js';
import { Cnmt } from './fs/cnmt.js';
import { NCAHeader } from './fs/nca.js';
import { XCIReader, XCIWriter } from './fs/xci.js';
import { HFS0Writer } from './fs/hfs0.js';

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
    constructor() {
        this.keys = null;
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

    async writePFS0Header(writable, metas, fixPadding) {
        const writer = new PFS0Writer(fixPadding);
        for (const m of metas) writer.add(m.name, m.size);
        const header = writer.buildHeader();
        await writable.write({ type: 'write', position: 0, data: header.buffer });
        return writer;
    }

    async decompressNSZtoNSP(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, fixPadding = false, verify = false } = options;

        onLog('info', `Processing: ${file.name} (${this.formatBytes(file.size)})`);
        await this.init();

        const fileBuffer = await file.slice(0, Math.min(file.size, 1024 * 1024)).arrayBuffer();
        const pfs0Reader = new PFS0(fileBuffer);
        const files = pfs0Reader.getFiles();
        onLog('info', `PFS0 header: ${files.length} files`);
        onLog('info', `Found ${files.length} files in container`);
        onProgress(0.02, 'Reading container...');

        const cnmtFiles = files.filter(f => f.name.toLowerCase().endsWith('.cnmt.nca'));
        const cnmtHashes = new Set();
        if (cnmtFiles.length > 0) {
            for (const cnmtFile of cnmtFiles) {
                const cnmtData = await file.slice(cnmtFile.offset, cnmtFile.offset + cnmtFile.size).arrayBuffer();
                const hashes = await this.extractCnmtHashes(cnmtData);
                hashes.forEach(h => cnmtHashes.add(h));
            }
            onLog('info', `Found ${cnmtHashes.size} expected NCA hashes from CNMT`);
        }

        const verifyHash = (hash, name, fileHashes) => {
            if (fileHashes.size > 0) {
                if (fileHashes.has(hash)) {
                    onLog('success', `[VERIFIED]   ${name} ${hash}`);
                } else {
                    onLog('error', `[CORRUPTED]  ${name} ${hash}`);
                    throw new Error(`Verification detected hash mismatch: ${name}`);
                }
            }
        };

        // First pass: determine output file names, sizes, and cache NCZ compressed data
        const outputMeta = [];
        for (const f of files) {
            const isNcz = f.name.toLowerCase().endsWith('.ncz');
            const outputName = isNcz ? f.name.slice(0, -4) + '.nca' : f.name;
            if (isNcz) {
                onLog('info', `Reading NCZ header: ${f.name}`);
                const headerReader = new FileSliceReader(file, f.offset, Math.min(f.size, 0x10000));
                const tmpDecomp = new NCZDecompressor(headerReader, this.keys);
                const { ncaSize } = await tmpDecomp.getSections();
                outputMeta.push({ name: outputName, size: ncaSize, isNcz: true, file: file, fileOffset: f.offset, nczLen: f.size });
            } else {
                outputMeta.push({ name: outputName, size: f.size, isNcz: false, nczChunks: null, nczLen: 0 });
            }
        }

        if (writable) {
            // Streaming path: write header first, then stream decompressed data
            onLog('info', 'Using streaming output (File System Access)');
            const writer = await this.writePFS0Header(writable, outputMeta, fixPadding);

            let dataWritten = 0;
            const totalDataSize = outputMeta.reduce((s, m) => s + m.size, 0);
            const pct = (bytes) => 0.02 + 0.93 * (bytes / totalDataSize);

            for (let idx = 0; idx < files.length; idx++) {
                const meta = outputMeta[idx];
                const f = files[idx];
                onLog('info', `[EXISTS]     ${f.name}`);
                const writePos = writer.headerSize + writer.files[idx].offset;

                if (meta.isNcz) {
                    const hasher = verify && new SHA256();
                    const reader = new FileSliceReader(meta.file, meta.fileOffset, meta.nczLen);
                    const decompressor = new NCZDecompressor(reader, this.keys);
                    await decompressor.decompress(
                        (p) => onProgress(pct(dataWritten + meta.size * p), `Decompressing ${f.name}...`),
                        async (chunk, offset) => {
                            if (hasher) hasher.update(chunk);
                            await writable.write({ type: 'write', position: writePos + offset, data: chunk });
                        });
                    if (hasher) {
                        const hash = hasher.hexdigest();
                        onLog('info', `NCA SHA256: ${hash}`);
                        if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                            verifyHash(hash, meta.name, cnmtHashes);
                        }
                    }
                } else {
                    onProgress(pct(dataWritten), `Copying ${f.name}...`);
                    const data = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                    if (verify) {
                        const hash = await sha256(data);
                        onLog('info', `SHA256: ${hash}`);
                        if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                            verifyHash(hash, meta.name, cnmtHashes);
                        }
                    }
                    await writable.write({ type: 'write', position: writePos, data });
                }

                dataWritten += meta.size;
                onProgress(pct(dataWritten), `File ${idx + 1}/${files.length} done`);
            }

            onProgress(1.0, 'Done!');
            const outputName = file.name.replace(/\.nsz$/i, '.nsp');
            const totalSize = writer.headerSize + totalDataSize;
            onLog('success', `Output: ${outputName} (${this.formatBytes(totalSize)})`);
            return { blob: null, name: outputName, size: totalSize, writable: true };
        } else {
            // Memory path (no File System Access): collect all data, build PFS0
            onLog('info', 'Using memory download (no File System Access)');
            const outputFiles = [];
            const totalDataSize = outputMeta.reduce((s, m) => s + m.size, 0);
            let dataWritten = 0;
            const pct = (bytes) => 0.02 + 0.93 * (bytes / totalDataSize);

            for (let idx = 0; idx < files.length; idx++) {
                const meta = outputMeta[idx];
                const f = files[idx];
                onLog('info', `[EXISTS]     ${f.name}`);

                if (meta.isNcz) {
                    const nczData = await this.decompressNCZ(file, f, (p) => onProgress(pct(dataWritten + meta.size * p), `Decompressing ${f.name}...`));
                    if (verify) {
                        const hash = await sha256(nczData);
                        onLog('info', `NCA SHA256: ${hash}`);
                        if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                            verifyHash(hash, meta.name, cnmtHashes);
                        }
                    }

                    outputFiles.push({ name: meta.name, data: nczData });
                } else {
                    onProgress(pct(dataWritten), `Copying ${f.name}...`);
                    const data = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                    if (verify) {
                        const hash = await sha256(data);
                        onLog('info', `SHA256: ${hash}`);
                        if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                            verifyHash(hash, meta.name, cnmtHashes);
                        }
                    }

                    outputFiles.push({ name: meta.name, data });
                }

                dataWritten += meta.size;
                onProgress(pct(dataWritten), `File ${idx + 1}/${files.length} done`);
            }

            onProgress(0.95, 'Building PFS0 container...');
            return this.buildPFS0(outputFiles, { file, onLog, fixPadding, onProgress });
        }
    }

    async decompressNCZ(file, nczFile, onProgress = () => {}) {
        const reader = new FileSliceReader(file, nczFile.offset, nczFile.size);
        try {
            const decompressor = new NCZDecompressor(reader, this.keys);
            return await decompressor.decompress(onProgress);
        } catch(e) {
            console.error('NCZ decompression error:', e);
            throw e;
        }
    }

    async decompressNCZtoNCA(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, verify = false } = options;
        const reader = new FileSliceReader(file);
        const decompressor = new NCZDecompressor(reader, this.keys);
        const outputName = file.name.replace(/\.ncz$/i, '.nca');

        if (writable) {
            onLog('info', 'Using streaming output (File System Access)');
            let maxPos = 0;
            const hasher = verify && new SHA256();
            await decompressor.decompress((p) => onProgress(p, 'Decompressing...'), async (chunk, position) => {
                if (hasher) hasher.update(chunk);
                await writable.write({ type: 'write', position, data: chunk });
                const end = position + chunk.byteLength;
                if (end > maxPos) maxPos = end;
            });
            if (hasher) {
                const hash = hasher.hexdigest();
                const fileNameHash = file.name.replace(/\.ncz$/i, '').toLowerCase();
                if (hash.substring(0, 32) === fileNameHash) {
                    onLog('success', `[VERIFIED]   ${outputName}`);
                } else {
                    onLog('warn', `[MISSMATCH]  Filename startes with ${fileNameHash} but ${hash.substring(0, 32)} was expected - hash verified failed!`);
                }
            }
            onProgress(1.0, 'Done!');
            onLog('success', `Output: ${outputName} (${this.formatBytes(maxPos)})`);
            return { blob: null, name: outputName, size: maxPos, writable: true };
        }

        onLog('info', 'Using memory download');
        const ncaData = await decompressor.decompress(onProgress);
        if (verify) {
            const hash = await sha256(ncaData);
            const fileNameHash = file.name.replace(/\.ncz$/i, '').toLowerCase();
            if (hash.substring(0, 32) === fileNameHash) {
                onLog('success', `[VERIFIED]   ${outputName}`);
            } else {
                onLog('warn', `[MISSMATCH]  Filename startes with ${fileNameHash} but ${hash.substring(0, 32)} was expected - hash verified failed!`);
            }
        }
        onProgress(1.0, 'Done!');
        const blob = new Blob([ncaData], { type: 'application/octet-stream' });
        return { blob, name: outputName, size: ncaData.length };
    }

    async decompressXCZtoXCI(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, verify = false } = options;
        onLog('info', 'Parsing XCI container...');
        const fileReader = new FileSliceReader(file);
        const xci = new XCIReader(fileReader);
        await xci.parse();
        const partitions = xci.getPartitions();
        onLog('info', `Found ${partitions.length} partitions: ${partitions.map(p => p.name).join(', ')}`);

        const PARTITION_HEADER_SIZE = 0x8000;
        const ROOT_HFS0_PADDED_SIZE = 0x8000;

        // First pass: read each partition's files and determine output sizes
        const partitionMetas = [];
        for (const partition of partitions) {
            if (partition.size === 0) {
                partitionMetas.push({ name: partition.name, files: [], totalSize: 0, hfs0Size: 0, cnmtHashes: new Set() });
                continue;
            }
            onLog('info', `Reading partition: ${partition.name}`);
            let hfs0;
            try {
                hfs0 = await xci.readPartitionFiles(partition);
            } catch (e) {
                onLog('warning', `Cannot parse partition ${partition.name} as HFS0, copying raw: ${e.message}`);
                partitionMetas.push({ name: partition.name, raw: true, offset: partition.offset, size: partition.size, files: [], totalSize: partition.size, hfs0Size: 0, cnmtHashes: new Set() });
                continue;
            }
            const partitionFiles = hfs0.getFiles();
            onLog('info', `  ${partitionFiles.length} files`);

            // Extract CNMT hashes from this partition
            const cnmtHashes = new Set();
            const cnmtFiles = partitionFiles.filter(f => f.name.toLowerCase().endsWith('.cnmt.nca'));
            if (cnmtFiles.length > 0) {
                for (const cnmtFile of cnmtFiles) {
                    const cnmtData = await file.slice(cnmtFile.offset, cnmtFile.offset + cnmtFile.size).arrayBuffer();
                    const hashes = await this.extractCnmtHashes(cnmtData);
                    hashes.forEach(h => cnmtHashes.add(h));
                }
                onLog('info', `  Found ${cnmtHashes.size} expected NCA hashes from CNMT in ${partition.name}`);
            }

            const fileMetas = [];
            for (const f of partitionFiles) {
                const isNcz = f.name.toLowerCase().endsWith('.ncz');
                const outputName = isNcz ? f.name.replace(/\.ncz$/i, '.nca') : f.name;
                if (isNcz) {
                    const headerReader = new FileSliceReader(file, f.offset, Math.min(f.size, 0x10000));
                    const tmpDecomp = new NCZDecompressor(headerReader, this.keys);
                    const { ncaSize } = await tmpDecomp.getSections();
                    fileMetas.push({ name: outputName, size: ncaSize, isNcz: true, fileOffset: f.offset, nczLen: f.size, inputName: f.name });
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
                cnmtHashes
            });
        }

        if (writable) {
            onLog('info', 'Using streaming output (File System Access)');
            const xciHeaderBytes = await fileReader.read(0, 0x200);
            const ROOT_HFS0_OFFSET = 0xF000;

            const rootWriter = new HFS0Writer(ROOT_HFS0_PADDED_SIZE);
            for (const pm of partitionMetas) {
                rootWriter.addEntry(pm.name, pm.raw ? pm.size : pm.hfs0BufferSize);
            }
            const rootActualHeader = rootWriter.getActualHeaderSize();

            let currentDataOffset = ROOT_HFS0_OFFSET + rootActualHeader;
            const partOffsets = [];
            for (const pm of partitionMetas) {
                partOffsets.push({ name: pm.name, offset: currentDataOffset });
                currentDataOffset += pm.raw ? pm.size : pm.hfs0BufferSize;
            }
            const totalSize = currentDataOffset;

            const rootHeader = rootWriter.buildHeader();
            const xciOut = new Uint8Array(0x200);
            xciOut.set(xciHeaderBytes, 0);
            const xciView = new DataView(xciOut.buffer);
            xciView.setBigUint64(0x118, BigInt(totalSize), true);
            xciView.setBigUint64(0x130, BigInt(ROOT_HFS0_OFFSET), true);
            xciView.setBigUint64(0x138, BigInt(rootActualHeader), true);

            await writable.write({ type: 'write', position: 0, data: xciOut.buffer });
            await writable.write({ type: 'write', position: ROOT_HFS0_OFFSET, data: rootHeader.buffer });

            // Build/store partition HFS0 buffers, then write them
            const totalDataSize = partitionMetas.reduce((s, m) => s + m.totalSize, 0);
            let dataOverall = 0;
            const pct = (bytes) => 0.02 + 0.93 * (bytes / totalDataSize);

            for (let pi = 0; pi < partitionMetas.length; pi++) {
                const pm = partitionMetas[pi];
                const po = partOffsets[pi];

                if (pm.raw) {
                    const data = await file.slice(pm.offset, pm.offset + pm.size).arrayBuffer();
                    await writable.write({ type: 'write', position: po.offset, data });
                    dataOverall += pm.size;
                    onProgress(pct(dataOverall), `Copied raw partition ${pm.name}`);
                    continue;
                }

                const pWriter = new HFS0Writer(PARTITION_HEADER_SIZE);
                for (const m of pm.files) pWriter.addEntry(m.name, m.size);
                const hfs0Header = pWriter.buildHeader();
                await writable.write({ type: 'write', position: po.offset, data: hfs0Header });

                let writePos = po.offset + PARTITION_HEADER_SIZE;
                for (let fi = 0; fi < pm.files.length; fi++) {
                    const meta = pm.files[fi];
                    if (meta.isNcz) {
                        const hasher = verify && new SHA256();
                        const reader = new FileSliceReader(file, meta.fileOffset, meta.nczLen);
                        const decomp = new NCZDecompressor(reader, this.keys);
                        await decomp.decompress(
                            (p) => onProgress(pct(dataOverall + meta.size * p), `Decompressing ${meta.inputName}...`),
                            async (chunk, offset) => {
                                if (hasher) hasher.update(chunk);
                                await writable.write({ type: 'write', position: writePos + offset, data: chunk });
                            });
                        if (hasher) {
                            const hash = hasher.hexdigest();
                            onLog('info', `  SHA256: ${hash}`);
                            if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                                verifyHash(hash, meta.name, pm.cnmtHashes);
                            }
                        }
                    } else {
                        onProgress(pct(dataOverall), `Copying ${meta.inputName}...`);
                        const data = await file.slice(meta.offset, meta.offset + meta.size).arrayBuffer();
                        if (verify) {
                            const hash = await sha256(data);
                            onLog('info', `  SHA256: ${hash}`);
                            if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                                verifyHash(hash, meta.name, pm.cnmtHashes);
                            }
                        }
                        await writable.write({ type: 'write', position: writePos, data });
                    }
                    writePos += meta.size;
                    dataOverall += meta.size;
                    onProgress(pct(dataOverall), `${pm.name}/${meta.inputName} done`);
                }

                // If partition HFS0 data area is smaller than the padded header, pad the file
                const paddedDataSize = Math.max(PARTITION_HEADER_SIZE, writePos - po.offset);
                if (paddedDataSize > writePos - po.offset) {
                    const padSize = paddedDataSize - (writePos - po.offset);
                    await writable.write({ type: 'write', position: writePos, data: new Uint8Array(padSize) });
                }
            }

            onProgress(1.0, 'Done!');
            const outputName = file.name.replace(/\.xcz$/i, '.xci');
            onLog('success', `Output: ${outputName} (${this.formatBytes(totalSize)})`);
            return { blob: null, name: outputName, size: totalSize, writable: true };
        } else {
            // Memory path: build entire XCI in memory
            onLog('info', 'Using memory download');

            const xciWriter = new XCIWriter(await fileReader.read(0, 0x200));
            const totalDataSize = partitionMetas.reduce((s, m) => s + m.totalSize, 0);
            let dataOverall = 0;
            const pct = (bytes) => 0.02 + 0.93 * (bytes / totalDataSize);

            for (const pm of partitionMetas) {
                if (pm.raw) {
                    const rawData = await file.slice(pm.offset, pm.offset + pm.size).arrayBuffer();
                    xciWriter.addPartition(pm.name, new Uint8Array(rawData));
                    onLog('info', `  Copied raw partition ${pm.name}: ${rawData.byteLength} bytes`);
                    dataOverall += pm.size;
                    onProgress(pct(dataOverall), `Copied ${pm.name}`);
                    continue;
                }

                const hfs0Writer = new HFS0Writer(PARTITION_HEADER_SIZE);

                for (const meta of pm.files) {
                    onLog('info', `${meta.isNcz ? 'Decompressing' : 'Copying'}: ${meta.inputName} -> ${meta.name}`);

                    let fileData;
                    if (meta.isNcz) {
                        const nczReader = new FileSliceReader(file, meta.fileOffset, meta.nczLen);
                        const decompressor = new NCZDecompressor(nczReader, this.keys);
                        fileData = await decompressor.decompress((p) => onProgress(pct(dataOverall + meta.size * p), `Decompressing ${meta.inputName}...`));
                        if (verify) {
                            const hash = await sha256(fileData);
                            onLog('info', `  SHA256: ${hash}`);
                            if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                                verifyHash(hash, meta.name, pm.cnmtHashes);
                            }
                        }
                    } else {
                        onProgress(pct(dataOverall), `Copying ${meta.inputName}...`);
                        fileData = new Uint8Array(await file.slice(meta.offset, meta.offset + meta.size).arrayBuffer());
                        if (verify) {
                            const hash = await sha256(fileData);
                            onLog('info', `  SHA256: ${hash}`);
                            if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                                verifyHash(hash, meta.name, pm.cnmtHashes);
                            }
                        }
                    }

                    hfs0Writer.addFile(meta.name, fileData);
                    dataOverall += meta.size;
                    onProgress(pct(dataOverall), `${pm.name}/${meta.inputName} done`);
                }

                const hfs0Data = hfs0Writer.build();
                xciWriter.addPartition(pm.name, hfs0Data);
                onLog('info', `  HFS0 partition ${pm.name} built: ${hfs0Data.length} bytes`);
            }

            onProgress(0.95, 'Building XCI...');
            const xciData = xciWriter.build();
            onLog('info', `XCI built: ${xciData.length} bytes`);

            onProgress(1.0, 'Done!');
            const outputName = file.name.replace(/\.xcz$/i, '.xci');
            const blob = new Blob([xciData], { type: 'application/octet-stream' });
            return { blob, name: outputName, size: xciData.length };
        }
    }

    async extractCnmtHashes(cnmtData) {
        const hashes = new Set();
        try {
            const header = NCAHeader.parse(cnmtData.slice(0, 0xC00));
            if (header && header.sectionTables && header.sectionTables[0]) {
                const fsOffset = header.sectionTables[0].offset;
                const fsSize = header.sectionTables[0].endOffset - header.sectionTables[0].offset;
                
                if (fsSize > 0 && fsOffset + fsSize <= cnmtData.byteLength) {
                    const fsData = cnmtData.slice(fsOffset, fsOffset + fsSize);
                    const cnmt = Cnmt.parse(fsData);
                    
                    if (cnmt && cnmt.contentEntries) {
                        for (const entry of cnmt.contentEntries) {
                            hashes.add(entry.hash);
                        }
                    }
                }
            }
        } catch (e) {
            console.error('Error extracting CNMT hashes:', e);
        }
        return hashes;
    }

    async buildPFS0(files, options = {}) {
        const { file = null, onLog = () => {}, fixPadding = false, onProgress = () => {} } = options;
        const outputName = file ? file.name.replace(/\.nsz$/i, '.nsp') : 'output.nsp';

        const writer = new PFS0Writer(fixPadding);
        for (const f of files) {
            const data = f.data;
            writer.add(f.name, data instanceof ArrayBuffer ? data.byteLength : data.length);
        }

        onLog('info', 'Using memory download');
        return this.buildPFS0Memory(writer, files, onProgress, outputName);
    }

    async buildPFS0Memory(writer, files, onProgress, outputName) {
        const header = writer.buildHeader();
        onProgress(0.95, 'Building file in memory...');

        const totalDataSize = writer.files.reduce((s, f) => s + f.size, 0);
        const totalSize = header.length + totalDataSize;

        const parts = [header];
        for (let i = 0; i < writer.files.length; i++) {
            const data = files[i].data;
            const arr = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
            parts.push(arr);
            onProgress(0.95 + (0.05 * (i + 1) / writer.files.length), `Building file ${i + 1}/${writer.files.length}...`);
        }

        const blob = new Blob(parts, { type: 'application/octet-stream' });
        onProgress(1.0, 'Done!');
        return { blob, name: outputName, size: totalSize };
    }
}

export { NSZConverter };