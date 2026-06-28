import { ZstdDecompressor } from './crypto/zstd.js';
import { PFS0, PFS0Writer } from './fs/pfs0.js';
import { NCZDecompressor, DataReader } from './fs/ncz.js';
import { KeysParser } from './keys.js';
import { SHA256, sha256 } from './crypto/sha256.js';
import { Cnmt } from './fs/cnmt.js';
import { NCAHeader } from './fs/nca.js';
import { XCIReader, XCIWriter } from './fs/xci.js';
import { HFS0Writer } from './fs/hfs0.js';
import { AesXts } from './crypto/aesxts.mjs';
import { AesCtr } from './crypto/aesctr.mjs';
import { AesEcb } from './crypto/aes128.js';

function verifyHash(hash, name, fileHashes, onLog) {
    if (fileHashes.size > 0) {
        if (fileHashes.has(hash)) {
            onLog('success', `[VERIFIED]   ${name} ${hash}`);
        } else {
            onLog('error', `[CORRUPTED]  ${name} ${hash}`);
            throw new Error(`Verification detected hash mismatch: ${name}`);
        }
    }
}

function verifyFileNameHash(hash, nczName, ncaName, onLog) {
    const fileNameHash = nczName.replace(/\.[^.]+$/, '').toLowerCase().slice(0, 32);
    if (hash.slice(0, 32) === fileNameHash) {
        onLog('success', `[VERIFIED]   ${ncaName} ${hash}`);
    } else {
        onLog('error', `[MISMATCH]   Filename starts with ${fileNameHash} but ${hash.slice(0, 32)} was expected`);
        throw new Error(`Verification detected hash mismatch: ${ncaName}`);
    }
}

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

        const pfs0Reader = await PFS0.open(new FileSliceReader(file));
        const files = pfs0Reader.getFiles();
        onLog('info', `PFS0 header: ${files.length} files`);
        onLog('info', `Found ${files.length} files in container`);


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
            const pct = (bytes) => bytes / totalDataSize;

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
                            if (cnmtHashes.size > 0) {
                                verifyHash(hash, meta.name, cnmtHashes, onLog);
                            } else {
                                verifyFileNameHash(hash, f.name, meta.name, onLog);
                            }
                        }
                    }
                } else {
                    onProgress(pct(dataWritten), `Copying ${f.name}...`);
                    const data = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                    if (verify) {
                        const hash = await sha256(data);
                        onLog('info', `SHA256: ${hash}`);
                        if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                            if (cnmtHashes.size > 0) {
                                verifyHash(hash, meta.name, cnmtHashes, onLog);
                            } else {
                                verifyFileNameHash(hash, f.name, meta.name, onLog);
                            }
                        }
                    }
                    await writable.write({ type: 'write', position: writePos, data });
                }

                dataWritten += meta.size;
                onProgress(pct(dataWritten), `File ${idx + 1}/${files.length} done`);
            }

            onProgress(1.0, 'Done!');
            const outputName = file.name.replace(/\.(nsz|nspz|nsx)$/i, '.nsp');
            const totalSize = writer.headerSize + totalDataSize;
            onLog('success', `Output: ${outputName} (${this.formatBytes(totalSize)})`);
            return { blob: null, name: outputName, size: totalSize, writable: true };
        } else {
            // Memory path (no File System Access): collect all data, build PFS0
            onLog('info', 'Using memory download (no File System Access)');
            const outputFiles = [];
            const totalDataSize = outputMeta.reduce((s, m) => s + m.size, 0);
            let dataWritten = 0;
            const pct = (bytes) => bytes / totalDataSize;

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
                            if (cnmtHashes.size > 0) {
                                verifyHash(hash, meta.name, cnmtHashes, onLog);
                            } else {
                                verifyFileNameHash(hash, f.name, meta.name, onLog);
                            }
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
                            if (cnmtHashes.size > 0) {
                                verifyHash(hash, meta.name, cnmtHashes, onLog);
                            } else {
                                verifyFileNameHash(hash, f.name, meta.name, onLog);
                            }
                        }
                    }

                    outputFiles.push({ name: meta.name, data });
                }

                dataWritten += meta.size;
                onProgress(pct(dataWritten), `File ${idx + 1}/${files.length} done`);
            }

            onLog('info', 'Building PFS0 container...');
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
                onLog('warn', `Cannot parse partition ${partition.name} as HFS0, copying raw: ${e.message}`);
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
            const partSizes = [];
            for (const pm of partitionMetas) {
                const partSize = pm.raw ? pm.size : pm.hfs0BufferSize + pm.totalSize;
                partSizes.push(partSize);
                rootWriter.addEntry(pm.name, partSize);
            }
            const rootActualHeader = rootWriter.getActualHeaderSize();

            let currentDataOffset = ROOT_HFS0_OFFSET + rootActualHeader;
            const partOffsets = [];
            for (let i = 0; i < partitionMetas.length; i++) {
                partOffsets.push({ name: partitionMetas[i].name, offset: currentDataOffset });
                currentDataOffset += partSizes[i];
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
            const pct = (bytes) => bytes / totalDataSize;

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
                                if (pm.cnmtHashes.size > 0) {
                                    verifyHash(hash, meta.name, pm.cnmtHashes, onLog);
                                } else {
                                    verifyFileNameHash(hash, meta.inputName, meta.name, onLog);
                                }
                            }
                        }
                    } else {
                        onProgress(pct(dataOverall), `Copying ${meta.inputName}...`);
                        const data = await file.slice(meta.offset, meta.offset + meta.size).arrayBuffer();
                        if (verify) {
                            const hash = await sha256(data);
                            onLog('info', `  SHA256: ${hash}`);
                            if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                                if (pm.cnmtHashes.size > 0) {
                                    verifyHash(hash, meta.name, pm.cnmtHashes, onLog);
                                } else {
                                    verifyFileNameHash(hash, meta.inputName, meta.name, onLog);
                                }
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
            const pct = (bytes) => bytes / totalDataSize;

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
                                if (pm.cnmtHashes.size > 0) {
                                    verifyHash(hash, meta.name, pm.cnmtHashes, onLog);
                                } else {
                                    verifyFileNameHash(hash, meta.inputName, meta.name, onLog);
                                }
                            }
                        }
                    } else {
                        onProgress(pct(dataOverall), `Copying ${meta.inputName}...`);
                        fileData = new Uint8Array(await file.slice(meta.offset, meta.offset + meta.size).arrayBuffer());
                        if (verify) {
                            const hash = await sha256(fileData);
                            onLog('info', `  SHA256: ${hash}`);
                            if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                                if (pm.cnmtHashes.size > 0) {
                                    verifyHash(hash, meta.name, pm.cnmtHashes, onLog);
                                } else {
                                    verifyFileNameHash(hash, meta.inputName, meta.name, onLog);
                                }
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

            onLog('info', 'Building XCI...');
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
            const arr = cnmtData instanceof Uint8Array ? cnmtData : new Uint8Array(cnmtData);

            if (!this.keys || !this.keys.header_key) {
                console.error('Cannot decrypt CNMT: missing keys (header_key)');
                return hashes;
            }

            const headerKey = this.keys.header_key;
            const headerKeyBytes = typeof headerKey === 'string'
                ? new Uint8Array(headerKey.match(/.{2}/g).map(b => parseInt(b, 16)))
                : headerKey;

            if (headerKeyBytes.length !== 32) {
                console.error('Invalid header_key length:', headerKeyBytes.length);
                return hashes;
            }

            const xts = new AesXts(headerKeyBytes);

            const hdrLen = Math.min(0xC00, arr.length);
            const hdrEncrypted = arr.subarray(0, hdrLen);
            const hdrDecrypted = xts.decrypt(hdrEncrypted, 0);

            const header = NCAHeader.parse(hdrDecrypted);

            if (header && header.sectionTables && header.sectionTables[0]) {
                const fsOffset = header.sectionTables[0].offset;
                const fsEndOffset = header.sectionTables[0].endOffset;
                const fsSize = fsEndOffset - fsOffset;

                if (fsSize > 0 && fsOffset + fsSize <= arr.length) {
                    const sectionData = arr.subarray(fsOffset, fsOffset + fsSize);

                    const keysArr = this.keys.keyAreaKeys;
                    const mk = header.masterKey;
                    const kakHex = keysArr[mk] && keysArr[mk][0];

                    if (!kakHex) {
                        console.error('No key_area_key_application for masterKey:', mk);
                        return hashes;
                    }

                    const kak = new Uint8Array(kakHex.match(/.{2}/g).map(b => parseInt(b, 16)));
                    const keyBlock = hdrDecrypted.subarray(0x300, 0x340);

                    let unwrapped;
                    try {
                        const nodeCrypto = await import('crypto');
                        const ecb = nodeCrypto.createDecipheriv('aes-128-ecb', kak, null);
                        ecb.setAutoPadding(false);
                        unwrapped = new Uint8Array(ecb.update(keyBlock));
                    } catch {
                        const ecb = new AesEcb(kak);
                        unwrapped = ecb.decrypt(keyBlock);
                    }
                    const sectionKey = unwrapped.subarray(32, 48);

                    const sectionHdr = hdrDecrypted.subarray(0x400, 0x600);
                    const ivBytes = sectionHdr.subarray(0x140, 0x148);

                    const raw = new Uint8Array(16);
                    for (let j = 0; j < 8; j++) raw[j] = 0;
                    raw.set(ivBytes, 8);
                    const cryptoCounter = new Uint8Array(raw).reverse();

                    const aesCtr = new AesCtr(sectionKey, cryptoCounter);
                    aesCtr.seek(fsOffset);

                    const fsData = await aesCtr.decrypt(sectionData);

                    const pfs0Start = 0x20;
                    const pfs0Magic = fsData.length > pfs0Start + 4
                        ? String.fromCharCode(fsData[pfs0Start], fsData[pfs0Start + 1], fsData[pfs0Start + 2], fsData[pfs0Start + 3])
                        : '';

                    let cnmtRaw = null;

                    if (pfs0Magic === 'PFS0') {
                        const pfs0 = new PFS0(fsData.subarray(pfs0Start));
                        const pfs0Files = pfs0.getFiles();
                        if (pfs0Files.length > 0) {
                            const f = pfs0Files[0];
                            cnmtRaw = pfs0._data.slice(f.offset, f.offset + f.size);
                        } else {
                            cnmtRaw = fsData.subarray(pfs0Start);
                        }
                    } else {
                        const magic = String.fromCharCode(fsData[0], fsData[1], fsData[2], fsData[3]);
                        if (magic === 'PFS0') {
                            cnmtRaw = fsData;
                        }
                    }

                    if (cnmtRaw) {
                        const cnmt = Cnmt.parse(cnmtRaw);
                        if (cnmt && cnmt.contentEntries) {
                            for (const entry of cnmt.contentEntries) {
                                hashes.add(entry.hash);
                            }
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
        const outputName = file ? file.name.replace(/\.(nsz|nspz|nsx)$/i, '.nsp') : 'output.nsp';

        const writer = new PFS0Writer(fixPadding);
        for (const f of files) {
            const data = f.data;
            writer.add(f.name, data instanceof ArrayBuffer ? data.byteLength : data.length);
        }

        return this.buildPFS0Memory(writer, files, onProgress, onLog, outputName);
    }

    async buildPFS0Memory(writer, files, onProgress, onLog, outputName) {
        const header = writer.buildHeader();
        onLog('info', 'Building file in memory...');

        const totalDataSize = writer.files.reduce((s, f) => s + f.size, 0);
        const totalSize = header.length + totalDataSize;

        const parts = [header];
        for (let i = 0; i < writer.files.length; i++) {
            const data = files[i].data;
            const arr = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
            parts.push(arr);
        }

        const blob = new Blob(parts, { type: 'application/octet-stream' });
        onProgress(1.0, 'Done!');
        return { blob, name: outputName, size: totalSize };
    }
}

export { NSZConverter };
