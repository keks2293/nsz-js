import { ZstdDecompressor } from './crypto/zstd.js';
import { PFS0Reader } from './pfs0.js';
import { NCZDecompressor, DataReader } from './ncz.js';
import { KeysParser } from './keys.js';
import { SHA256, sha256 } from './crypto/sha256.js';
import { extractHashesFromCnmt, Cnmt, ContentEntry, NCAHeader } from './ticket.js';
import { XCIReader, HFS0Writer, XCIWriter } from './xci.js';

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

    async writePFS0HeaderOnly(writable, fileEntries, stringTable, fixPadding) {
        const headerSize = 0x10 + fileEntries.length * 0x18 + stringTable.length;
        const paddingSize = fixPadding ? (16 - (headerSize % 16)) % 16 : 0;
        const encoder = new TextEncoder();

        let paddedStringTable;
        let paddedHeaderSize;
        let stringTableSizeInHeader;

        if (fixPadding) {
            paddedStringTable = stringTable + '\x00'.repeat(paddingSize);
            paddedHeaderSize = 0x10 + fileEntries.length * 0x18 + paddedStringTable.length;
            stringTableSizeInHeader = paddedStringTable.length;
        } else {
            paddedStringTable = stringTable;
            paddedHeaderSize = headerSize + paddingSize;
            stringTableSizeInHeader = stringTable.length + paddingSize;
        }

        const headerBuffer = new Uint8Array(paddedHeaderSize);
        const view = new DataView(headerBuffer.buffer);

        headerBuffer[0] = 0x50; headerBuffer[1] = 0x46; headerBuffer[2] = 0x53; headerBuffer[3] = 0x30;
        view.setUint32(4, fileEntries.length, true);
        view.setUint32(8, stringTableSizeInHeader, true);
        view.setUint32(12, 0, true);

        let stringOffset = 0;
        for (let i = 0; i < fileEntries.length; i++) {
            const entry = fileEntries[i];
            const pos = 0x10 + i * 0x18;
            view.setBigUint64(pos, BigInt(entry.offset), true);
            view.setBigUint64(pos + 8, BigInt(entry.size), true);
            view.setUint32(pos + 16, stringOffset, true);
            view.setUint32(pos + 20, 0, true);
            const nameBytes = encoder.encode(entry.name);
            headerBuffer.set(nameBytes, 0x10 + fileEntries.length * 0x18 + stringOffset);
            stringOffset += nameBytes.length + 1;
        }

        await writable.write({ type: 'write', position: 0, data: headerBuffer.buffer });
        return paddedHeaderSize;
    }

    async decompressNSZtoNSP(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, fixPadding = false } = options;

        onLog('info', `Processing: ${file.name} (${this.formatBytes(file.size)})`);
        await this.init();

        const fileBuffer = await file.slice(0, Math.min(file.size, 1024 * 1024)).arrayBuffer();
        const pfs0Reader = new PFS0Reader(fileBuffer);
        const files = pfs0Reader.getFiles();
        onLog('info', `PFS0 header: ${files.length} files`);
        onLog('info', `Found ${files.length} files in container`);
        onProgress(0.05, 'Reading container...');

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

        // Compute PFS0 file entries with relative offsets
        let fileDataOffset = 0;
        const fileEntries = outputMeta.map(m => {
            const entry = { name: m.name, offset: fileDataOffset, size: m.size };
            fileDataOffset += m.size;
            return entry;
        });

        const stringTable = outputMeta.map(m => m.name).join('\0') + '\0';

        if (writable) {
            // Streaming path: write header first, then stream decompressed data
            onLog('info', 'Using streaming output (File System Access)');
            const paddedHeaderSize = await this.writePFS0HeaderOnly(writable, fileEntries, stringTable, fixPadding);
            onProgress(0.8, 'Writing output file...');

            let dataWritten = 0;
            const totalDataSize = outputMeta.reduce((s, m) => s + m.size, 0);

            for (let idx = 0; idx < files.length; idx++) {
                const meta = outputMeta[idx];
                const f = files[idx];
                const writePos = paddedHeaderSize + fileEntries[idx].offset;

                if (meta.isNcz) {
                    const hasher = new SHA256();
                    const reader = new FileSliceReader(meta.file, meta.fileOffset, meta.nczLen);
                    const decompressor = new NCZDecompressor(reader, this.keys);
                    await decompressor.decompress(null, async (chunk, offset) => {
                        hasher.update(chunk);
                        await writable.write({ type: 'write', position: writePos + offset, data: chunk });
                    });
                    const hash = hasher.hexdigest();
                    onLog('info', `NCA SHA256: ${hash}`);

                    if (!meta.name.endsWith('.cnmt.nca')) {
                        if (cnmtHashes.size > 0) {
                            if (cnmtHashes.has(hash)) {
                                onLog('success', `[VERIFIED]   ${meta.name}`);
                            } else {
                                onLog('error', `[CORRUPTED]  ${meta.name} - hash mismatch!`);
                            }
                        } else {
                            const expectedFromFilename = file.name.toLowerCase().replace(/\.nsz$/i, '.nca');
                            if (hash.startsWith(expectedFromFilename.substring(0, 32))) {
                                onLog('success', `[VERIFIED]   ${meta.name}`);
                            }
                        }
                    }
                } else {
                    const data = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                    const hash = sha256(data);
                    onLog('info', `SHA256: ${hash}`);
                    await writable.write({ type: 'write', position: writePos, data });

                    if (cnmtHashes.size > 0 && !meta.name.endsWith('.cnmt.nca')) {
                        if (cnmtHashes.has(hash)) {
                            onLog('success', `[VERIFIED]   ${meta.name}`);
                        } else if (hash in cnmtHashes) {
                            onLog('success', `[VERIFIED]   ${meta.name}`);
                        } else {
                            onLog('error', `[CORRUPTED]  ${meta.name} - hash mismatch!`);
                        }
                    }
                }

                dataWritten += meta.size;
                const progress = 0.8 + (0.2 * (dataWritten / totalDataSize));
                onProgress(progress, `Writing file ${idx + 1}/${files.length}...`);
            }

            onProgress(1.0, 'Done!');
            const outputName = file.name.replace(/\.nsz$/i, '.nsp');
            const totalSize = paddedHeaderSize + totalDataSize;
            onLog('success', `Output: ${outputName} (${this.formatBytes(totalSize)})`);
            return { blob: null, name: outputName, size: totalSize, writable: true };
        } else {
            // Memory path (no File System Access): collect all data, build PFS0
            onLog('info', 'Using memory download (no File System Access)');
            const outputFiles = [];

            for (let idx = 0; idx < files.length; idx++) {
                const meta = outputMeta[idx];
                const f = files[idx];
                const progress = 0.05 + (0.65 * (idx / files.length));
                onProgress(progress, `Processing file ${idx + 1}/${files.length}...`);
                onLog('info', `${meta.isNcz ? 'Decompressing' : 'Copying'}: ${f.name}`);

                if (meta.isNcz) {
                    const nczData = await this.decompressNCZ(file, f);
                    const hash = sha256(nczData);
                    onLog('info', `NCA SHA256: ${hash}`);

                    if (!meta.name.endsWith('.cnmt.nca')) {
                        if (cnmtHashes.size > 0) {
                            if (cnmtHashes.has(hash)) {
                                onLog('success', `[VERIFIED]   ${meta.name}`);
                            } else {
                                onLog('error', `[CORRUPTED]  ${meta.name} - hash mismatch!`);
                            }
                        } else {
                            const expectedFromFilename = file.name.toLowerCase().replace(/\.nsz$/i, '.nca');
                            if (hash.startsWith(expectedFromFilename.substring(0, 32))) {
                                onLog('success', `[VERIFIED]   ${meta.name}`);
                            }
                        }
                    }

                    outputFiles.push({ name: meta.name, data: nczData });
                } else {
                    const data = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                    const hash = sha256(data);
                    onLog('info', `SHA256: ${hash}`);

                    if (cnmtHashes.size > 0 && !meta.name.endsWith('.cnmt.nca')) {
                        if (cnmtHashes.has(hash)) {
                            onLog('success', `[VERIFIED]   ${meta.name}`);
                        } else if (hash in cnmtHashes) {
                            onLog('success', `[VERIFIED]   ${meta.name}`);
                        } else {
                            onLog('error', `[CORRUPTED]  ${meta.name} - hash mismatch!`);
                        }
                    }

                    outputFiles.push({ name: meta.name, data });
                }
            }

            onProgress(0.7, 'Building PFS0 container...');
            return this.buildPFS0(outputFiles, null, { file, onLog, fixPadding, onProgress });
        }
    }

    async buildPFS0Stream(writable, fileEntries, fileDataList, headerSize, stringTable, paddingSize, fixPadding = false, onProgress = () => {}) {
        const encoder = new TextEncoder();
        
        let paddedStringTable;
        let paddedHeaderSize;
        let stringTableSizeInHeader;
        
        if (fixPadding) {
            // Padding added to string table itself (like Python fix_padding=True)
            paddedStringTable = stringTable + '\x00'.repeat(paddingSize);
            paddedHeaderSize = 0x10 + fileEntries.length * 0x18 + paddedStringTable.length;
            stringTableSizeInHeader = paddedStringTable.length;
        } else {
            // No padding in string table, separate padding after
            paddedStringTable = stringTable;
            paddedHeaderSize = headerSize + paddingSize;
            stringTableSizeInHeader = stringTable.length + paddingSize;
        }
        
        const headerBuffer = new Uint8Array(paddedHeaderSize);
        const view = new DataView(headerBuffer.buffer);

        headerBuffer[0] = 0x50; headerBuffer[1] = 0x46; headerBuffer[2] = 0x53; headerBuffer[3] = 0x30;
        view.setUint32(4, fileEntries.length, true);
        view.setUint32(8, stringTableSizeInHeader, true);
        view.setUint32(12, 0, true);

        let stringOffset = 0;
        for (let i = 0; i < fileEntries.length; i++) {
            const entry = fileEntries[i];
            const pos = 0x10 + i * 0x18;
            
            view.setBigUint64(pos, BigInt(entry.offset), true);
            view.setBigUint64(pos + 8, BigInt(entry.size), true);
            view.setUint32(pos + 16, stringOffset, true);
            view.setUint32(pos + 20, 0, true);

            const nameBytes = encoder.encode(entry.name);
            headerBuffer.set(nameBytes, 0x10 + fileEntries.length * 0x18 + stringOffset);
            stringOffset += nameBytes.length + 1;
        }

        await writable.write({ type: 'write', position: 0, data: headerBuffer.buffer });
        onProgress(0.85, 'Writing header...');
        
        // Write files at absolute positions (after header)
        const totalSize = fileDataList.reduce((sum, d) => sum + (d.byteLength || d.length), 0);
        let written = 0;
        
        for (let i = 0; i < fileEntries.length; i++) {
            const data = fileDataList[i];
            let buffer = data instanceof ArrayBuffer ? data : (data.buffer || data);
            
            // Absolute position = header size + relative offset
            const writePosition = paddedHeaderSize + Number(fileEntries[i].offset);
            await writable.write({ type: 'write', position: writePosition, data: buffer });
            
            written += buffer.byteLength || buffer.length;
            const progress = 0.85 + (0.15 * (written / totalSize));
            onProgress(progress, `Writing file ${i + 1}/${fileEntries.length}...`);
        }

        const total = paddedHeaderSize + fileEntries.reduce((sum, e) => sum + Number(e.size), 0);
        return { size: total };
    }

    async decompressNCZ(file, nczFile) {
        const reader = new FileSliceReader(file, nczFile.offset, nczFile.size);
        try {
            const decompressor = new NCZDecompressor(reader, this.keys);
            return await decompressor.decompress();
        } catch(e) {
            console.error('NCZ decompression error:', e);
            throw e;
        }
    }

    async decompressNCZtoNCA(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {} } = options;
        const reader = new FileSliceReader(file);
        const decompressor = new NCZDecompressor(reader, this.keys);
        const ncaData = await decompressor.decompress();
        const hash = sha256(ncaData);
        onLog('info', `NCA SHA256: ${hash}`);
        onProgress(1.0, 'Done!');
        const outputName = file.name.replace(/\.ncz$/i, '.nca');
        const blob = new Blob([ncaData], { type: 'application/octet-stream' });
        return { blob, name: outputName, size: ncaData.length };
    }

    async decompressXCZtoXCI(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null } = options;
        onLog('info', 'Parsing XCI container...');
        const fileReader = new FileSliceReader(file);
        const xci = new XCIReader(fileReader);
        await xci.parse();
        const files = xci.getSecurePartition();
        onLog('info', `Found ${files.length} files in secure partition`);

        // First pass: determine sizes, cache compressed NCZ data
        const outputMeta = [];
        for (const f of files) {
            const isNcz = f.name.toLowerCase().endsWith('.ncz');
            const outputName = isNcz ? f.name.replace(/\.ncz$/i, '.nca') : f.name;
            if (isNcz) {
                const headerReader = new FileSliceReader(file, f.offset, Math.min(f.size, 0x10000));
                const tmpDecomp = new NCZDecompressor(headerReader, this.keys);
                const { ncaSize } = await tmpDecomp.getSections();
                outputMeta.push({ name: outputName, size: ncaSize, isNcz: true, file: file, fileOffset: f.offset, nczLen: f.size });
            } else {
                outputMeta.push({ name: outputName, size: f.size, isNcz: false, offset: f.offset, nczChunks: null, nczLen: 0 });
            }
        }

        // Compute file offsets within HFS0
        let fileDataOffset = 0;
        const fileEntries = outputMeta.map(m => {
            const entry = { name: m.name, offset: fileDataOffset, size: m.size };
            fileDataOffset += m.size;
            return entry;
        });

        const stringTable = outputMeta.map(m => m.name).join('\0') + '\0';
        const stringTableBytes = new TextEncoder().encode(stringTable);
        const hfs0HeaderBase = 0x10 + outputMeta.length * 0x40;
        const hfs0TotalHeader = hfs0HeaderBase + stringTableBytes.length;

        if (writable) {
            onLog('info', 'Using streaming output (File System Access)');
            const xciHeaderBytes = await fileReader.read(0, 0x200);
            const hfs0Offset = 0x200;

            // Build HFS0 header buffer
            const hfs0Header = new Uint8Array(hfs0TotalHeader);
            const hdrView = new DataView(hfs0Header.buffer);
            hfs0Header[0] = 0x48; hfs0Header[1] = 0x46; hfs0Header[2] = 0x53; hfs0Header[3] = 0x30;
            hdrView.setUint32(4, outputMeta.length, true);
            hdrView.setUint32(8, stringTableBytes.length, true);
            hdrView.setUint32(12, 0, true);
            hfs0Header.set(stringTableBytes, hfs0HeaderBase);

            for (let i = 0; i < outputMeta.length; i++) {
                const m = outputMeta[i];
                const pos = 0x10 + i * 0x40;
                const nameOffset = stringTable.indexOf(m.name);
                hdrView.setBigUint64(pos, BigInt(m.offset), true);
                hdrView.setBigUint64(pos + 8, BigInt(m.size), true);
                hdrView.setUint32(pos + 16, nameOffset, true);
                hdrView.setUint32(pos + 20, 0, true);
                hdrView.setUint32(pos + 24, 0, true);
                hdrView.setUint32(pos + 28, 0, true);
                hdrView.setBigUint64(pos + 32, 0n, true);
            }

            // Update XCI header with correct offsets
            const xciOut = new Uint8Array(0x200);
            xciOut.set(xciHeaderBytes, 0);
            const xciView = new DataView(xciOut.buffer);
            const hfs0TotalSize = hfs0TotalHeader + fileDataOffset;
            xciView.setBigUint64(0x118, BigInt(hfs0Offset + hfs0TotalSize), true);
            xciView.setBigUint64(0x130, BigInt(hfs0Offset), true);
            const hfs0HeaderSize = 0x10 + outputMeta.length * 0x40 + stringTableBytes.length;
            xciView.setBigUint64(0x138, BigInt(hfs0HeaderSize), true);

            await writable.write({ type: 'write', position: 0, data: xciOut.buffer });
            await writable.write({ type: 'write', position: hfs0Offset, data: hfs0Header.buffer });

            let writePos = hfs0Offset + hfs0TotalHeader;
            for (let idx = 0; idx < files.length; idx++) {
                const meta = outputMeta[idx];
                const f = files[idx];

                if (meta.isNcz) {
                    const hasher = new SHA256();
                    const reader = new FileSliceReader(meta.file, meta.fileOffset, meta.nczLen);
                    const decomp = new NCZDecompressor(reader, this.keys);
                    await decomp.decompress(null, async (chunk, offset) => {
                        hasher.update(chunk);
                        await writable.write({ type: 'write', position: writePos + offset, data: chunk });
                    });
                    onLog('info', `  SHA256: ${hasher.hexdigest()}`);
                } else {
                    const data = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                    const hash = sha256(data);
                    onLog('info', `  SHA256: ${hash}`);
                    await writable.write({ type: 'write', position: writePos, data });
                }
                writePos += meta.size;
                const progress = 0.1 + 0.8 * ((idx + 1) / files.length);
                onProgress(progress, `Writing file ${idx + 1}/${files.length}...`);
            }

            onProgress(1.0, 'Done!');
            const outputName = file.name.replace(/\.xcz$/i, '.xci');
            const totalSize = hfs0Offset + hfs0TotalSize;
            onLog('success', `Output: ${outputName} (${this.formatBytes(totalSize)})`);
            return { blob: null, name: outputName, size: totalSize, writable: true };
        } else {
            // Memory path: build in memory for download
            onLog('info', 'Using memory download');
            const hfs0Writer = new HFS0Writer();
            for (let idx = 0; idx < files.length; idx++) {
                const meta = outputMeta[idx];
                const f = files[idx];
                const isNcz = meta.isNcz;
                const outputName = meta.name;
                onLog('info', `${isNcz ? 'Decompressing' : 'Copying'}: ${f.name} -> ${outputName}`);

                if (isNcz) {
                    const nczReader = new FileSliceReader(file, f.offset, f.size);
                    const decompressor = new NCZDecompressor(nczReader, this.keys);
                    const ncaData = await decompressor.decompress();
                    const hash = sha256(ncaData);
                    onLog('info', `  SHA256: ${hash}`);
                    hfs0Writer.addFile(outputName, ncaData);
                } else {
                    const fileData = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                    onLog('info', `  Size: ${fileData.byteLength} bytes`);
                    hfs0Writer.addFile(outputName, new Uint8Array(fileData));
                }
                onProgress(0.1 + 0.8 * ((idx + 1) / files.length), `Processing file ${idx + 1}/${files.length}...`);
            }

            onProgress(0.9, 'Building XCI...');
            const hfs0Data = hfs0Writer.build();
            onLog('info', `HFS0 partition built: ${hfs0Data.length} bytes`);

            const xciHeader = await fileReader.read(0, 0x200);
            const xciWriter = new XCIWriter(xciHeader);
            xciWriter.setHFS0Data(hfs0Data);
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

    async buildPFS0(files, writable = null, options = {}) {
        const { file = null, onLog = () => {}, fixPadding = false, onProgress = () => {} } = options;
        const outputName = file ? file.name.replace(/\.nsz$/i, '.nsp') : 'output.nsp';
        
        const stringTable = files.map(f => f.name).join('\0') + '\0';
        const headerSize = 0x10 + files.length * 0x18 + stringTable.length;
        const paddingSize = fixPadding ? (16 - (headerSize % 16)) % 16 : 0;

        let fileOffset = 0;
        
        const fileEntries = files.map(f => {
            const data = f.data;
            const entry = {
                name: f.name,
                offset: fileOffset,
                size: data instanceof ArrayBuffer ? data.byteLength : data.length,
                data: data
            };
            fileOffset += entry.size;
            return entry;
        });
        
        if (!writable) {
            onLog('info', 'Using memory download (no File System Access)');
            return this.buildPFS0Memory(fileEntries, stringTable, headerSize, paddingSize, fixPadding, onProgress, outputName);
        }
        
        onProgress(0.8, 'Writing output file...');
        const fileDataList = files.map(f => f.data);
        const streamResult = await this.buildPFS0Stream(writable, fileEntries, fileDataList, headerSize, stringTable, paddingSize, fixPadding, onProgress);
        onProgress(1.0, 'Done!');
        onLog('success', `Output: ${outputName} (${this.formatBytes(streamResult.size)})`);
        return { blob: null, name: outputName, size: streamResult.size, writable: true };
    }

    async buildPFS0Memory(fileEntries, stringTable, headerSize, paddingSize, fixPadding, onProgress, outputName) {
        const encoder = new TextEncoder();
        
        const fullHeaderSize = headerSize + paddingSize;
        const header = new Uint8Array(fullHeaderSize);
        const view = new DataView(header.buffer);

        header[0] = 0x50; header[1] = 0x46; header[2] = 0x53; header[3] = 0x30;
        view.setUint32(4, fileEntries.length, true);
        view.setUint32(8, stringTable.length + paddingSize, true);
        view.setUint32(12, 0, true);

        let stringOffset = 0;
        for (let i = 0; i < fileEntries.length; i++) {
            const entry = fileEntries[i];
            const pos = 0x10 + i * 0x18;
            
            view.setBigUint64(pos, BigInt(entry.offset), true);
            view.setBigUint64(pos + 8, BigInt(entry.size), true);
            view.setUint32(pos + 16, stringOffset, true);
            view.setUint32(pos + 20, 0, true);

            const nameBytes = encoder.encode(entry.name);
            header.set(nameBytes, 0x10 + fileEntries.length * 0x18 + stringOffset);
            stringOffset += nameBytes.length + 1;
        }

        onProgress(0.85, 'Building file in memory...');
        
        const totalDataSize = fileEntries.reduce((sum, e) => sum + Number(e.size), 0);
        const totalSize = fullHeaderSize + totalDataSize;
        const outputBuffer = new Uint8Array(totalSize);
        
        outputBuffer.set(header, 0);
        
        let offset = fullHeaderSize;
        for (let i = 0; i < fileEntries.length; i++) {
            const data = fileEntries[i].data;
            const arr = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
            outputBuffer.set(arr, offset);
            offset += arr.length;
            
            const progress = 0.85 + (0.15 * (offset - fullHeaderSize) / totalDataSize);
            onProgress(progress, `Building file ${i + 1}/${fileEntries.length}...`);
        }

        const blob = new Blob([outputBuffer], { type: 'application/octet-stream' });
        onProgress(1.0, 'Done!');
        return { blob, name: outputName, size: totalSize };
    }
}

export { NSZConverter };