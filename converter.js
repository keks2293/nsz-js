import { ZstdDecompressor } from './crypto/zstd.js';
import { PFS0, PFS0Writer } from './fs/pfs0.js';
import { NCZDecompressor, DataReader } from './fs/ncz.js';
import { KeysParser } from './keys.js';
import { SHA256, sha256 } from './crypto/sha256.js';
import { extractHashesFromCnmt, Cnmt, ContentEntry, NCAHeader } from './fs/ticket.js';
import { XCIReader, HFS0Writer, XCIWriter } from './fs/xci.js';

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
        const { onProgress = () => {}, onLog = () => {}, writable = null, fixPadding = false } = options;

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
                const writePos = writer.headerSize + writer.files[idx].offset;

                if (meta.isNcz) {
                    const hasher = new SHA256();
                    const reader = new FileSliceReader(meta.file, meta.fileOffset, meta.nczLen);
                    const decompressor = new NCZDecompressor(reader, this.keys);
                    await decompressor.decompress(
                        (p) => onProgress(pct(dataWritten + meta.size * p), `Decompressing ${f.name}...`),
                        async (chunk, offset) => {
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
                    onProgress(pct(dataWritten), `Copying ${f.name}...`);
                    const data = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                    const hash = await sha256(data);
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
                onLog('info', `${meta.isNcz ? 'Decompressing' : 'Copying'}: ${f.name}`);

                if (meta.isNcz) {
                    const nczData = await this.decompressNCZ(file, f, (p) => onProgress(pct(dataWritten + meta.size * p), `Decompressing ${f.name}...`));
                    const hash = await sha256(nczData);
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
                    onProgress(pct(dataWritten), `Copying ${f.name}...`);
                    const data = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                    const hash = await sha256(data);
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
        const { onProgress = () => {}, onLog = () => {}, writable = null } = options;
        const reader = new FileSliceReader(file);
        const decompressor = new NCZDecompressor(reader, this.keys);
        const outputName = file.name.replace(/\.ncz$/i, '.nca');

        if (writable) {
            onLog('info', 'Using streaming output (File System Access)');
            let maxPos = 0;
            await decompressor.decompress((p) => onProgress(p, 'Decompressing...'), async (chunk, position) => {
                await writable.write({ type: 'write', position, data: chunk });
                const end = position + chunk.byteLength;
                if (end > maxPos) maxPos = end;
            });
            onProgress(1.0, 'Done!');
            onLog('success', `Output: ${outputName} (${this.formatBytes(maxPos)})`);
            return { blob: null, name: outputName, size: maxPos, writable: true };
        }

        onLog('info', 'Using memory download');
        const ncaData = await decompressor.decompress(onProgress);
        const hash = await sha256(ncaData);
        onLog('info', `NCA SHA256: ${hash}`);
        onProgress(1.0, 'Done!');
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
            const totalDataSize = outputMeta.reduce((s, m) => s + m.size, 0);
            let dataWritten = 0;
            const pct = (bytes) => 0.02 + 0.93 * (bytes / totalDataSize);
            for (let idx = 0; idx < files.length; idx++) {
                const meta = outputMeta[idx];
                const f = files[idx];

                if (meta.isNcz) {
                    const hasher = new SHA256();
                    const reader = new FileSliceReader(meta.file, meta.fileOffset, meta.nczLen);
                    const decomp = new NCZDecompressor(reader, this.keys);
                    await decomp.decompress(
                        (p) => onProgress(pct(dataWritten + meta.size * p), `Decompressing ${f.name}...`),
                        async (chunk, offset) => {
                            hasher.update(chunk);
                            await writable.write({ type: 'write', position: writePos + offset, data: chunk });
                        });
                    onLog('info', `  SHA256: ${hasher.hexdigest()}`);
                } else {
                    onProgress(pct(dataWritten), `Copying ${f.name}...`);
                    const data = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                    const hash = await sha256(data);
                    onLog('info', `  SHA256: ${hash}`);
                    await writable.write({ type: 'write', position: writePos, data });
                }
                writePos += meta.size;
                dataWritten += meta.size;
                onProgress(pct(dataWritten), `File ${idx + 1}/${files.length} done`);
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
            const totalDataSize = outputMeta.reduce((s, m) => s + m.size, 0);
            let dataWritten = 0;
            const pct = (bytes) => 0.02 + 0.93 * (bytes / totalDataSize);
            for (let idx = 0; idx < files.length; idx++) {
                const meta = outputMeta[idx];
                const f = files[idx];
                const isNcz = meta.isNcz;
                const outputName = meta.name;
                onLog('info', `${isNcz ? 'Decompressing' : 'Copying'}: ${f.name} -> ${outputName}`);

                if (isNcz) {
                    const nczReader = new FileSliceReader(file, f.offset, f.size);
                    const decompressor = new NCZDecompressor(nczReader, this.keys);
                    const ncaData = await decompressor.decompress((p) => onProgress(pct(dataWritten + meta.size * p), `Decompressing ${f.name}...`));
                    const hash = await sha256(ncaData);
                    onLog('info', `  SHA256: ${hash}`);
                    hfs0Writer.addFile(outputName, ncaData);
                } else {
                    onProgress(pct(dataWritten), `Copying ${f.name}...`);
                    const fileData = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                    onLog('info', `  Size: ${fileData.byteLength} bytes`);
                    hfs0Writer.addFile(outputName, new Uint8Array(fileData));
                }
                dataWritten += meta.size;
                onProgress(pct(dataWritten), `File ${idx + 1}/${files.length} done`);
            }

            onProgress(0.95, 'Building XCI...');
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