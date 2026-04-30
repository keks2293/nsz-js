import { ZstdDecompressor } from './crypto/zstd.js';
import { PFS0Reader } from './pfs0.js';
import { NCZDecompressor } from './ncz.js';
import { KeysParser } from './keys.js';
import { sha256 } from './crypto/sha256.js';
import { extractHashesFromCnmt, Cnmt, ContentEntry, NCAHeader } from './ticket.js';

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

    async decompressNSZtoNSP(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, fixPadding = false } = options;

        onLog('info', `Processing: ${file.name} (${this.formatBytes(file.size)})`);
        
        await this.init();

        const fileBuffer = await file.slice(0, Math.min(file.size, 4 * 1024 * 1024)).arrayBuffer();
        const pfs0Reader = new PFS0Reader(fileBuffer);
        const files = pfs0Reader.getFiles();
        
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

        const outputFiles = [];
        
        for (let idx = 0; idx < files.length; idx++) {
            const f = files[idx];
            const progress = 0.05 + (0.65 * (idx / files.length));
            onProgress(progress, `Processing file ${idx + 1}/${files.length}...`);
            
            const isNcz = f.name.toLowerCase().endsWith('.ncz');
            const outputName = isNcz ? f.name.slice(0, -4) + '.nca' : f.name;
            
            onLog('info', `${isNcz ? 'Decompressing' : 'Copying'}: ${f.name}`);

            if (isNcz) {
                const nczData = await this.decompressNCZ(file, f);
                const hash = sha256(nczData);
                onLog('info', `NCA SHA256: ${hash}`);
                
                if (!outputName.endsWith('.cnmt.nca')) {
                    if (cnmtHashes.size > 0) {
                        if (cnmtHashes.has(hash)) {
                            onLog('success', `[VERIFIED]   ${outputName}`);
                        } else {
                            onLog('error', `[CORRUPTED]  ${outputName} - hash mismatch!`);
                        }
                    } else {
                        const expectedFromFilename = file.name.toLowerCase().replace('.nsz', '.nca');
                        if (hash.startsWith(expectedFromFilename.substring(0, 32))) {
                            onLog('success', `[VERIFIED]   ${outputName}`);
                        }
                    }
                }
                
                outputFiles.push({ name: outputName, data: nczData });
            } else {
                const data = await file.slice(f.offset, f.offset + f.size).arrayBuffer();
                const hash = sha256(data);
                onLog('info', `NCA SHA256: ${hash}`);
                
                if (cnmtHashes.size > 0 && !outputName.endsWith('.cnmt.nca')) {
                    if (cnmtHashes.has(hash)) {
                        onLog('success', `[VERIFIED]   ${outputName}`);
                    } else {
                        if (hash in cnmtHashes) {
                            onLog('success', `[VERIFIED]   ${outputName}`);
                        } else {
                            onLog('error', `[CORRUPTED]  ${outputName} - hash mismatch!`);
                        }
                    }
                }
                
                outputFiles.push({ name: outputName, data });
            }
        }

        onProgress(0.7, 'Building PFS0 container...');
        const stringTable = outputFiles.map(f => f.name).join('\0') + '\0';
        return this.buildPFS0(outputFiles, writable, { file, onLog, fixPadding, onProgress });
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
            stringTableSizeInHeader = stringTable.length;
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
        const nczSize = nczFile.size;
        const buffer = await file.slice(nczFile.offset, nczFile.offset + nczSize).arrayBuffer();
        try {
            const decompressor = new NCZDecompressor(buffer, this.keys);
            return decompressor.decompress();
        } catch(e) {
            console.error('NCZ decompression error:', e);
            throw e;
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
        const paddingSize = (16 - (headerSize % 16)) % 16;

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
            onProgress(progress, `Processing file ${i + 1}/${fileEntries.length}...`);
        }

        const blob = new Blob([outputBuffer], { type: 'application/octet-stream' });
        onProgress(1.0, 'Done!');
        return { blob, name: outputName, size: totalSize };
    }
}

export { NSZConverter };