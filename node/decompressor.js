import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { PFS0 } from './fs/pfs0.js';
import { NCZ } from './fs/ncz.js';
import { Keys } from './keys.js';
import { FileExistingChecks } from './fileExistingChecks.js';
import { PathTools } from './pathTools.js';

const CHUNK_SIZE = 0x100000;
const UNCOMPRESSABLE_HEADER_SIZE = 0x4000;

export class NSZDecompressor {
    constructor(inputPath, outputDir = null) {
        this.inputPath = inputPath;
        this.outputDir = outputDir || path.dirname(inputPath);
        this.inputBuffer = null;
        this.outputPath = null;
        this.keys = null;
        this.fileHashes = new Set();
    }

    async decompress(statusCallback = null) {
        this.log(statusCallback, 'info', `Opening ${this.inputPath}`);
        
        const buffer = fs.readFileSync(this.inputPath);
        this.inputBuffer = buffer;
        
        const container = new PFS0(buffer);
        
        if (this.keys) {
            this.fileHashes = FileExistingChecks.extractHashes(container, this.keys);
        }
        
        this.outputPath = PathTools.changeExtension(this.inputPath, '.nsp');
        if (this.outputDir) {
            this.outputPath = path.join(this.outputDir, path.basename(this.outputPath));
        }
        
        this.log(statusCallback, 'info', `Decompressing to ${this.outputPath}`);
        
        const outputFiles = [];
        
        for (const file of container.files) {
            if (file.path.endsWith('.ncz')) {
                this.log(statusCallback, 'info', `Decompressing NCZ: ${file.path}`);
                const ncaData = await this.decompressNCZ(file.data, statusCallback);
                const ncaName = file.path.replace(/\.ncz$/i, '.nca');
                outputFiles.push({ name: ncaName, data: ncaData });
            } else {
                this.log(statusCallback, 'info', `Copying: ${file.path}`);
                outputFiles.push({ name: file.path, data: file.data });
            }
        }
        
        this.writeNSP(outputFiles);
        
        return this.outputPath;
    }

    async decompressNCZ(data, statusCallback = null) {
        const magic = data.slice(0, 8).toString('ascii');
        if (magic !== 'NCZSECTN') {
            throw new Error('Invalid NCZ file: missing NCZSECTN magic');
        }

        let offset = 8;
        const sectionCount = data.readBigUInt64LE(offset);
        offset += 8;

        const sections = [];
        for (let i = 0; i < Number(sectionCount); i++) {
            const sectionOffset = Number(data.readBigUInt64LE(offset));
            offset += 8;
            const sectionSize = Number(data.readBigUInt64LE(offset));
            offset += 8;
            const cryptoType = Number(data.readBigUInt64LE(offset));
            offset += 8;
            offset += 8;
            const cryptoKey = data.slice(offset, offset + 16);
            offset += 16;
            const cryptoCounter = data.slice(offset, offset + 16);
            offset += 16;
            
            sections.push({ offset: sectionOffset, size: sectionSize, cryptoType, cryptoKey, cryptoCounter });
        }

        if (sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE > 0) {
            sections.unshift({
                offset: UNCOMPRESSABLE_HEADER_SIZE,
                size: sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE,
                cryptoType: 1
            });
        }

        let ncaSize = UNCOMPRESSABLE_HEADER_SIZE;
        for (const s of sections) {
            ncaSize += s.size;
        }

        const header = data.slice(0, UNCOMPRESSABLE_HEADER_SIZE);
        const output = Buffer.alloc(ncaSize);
        header.copy(output, 0);

        const compressedData = data.slice(offset);
        const blockMagic = compressedData.slice(0, 8).toString('ascii');
        const useBlockCompression = blockMagic === 'NCZBLOCK';

        let decompressedOffset = UNCOMPRESSABLE_HEADER_SIZE;

        for (let sIdx = 0; sIdx < sections.length; sIdx++) {
            const s = sections[sIdx];
            let i = s.offset;
            const end = s.offset + s.size;

            if (sIdx === 0) {
                const uncompressedSize = UNCOMPRESSABLE_HEADER_SIZE - sections[0].offset;
                if (uncompressedSize > 0) {
                    i += uncompressedSize;
                }
            }

            while (i < end) {
                const chunkSize = Math.min(0x10000, end - i);
                
                let chunk;
                if (useBlockCompression) {
                    chunk = await this.decompressBlock(compressedData, chunkSize);
                } else {
                    chunk = await this.decompressZstd(compressedData, chunkSize);
                }

                if (chunk.length === 0) break;

                if (s.cryptoType === 3 || s.cryptoType === 4) {
                    chunk = this.decryptChunk(chunk, s.cryptoKey, s.cryptoCounter, i);
                }

                chunk.copy(output, i);
                i += chunk.length;
                decompressedOffset += chunk.length;

                if (statusCallback) {
                    statusCallback(decompressedOffset / ncaSize, `Decompressing: ${Math.round(decompressedOffset / ncaSize * 100)}%`);
                }
            }
        }

        const hash = crypto.createHash('sha256').update(output).digest('hex');
        this.log(statusCallback, 'info', `NCA SHA256: ${hash}`);

        return output;
    }

    async decompressZstd(data, maxSize) {
        try {
            const zstd = await import('zstd-codec');
            const decompressor = new zstd.ZstdDecompressor();
            decompressor.init();
            return decompressor.decompress(data);
        } catch (e) {
            return Buffer.alloc(0);
        }
    }

    async decompressBlock(data, maxSize) {
        try {
            const zstd = await import('zstd-codec');
            const decompressor = new zstd.ZstdDecompressor();
            decompressor.init();
            return decompressor.decompress(data);
        } catch (e) {
            return Buffer.alloc(0);
        }
    }

    decryptChunk(data, key, counter, offset) {
        const ctr = Buffer.from(counter);
        const ofs = Math.floor(offset / 16);
        
        for (let j = 0; j < 8; j++) {
            ctr[0x10 - j - 1] = ofs & 0xff;
            ofs >>= 8;
        }

        const output = Buffer.alloc(data.length);
        
        for (let i = 0; i < data.length; i++) {
            const keyByte = key[i % 16];
            const ctrByte = ctr[8 + (i % 8)];
            output[i] = data[i] ^ keyByte ^ ctrByte;
        }
        
        return output;
    }

    writeNSP(files) {
        const stringTable = files.map(f => f.name).join('\0') + '\0';
        const headerSize = 0x10 + files.length * 0x18 + stringTable.length;
        const paddingSize = (16 - (headerSize % 16)) % 16;
        const paddedStringTableSize = stringTable.length + paddingSize;

        let fileOffset = 0x10 + files.length * 0x18 + paddedStringTableSize;
        const fileEntries = files.map(f => {
            const entry = {
                name: f.name,
                offset: fileOffset,
                size: f.data.length
            };
            fileOffset += f.data.length;
            return entry;
        });

        const output = Buffer.alloc(fileOffset + paddingSize);
        
        output.write('PFS0', 0);
        output.writeUInt32LE(files.length, 4);
        output.writeUInt32LE(paddedStringTableSize, 8);
        output.writeUInt32LE(0, 12);

        let stringOffset = 0;
        for (let i = 0; i < fileEntries.length; i++) {
            const entry = fileEntries[i];
            const pos = 0x10 + i * 0x18;
            
            output.writeBigUInt64LE(BigInt(entry.offset - 0x10 - files.length * 0x18 - paddedStringTableSize + 0x10 + files.length * 0x18), pos);
            output.writeBigUInt64LE(BigInt(entry.size), pos + 8);
            output.writeUInt32LE(stringOffset, pos + 16);
            output.writeUInt32LE(0, pos + 20);
            
            output.write(entry.name, 0x10 + files.length * 0x18 + stringOffset);
            stringOffset += entry.name.length + 1;
        }

        for (let i = 0; i < paddingSize; i++) {
            output.writeUInt8(0, 0x10 + files.length * 0x18 + stringTable.length + i);
        }

        for (const file of files) {
            file.data.copy(output, file.offset);
        }

        fs.writeFileSync(this.outputPath, output);
    }

    log(callback, type, message) {
        console.log(`[${type.toUpperCase()}] ${message}`);
        if (callback) {
            callback(type, message);
        }
    }

    setKeys(keyPath) {
        this.keys = Keys.load(keyPath);
    }
}