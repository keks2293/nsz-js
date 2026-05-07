import fs from 'fs';
import path from 'path';
import { sha256 } from '../crypto/unified.js';
import { PFS0 } from './fs/pfs0.js';
import { NCZDecompressor } from '../ncz.js';
import { Keys } from './keys.js';
import { extractHashes } from './fileExistingChecks.js';
import { changeExtension } from './pathTools.js';

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
            this.fileHashes = extractHashes(container);
        }
        
        this.outputPath = changeExtension(this.inputPath, '.nsp');
        if (this.outputDir) {
            this.outputPath = path.join(this.outputDir, path.basename(this.outputPath));
        }
        
        this.log(statusCallback, 'info', `Decompressing to ${this.outputPath}`);
        
        const outputFiles = [];
        
        for (const file of container.files) {
            if (file.name.endsWith('.ncz')) {
                this.log(statusCallback, 'info', `Decompressing NCZ: ${file.name}`);
                // Use the working browser version
                const ncz = new NCZDecompressor(file.data, null);
                const ncaData = await ncz.decompress();
                const ncaName = file.name.replace(/\.ncz$/i, '.nca');
                outputFiles.push({ name: ncaName, data: Buffer.from(ncaData) });
            } else {
                this.log(statusCallback, 'info', `Copying: ${file.name}`);
                outputFiles.push({ name: file.name, data: file.data });
            }
        }
        
        this.writeNSP(outputFiles);
        
        return this.outputPath;
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
            
            output.writeBigUInt64LE(BigInt(entry.offset), pos);
            output.writeBigUInt64LE(BigInt(entry.size), pos + 8);
            output.writeUInt32LE(stringOffset, pos + 16);
            output.writeUInt32LE(0, pos + 20);
            
            output.write(entry.name, 0x10 + files.length * 0x18 + stringOffset);
            stringOffset += entry.name.length + 1;
        }

        for (let i = 0; i < paddingSize; i++) {
            output.writeUInt8(0, 0x10 + files.length * 0x18 + stringTable.length + i);
        }

        for (let i = 0; i < files.length; i++) {
            files[i].data.copy(output, fileEntries[i].offset);
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