import fs from 'fs';
import path from 'path';
import { sha256 } from '../crypto/unified.js';
import { PFS0, PFS0Writer } from '../pfs0.js';
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
        const writer = new PFS0Writer(true);
        for (const f of files) writer.add(f.name, f.data.length);
        const header = writer.buildHeader();

        const output = Buffer.alloc(header.length + writer.files.reduce((s, f) => s + f.size, 0));
        Buffer.from(header.buffer, header.byteOffset, header.byteLength).copy(output, 0);
        for (let i = 0; i < writer.files.length; i++) {
            files[i].data.copy(output, header.length + writer.files[i].offset);
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