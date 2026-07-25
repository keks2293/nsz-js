#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { DataReader } from './fs/ncz.js';
import { KeysParser } from './keys.js';
import { convertNSZ as convertNSZFile } from './fs/nsz-convert.js';
import { convertXCZ as convertXCZFile } from './fs/xcz-convert.js';
import { extractContentHashMap } from './fs/cnmt-hashes.js';

class FileDescriptorReader extends DataReader {
    constructor(fd, baseOffset = 0, totalLength = null) {
        super();
        this.fd = fd;
        this.baseOffset = baseOffset;
        this._length = totalLength;
    }

    get length() {
        return this._length;
    }

    async read(offset, size) {
        const buf = Buffer.allocUnsafe(size);
        const bytesRead = fs.readSync(this.fd, buf, 0, size, this.baseOffset + offset);
        if (bytesRead < size) {
            return new Uint8Array(buf.buffer, buf.byteOffset, bytesRead);
        }
        return new Uint8Array(buf.buffer, buf.byteOffset, size);
    }
}

function makeExtractCnmtHashMap(keys) {
    return (cnmtData) => extractContentHashMap(cnmtData, keys);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function main() {
    const args = process.argv.slice(2);
    let inputPath = null;
    let outputDir = null;
    let keysPath = null;
    let fixPadding = false;
    let verify = true;
    let overwrite = false;
    let rmSource = false;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--fix-padding' || args[i] === '-p') {
            fixPadding = true;
        } else if (args[i] === '--no-verify' || args[i] === '-nv') {
            verify = false;
        } else if (args[i] === '--help' || args[i] === '-h') {
            printUsage();
            process.exit(0);
        } else if (args[i] === '--keys' && i + 1 < args.length) {
            keysPath = args[++i];
        } else if (args[i] === '--overwrite' || args[i] === '-w') {
            overwrite = true;
        } else if (args[i] === '--rm-source') {
            rmSource = true;
        } else if ((args[i] === '-o' || args[i] === '--output') && i + 1 < args.length) {
            outputDir = args[++i];
        } else if (!inputPath) {
            inputPath = args[i];
        } else if (!keysPath && !args[i].startsWith('-')) {
            keysPath = args[i];
        }
    }

    function printUsage() {
        console.log('NSZ to NSP Converter');
        console.log('');
        console.log('Usage: node nsz-cli.js <input> [keys.txt] [options]');
        console.log('');
        console.log('Input formats:');
        console.log('  .nsz   -> .nsp');
        console.log('  .xcz                -> .xci');
        console.log('');
        console.log('Options:');
        console.log('  -o, --output <dir>   Output directory');
        console.log('  -w, --overwrite      Overwrite existing output files');
        console.log('  --rm-source          Delete input file after successful conversion');
        console.log('  --no-verify, -nv     Skip SHA256 verification (faster, no CNMT parsing)');
        console.log('  --fix-padding, -p    Re-pad PFS0 header to 0x20 boundary (default: reuse input string-table size, matching Python nsz)');
        console.log('');
    }

    if (!inputPath) {
        printUsage();
        process.exit(1);
    }

    let keys = null;
    const keysLocations = [
        keysPath,
        './static/prod.keys'
    ].filter(Boolean);

    for (const loc of keysLocations) {
        try {
            const keyText = fs.readFileSync(loc, 'utf-8');
            keys = KeysParser.parse(keyText);
            console.log(`Keys loaded from ${loc}`);
            break;
        } catch(e) {}
    }

    if (!keys) {
        console.log('Warning: No keys loaded - encrypted NCZ files may fail to decrypt');
    }

    const isXcz = inputPath.toLowerCase().endsWith('.xcz');
    const inStat = fs.statSync(inputPath);
    const inputSize = inStat.size;
    console.log('=== NSZ to NSP Converter ===');
    console.log(`Input: ${inputPath} (${formatBytes(inputSize)})`);

    const inputFd = fs.openSync(inputPath, 'r');
    const inReader = new FileDescriptorReader(inputFd, 0, inputSize);

    try {
        if (isXcz) {
            await convertXCZ(inReader, inputFd, inputPath, outputDir, keys, verify, overwrite, rmSource);
        } else {
            await convertNSZ(inReader, inputFd, inputPath, outputDir, keys, fixPadding, verify, overwrite, rmSource);
        }
    } finally {
        fs.closeSync(inputFd);
    }
}

async function convertXCZ(inReader, inputFd, inputPath, outputDir, keys, verify, overwrite, rmSource) {
    console.log(`[VERIFY NSZ] ${inputPath}`);
    console.log('Detected XCZ file');
    const outPath = outputDir ? path.join(outputDir, path.basename(inputPath).replace(/\.xcz$/i, '.xci')) : inputPath.replace(/\.xcz$/i, '.xci');
    console.log(`Output: ${outPath}`);

    if (!overwrite && fs.existsSync(outPath)) {
        console.error(`Error: ${outPath} already exists. Use -w/--overwrite to overwrite.`);
        process.exit(1);
    }

    const outputFd = fs.openSync(outPath, 'w');
    try {
        await convertXCZFile(inReader, keys, { fd: outputFd }, {
            verify,
            log: (level, msg) => console.log(msg),
            progress: () => {},
            createHash: () => {
                const h = crypto.createHash('sha256');
                return { update: (d) => h.update(d), hex: () => h.digest('hex') };
            },
            extractCnmtHashMap: makeExtractCnmtHashMap(keys),
        });
    } catch (e) {
        fs.closeSync(outputFd);
        try { fs.unlinkSync(outPath); } catch {}
        throw e;
    }
    fs.closeSync(outputFd);

    const outStat = fs.statSync(outPath);
    console.log('');
    console.log('=== DONE ===');
    console.log(`Output: ${outPath} (${formatBytes(outStat.size)})`);

    if (rmSource) {
        fs.unlinkSync(inputPath);
        console.log(`Deleted source: ${inputPath}`);
    }
}

async function convertNSZ(inReader, inputFd, inputPath, outputDir, keys, fixPadding, verify, overwrite, rmSource) {
    const outPath = outputDir ? path.join(outputDir, path.basename(inputPath).replace(/\.nsz$/i, '.nsp')) : inputPath.replace(/\.nsz$/i, '.nsp');
    console.log(`[VERIFY NSZ] ${inputPath}`);
    console.log(`Output: ${outPath}`);

    if (!overwrite && fs.existsSync(outPath)) {
        console.error(`Error: ${outPath} already exists. Use -w/--overwrite to overwrite.`);
        process.exit(1);
    }

    const outputFd = fs.openSync(outPath, 'w');
    try {
        await convertNSZFile(inReader, keys, { fd: outputFd }, {
            verify, fixPadding,
            log: (level, msg) => console.log(msg),
            progress: () => {},
            createHash: () => {
                const h = crypto.createHash('sha256');
                return { update: (d) => h.update(d), hex: () => h.digest('hex') };
            },
            extractCnmtHashMap: makeExtractCnmtHashMap(keys),
        });
    } catch (e) {
        fs.closeSync(outputFd);
        try { fs.unlinkSync(outPath); } catch {}
        throw e;
    }
    fs.closeSync(outputFd);

    const outStat = fs.statSync(outPath);
    console.log('');
    console.log('=== DONE ===');
    console.log(`Output: ${outPath} (${formatBytes(outStat.size)})`);

    if (rmSource) {
        fs.unlinkSync(inputPath);
        console.log(`Deleted source: ${inputPath}`);
    }
}

main().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
