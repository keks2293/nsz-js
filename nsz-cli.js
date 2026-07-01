#!/usr/bin/env node

import fs from 'fs';
import crypto from 'crypto';
import { PFS0 } from './fs/pfs0.js';
import { FileDescriptorReader } from './fs/ncz.js';
import { KeysParser } from './keys.js';
import { convertXCZStreaming } from './fs/xcz-convert.js';
import { convertNSZStreaming } from './fs/nsz-convert.js';

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
    let outputPath = null;
    let keysPath = null;
    let fixPadding = false;
    let verify = true;

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
        } else if (!inputPath) {
            inputPath = args[i];
        } else if (!outputPath && !args[i].startsWith('-')) {
            outputPath = args[i];
        } else if (!keysPath && !args[i].startsWith('-')) {
            keysPath = args[i];
        }
    }

    function printUsage() {
        console.log('NSZ to NSP Converter');
        console.log('');
        console.log('Usage: node nsz-cli.js <input> [output] [keys.txt] [options]');
        console.log('');
        console.log('Input formats:');
        console.log('  .nsz, .nspz, .nsx   -> .nsp');
        console.log('  .xcz                -> .xci');
        console.log('');
        console.log('Options:');
        console.log('  --no-verify, -nv     Skip SHA256 verification (faster, no CNMT parsing)');
        console.log('  --fix-padding, -p    Use 0x20-byte alignment (default: 16-byte, matching Python nsz)');
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
            await convertXCZ(inReader, inputFd, inputPath, outputPath, keys, verify);
        } else {
            await convertNSZ(inReader, inputFd, inputPath, outputPath, keys, fixPadding, verify);
        }
    } finally {
        fs.closeSync(inputFd);
    }
}

async function convertXCZ(inReader, inputFd, inputPath, outputPath, keys, verify) {
    console.log(`[VERIFY NSZ] ${inputPath}`);
    console.log('Detected XCZ file');
    const { XCIReader } = await import('./fs/xci.js');
    const outPath = outputPath || inputPath.replace(/\.xcz$/i, '.xci');
    console.log(`Output: ${outPath}`);

    const xci = new XCIReader(inReader);
    await xci.parse();
    console.log(`Partitions: ${xci.getPartitions().map(p => p.name).join(', ')}`);

    const outputFd = fs.openSync(outPath, 'w');
    try {
        const adapter = {
            read: (offset, size) => {
                const buf = Buffer.alloc(size);
                fs.readSync(inputFd, buf, 0, size, offset);
                return buf;
            },
            write: (offset, data) => fs.writeSync(outputFd, data, 0, data.byteLength, offset),
            log: (level, msg) => console.log(msg),
            progress: () => {},
        };

        const extractCnmtHashes = async (cnmtData) => {
            const { NSZConverter } = await import('./converter.js');
            const converter = new NSZConverter(keys);
            return converter.extractCnmtHashes(cnmtData);
        };

        await convertXCZStreaming(xci, keys, adapter, {
            verify,
            log: (level, msg) => console.log(msg),
            progress: () => {},
            createHash: () => {
                const h = crypto.createHash('sha256');
                return { update: (d) => h.update(d), digest: () => h.digest('hex') };
            },
        }, extractCnmtHashes);
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
}

async function convertNSZ(inReader, inputFd, inputPath, outputPath, keys, fixPadding, verify) {
    const outPath = outputPath || inputPath.replace(/\.(nsz|nspz|nsx)$/i, '.nsp');
    console.log(`[VERIFY NSZ] ${inputPath}`);
    console.log(`Output: ${outPath}`);

    const pfs0Reader = await PFS0.open(inReader);
    for (const f of pfs0Reader.getFiles()) {
        console.log(`[OPEN  ]     ${f.name} 0x${f.size.toString(16)} bytes at 0x${f.offset.toString(16)}`);
    }

    const outputFd = fs.openSync(outPath, 'w');
    try {
        const adapter = {
            read: (offset, size) => {
                const buf = Buffer.alloc(size);
                fs.readSync(inputFd, buf, 0, size, offset);
                return buf;
            },
            write: (offset, data) => fs.writeSync(outputFd, data, 0, data.byteLength, offset),
            log: (level, msg) => console.log(msg),
            progress: () => {},
        };

        const extractCnmtHashes = async (cnmtData) => {
            const { NSZConverter } = await import('./converter.js');
            const converter = new NSZConverter(keys);
            return converter.extractCnmtHashes(cnmtData);
        };

        await convertNSZStreaming(pfs0Reader, keys, adapter, {
            verify, fixPadding,
            log: (level, msg) => console.log(msg),
            progress: () => {},
            createHash: () => {
                const h = crypto.createHash('sha256');
                return { update: (d) => h.update(d), digest: () => h.digest('hex') };
            },
        }, extractCnmtHashes);
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
}

main().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
