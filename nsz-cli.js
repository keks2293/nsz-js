#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { PFS0 } from './fs/pfs0.js';
import { FileDescriptorReader } from './fs/ncz.js';
import { KeysParser } from './keys.js';
import { convertXCZStreaming, getInfoXCZ, extractXCZContainer, printXCZInfo } from './fs/xcz-convert.js';
import { convertNSZStreaming, getInfoNSZ, extractNSZContainer, printNSZInfo } from './fs/nsz-convert.js';
import { NCA, formatBytes } from './fs/nca.js';

function makeAdapter(inputFd, outputFd) {
    return {
        read: (offset, size) => {
            const buf = Buffer.alloc(size);
            fs.readSync(inputFd, buf, 0, size, offset);
            return buf;
        },
        write: (offset, data) => fs.writeSync(outputFd, data, 0, data.byteLength, offset),
        log: (level, msg) => console.log(msg),
        progress: () => {},
    };
}

function makeExtractAdapter(inputFd) {
    return {
        log: (msg) => console.log(msg),
        writeFile: (p, data) => {
            const fd = fs.openSync(p, 'w');
            fs.writeSync(fd, data, 0, data.length, 0);
            fs.closeSync(fd);
        },
        mkdir: (dir) => fs.mkdirSync(dir, { recursive: true }),
        read: (offset, size) => {
            const buf = Buffer.alloc(size);
            fs.readSync(inputFd, buf, 0, size, offset);
            return buf;
        },
        pathJoin: (...parts) => path.join(...parts),
        basename: (p, ext) => ext ? path.basename(p, ext) : path.basename(p),
        exists: (p) => fs.existsSync(p),
    };
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
    let extractMode = false;
    let infoMode = false;
    let depth = 1;
    let extractRegex = null;

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
        } else if (args[i] === '--extract' || args[i] === '-x') {
            extractMode = true;
        } else if (args[i] === '--extractregex' && i + 1 < args.length) {
            extractRegex = args[++i];
        } else if (args[i] === '--info' || args[i] === '-i') {
            infoMode = true;
        } else if (args[i] === '--depth' && i + 1 < args.length) {
            depth = parseInt(args[++i], 10);
        } else if (!inputPath) {
            inputPath = args[i];
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
        console.log('  -o, --output <dir>   Output directory');
        console.log('  -i, --info           Show NCA/container information');
        console.log('  -x, --extract        Extract NCA contents recursively');
        console.log('  --depth <n>          Extraction/info depth (default: 1)');
        console.log('  --extractregex <rx>  Regex filter for extracted files');
        console.log('  -w, --overwrite      Overwrite existing output files');
        console.log('  --rm-source          Delete input file after successful conversion');
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

    const inputFd = fs.openSync(inputPath, 'r');
    const inReader = new FileDescriptorReader(inputFd, 0, inputSize);

    try {
        if (infoMode) {
            console.log('');
            if (isXcz) {
                await printXCZInfo(inReader, inputPath, keys, depth, makeExtractAdapter(inputFd));
            } else {
                await printNSZInfo(inReader, inputPath, keys, depth, makeExtractAdapter(inputFd));
            }
        } else if (extractMode) {
            console.log('');
            if (isXcz) {
                await extractXCZContainer(inReader, inputPath, outputDir, keys, depth, extractRegex, makeExtractAdapter(inputFd));
            } else {
                await extractNSZContainer(inReader, inputPath, outputDir, keys, depth, extractRegex, makeExtractAdapter(inputFd));
            }
        } else {
            console.log('=== NSZ to NSP Converter ===');
            console.log(`Input: ${inputPath} (${formatBytes(inputSize)})`);

            if (isXcz) {
                await convertXCZ(inReader, inputFd, inputPath, outputDir, keys, verify, overwrite, rmSource);
            } else {
                await convertNSZ(inReader, inputFd, inputPath, outputDir, keys, fixPadding, verify, overwrite, rmSource);
            }
        }
    } finally {
        fs.closeSync(inputFd);
    }
}

async function convertXCZ(inReader, inputFd, inputPath, outputDir, keys, verify, overwrite, rmSource) {
    console.log(`[VERIFY NSZ] ${inputPath}`);
    console.log('Detected XCZ file');
    const { XCIReader } = await import('./fs/xci.js');
    const outPath = outputDir ? path.join(outputDir, path.basename(inputPath).replace(/\.xcz$/i, '.xci')) : inputPath.replace(/\.xcz$/i, '.xci');
    console.log(`Output: ${outPath}`);

    if (!overwrite && fs.existsSync(outPath)) {
        console.error(`Error: ${outPath} already exists. Use -w/--overwrite to overwrite.`);
        process.exit(1);
    }

    const xci = new XCIReader(inReader);
    await xci.parse();
    console.log(`Partitions: ${xci.getPartitions().map(p => p.name).join(', ')}`);

    const outputFd = fs.openSync(outPath, 'w');
    try {
        const adapter = makeAdapter(inputFd, outputFd);

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

    if (rmSource) {
        fs.unlinkSync(inputPath);
        console.log(`Deleted source: ${inputPath}`);
    }
}

async function convertNSZ(inReader, inputFd, inputPath, outputDir, keys, fixPadding, verify, overwrite, rmSource) {
    const outPath = outputDir ? path.join(outputDir, path.basename(inputPath).replace(/\.(nsz|nspz|nsx)$/i, '.nsp')) : inputPath.replace(/\.(nsz|nspz|nsx)$/i, '.nsp');
    console.log(`[VERIFY NSZ] ${inputPath}`);
    console.log(`Output: ${outPath}`);

    if (!overwrite && fs.existsSync(outPath)) {
        console.error(`Error: ${outPath} already exists. Use -w/--overwrite to overwrite.`);
        process.exit(1);
    }

    const pfs0Reader = await PFS0.open(inReader);
    for (const f of pfs0Reader.getFiles()) {
        console.log(`[OPEN  ]     ${f.name} 0x${f.size.toString(16)} bytes at 0x${f.offset.toString(16)}`);
    }

    const outputFd = fs.openSync(outPath, 'w');
    try {
        const adapter = makeAdapter(inputFd, outputFd);

        let cnmtHashes = new Set();
        if (verify) {
            const { NSZConverter } = await import('./converter.js');
            const converter = new NSZConverter(keys);
            const files = pfs0Reader.getFiles();
            for (const f of files.filter(f => f.name.toLowerCase().endsWith('.cnmt.nca'))) {
                const cnmtData = await adapter.read(f.offset, f.size);
                const hashes = await converter.extractCnmtHashes(cnmtData);
                hashes.forEach(h => cnmtHashes.add(h));
            }
            console.log(`Found ${cnmtHashes.size} expected NCA hahses from CNMT`);
        }

        await convertNSZStreaming(pfs0Reader, keys, adapter, {
            verify, fixPadding,
            log: (level, msg) => console.log(msg),
            progress: () => {},
            createHash: () => {
                const h = crypto.createHash('sha256');
                return { update: (d) => h.update(d), digest: () => h.digest('hex') };
            },
        }, cnmtHashes);
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
