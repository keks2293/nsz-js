#!/usr/bin/env node

import fs from 'fs';
import crypto from 'crypto';
import { PFS0, PFS0Writer } from './fs/pfs0.js';
import { NCZDecompressor, FileDescriptorReader } from './fs/ncz.js';
import { KeysParser } from './keys.js';
import { HFS0Writer } from './fs/hfs0.js';

function verifyHash(hash, name, fileHashes) {
    if (fileHashes.size > 0) {
        if (fileHashes.has(hash)) {
            console.log(`  [VERIFIED]   ${name} ${hash}`);
        } else {
            console.log(`  [CORRUPTED]  ${name} ${hash}`);
            throw new Error(`Verification detected hash mismatch: ${name}`);
        }
    }
}

function verifyFileNameHash(hash, nczName, ncaName) {
    const fileNameHash = nczName.replace(/\.[^.]+$/, '').toLowerCase().slice(0, 32);
    if (hash.slice(0, 32) === fileNameHash) {
        console.log(`  [VERIFIED]   ${ncaName} ${hash}`);
    } else {
        console.log(`  [MISMATCH]   Filename starts with ${fileNameHash} but ${hash.slice(0, 32)} was expected`);
        throw new Error(`Verification detected hash mismatch: ${ncaName}`);
    }
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
    let outputPath = null;
    let keysPath = null;
    let fixPadding = false;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--fix-padding' || args[i] === '-p') {
            fixPadding = true;
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
            await convertXCZ(inReader, inputFd, inputPath, outputPath, keys);
        } else {
            await convertNSZ(inReader, inputFd, inputPath, outputPath, keys, fixPadding);
        }
    } finally {
        fs.closeSync(inputFd);
    }
}

async function convertXCZ(inReader, inputFd, inputPath, outputPath, keys) {
    console.log('Detected XCZ file');
    const { XCIReader } = await import('./fs/xci.js');
    const outPath = outputPath || inputPath.replace(/\.xcz$/i, '.xci');
    console.log(`Output: ${outPath}`);

    const xci = new XCIReader(inReader);
    await xci.parse();
    const partitions = xci.getPartitions();
    console.log(`Partitions: ${partitions.map(p => p.name).join(', ')}`);

    const PARTITION_HEADER_SIZE = 0x8000;
    const ROOT_HFS0_OFFSET = 0xF000;
    const ROOT_HFS0_PADDED_SIZE = 0x8000;
    const ROOT_DATA_SECTION = ROOT_HFS0_OFFSET + ROOT_HFS0_PADDED_SIZE;

    // First pass: read each partition's files and determine output sizes
    const partitionMetas = [];
    for (const partition of partitions) {
        if (partition.size === 0) {
            partitionMetas.push({ name: partition.name, files: [], totalSize: 0, cnmtHashes: new Set() });
            continue;
        }
        let hfs0;
        try {
            hfs0 = await xci.readPartitionFiles(partition);
        } catch (e) {
            console.log(`  ${partition.name}: cannot parse as HFS0, copying raw (${e.message})`);
            const buf = Buffer.alloc(partition.size);
            fs.readSync(inputFd, buf, 0, partition.size, partition.offset);
            partitionMetas.push({ name: partition.name, raw: true, rawData: buf, files: [], totalSize: partition.size, cnmtHashes: new Set() });
            continue;
        }
        const pFiles = hfs0.getFiles();
        console.log(`  ${partition.name}: ${pFiles.length} files`);

        // Extract CNMT hashes from this partition
        const cnmtHashes = new Set();
        const cnmtFiles = pFiles.filter(f => f.name.toLowerCase().endsWith('.cnmt.nca'));
        if (cnmtFiles.length > 0) {
            const { NSZConverter } = await import('./converter.js');
            const converter = new NSZConverter(keys);
            for (const cnmtFile of cnmtFiles) {
                const cnmtData = Buffer.alloc(cnmtFile.size);
                fs.readSync(inputFd, cnmtData, 0, cnmtFile.size, cnmtFile.offset);
                const hashes = await converter.extractCnmtHashes(cnmtData);
                hashes.forEach(h => cnmtHashes.add(h));
            }
            console.log(`  Found ${cnmtHashes.size} expected NCA hashes from CNMT in ${partition.name}`);
        }

        const fileMetas = [];
        for (const f of pFiles) {
            const isNcz = f.name.toLowerCase().endsWith('.ncz');
            const outputName = isNcz ? f.name.replace(/\.ncz$/i, '.nca') : f.name;
            if (isNcz) {
                const nczReader = new FileDescriptorReader(inputFd, f.offset, f.size);
                const tmpDecomp = new NCZDecompressor(nczReader, keys);
                const { ncaSize } = await tmpDecomp.getSections();
                fileMetas.push({ name: outputName, size: ncaSize, isNcz: true, offset: f.offset, nczLen: f.size, inputName: f.name });
            } else {
                fileMetas.push({ name: outputName, size: f.size, isNcz: false, offset: f.offset, inputName: f.name });
            }
        }
        const totalSize = fileMetas.reduce((s, m) => s + m.size, 0);
        partitionMetas.push({ name: partition.name, files: fileMetas, totalSize, raw: false, rawData: null, cnmtHashes });
    }

    const rootWriter = new HFS0Writer(ROOT_HFS0_PADDED_SIZE);
    const partSizes = [];
    for (const pm of partitionMetas) {
        const partSize = pm.raw ? pm.rawData.length : PARTITION_HEADER_SIZE + pm.totalSize;
        partSizes.push(partSize);
        rootWriter.addEntry(pm.name, partSize);
    }
    const rootActualHeader = rootWriter.getActualHeaderSize();

    let currentDataPos = 0;
    const partOffsets = [];
    for (let i = 0; i < partitionMetas.length; i++) {
        const pm = partitionMetas[i];
        const partSize = partSizes[i];
        partOffsets.push({ name: pm.name, offset: ROOT_DATA_SECTION + currentDataPos, size: partSize });
        currentDataPos += partSize;
    }
    const totalFileSize = ROOT_DATA_SECTION + currentDataPos;

    const outputFd = fs.openSync(outPath, 'w');
    try {
        const xciHeader = await inReader.read(0, 0x200);
        const xciHeaderOut = Buffer.alloc(0x200);
        xciHeaderOut.set(xciHeader.slice(0, 0x200), 0);
        xciHeaderOut.writeBigUInt64LE(BigInt(totalFileSize), 0x118);
        xciHeaderOut.writeBigUInt64LE(BigInt(ROOT_HFS0_OFFSET), 0x130);
        xciHeaderOut.writeBigUInt64LE(BigInt(rootActualHeader), 0x138);
        fs.writeSync(outputFd, xciHeaderOut, 0, 0x200, 0);

        const rootHeader = Buffer.from(rootWriter.buildHeader());
        fs.writeSync(outputFd, rootHeader, 0, rootHeader.length, ROOT_HFS0_OFFSET);

        // Write partitions
        for (let pi = 0; pi < partitionMetas.length; pi++) {
            const pm = partitionMetas[pi];
            const po = partOffsets[pi];

            if (pm.raw) {
                fs.writeSync(outputFd, pm.rawData, 0, pm.rawData.length, po.offset);
                console.log(`  [RAW] ${pm.name}: ${pm.rawData.length} bytes`);
                continue;
            }

            const pWriter = new HFS0Writer(PARTITION_HEADER_SIZE);
            for (const m of pm.files) pWriter.addEntry(m.name, m.size);
            const pHeader = Buffer.from(pWriter.buildHeader());
            fs.writeSync(outputFd, pHeader, 0, pHeader.length, po.offset);

            // Write files within partition
            let writePos = po.offset + PARTITION_HEADER_SIZE;
            for (let fi = 0; fi < pm.files.length; fi++) {
                const m = pm.files[fi];
                if (m.isNcz) {
                    console.log(`Decompressing: ${pm.name}/${m.inputName} -> ${m.name}`);
                    const nczReader = new FileDescriptorReader(inputFd, m.offset, m.nczLen);
                    const decomp = new NCZDecompressor(nczReader, keys);
                    const hasher = crypto.createHash('sha256');
                    await decomp.decompress(null, async (chunk, offset) => {
                        hasher.update(chunk);
                        fs.writeSync(outputFd, chunk, 0, chunk.byteLength, writePos + offset);
                    });
                    const hash = hasher.digest('hex');
                    console.log(`  SHA256: ${hash}`);
                    if (m.name.endsWith('.nca') && !m.name.endsWith('.cnmt.nca')) {
                        if (pm.cnmtHashes.size > 0) {
                            verifyHash(hash, m.name, pm.cnmtHashes);
                        } else {
                            verifyFileNameHash(hash, m.inputName, m.name);
                        }
                    }
                } else {
                    console.log(`Copying: ${pm.name}/${m.inputName} -> ${m.name}`);
                    const buf = Buffer.alloc(m.size);
                    fs.readSync(inputFd, buf, 0, m.size, m.offset);
                    const hash = crypto.createHash('sha256').update(buf).digest('hex');
                    console.log(`  SHA256: ${hash}`);
                    fs.writeSync(outputFd, buf, 0, m.size, writePos);
                    if (m.name.endsWith('.nca') && !m.name.endsWith('.cnmt.nca')) {
                        if (pm.cnmtHashes.size > 0) {
                            verifyHash(hash, m.name, pm.cnmtHashes);
                        } else {
                            verifyFileNameHash(hash, m.inputName, m.name);
                        }
                    }
                }
                writePos += m.size;
            }
        }
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

async function convertNSZ(inReader, inputFd, inputPath, outputPath, keys, fixPadding) {
    const outPath = outputPath || inputPath.replace(/\.(nsz|nspz|nsx)$/i, '.nsp');
    console.log(`Output: ${outPath}`);

    const pfs0Reader = await PFS0.open(inReader);
    const files = pfs0Reader.getFiles();
    console.log(`PFS0 files: ${files.length}`);

    // Collect CNMT hashes for verification
    const cnmtHashes = new Set();
    const cnmtFiles = files.filter(f => f.name.toLowerCase().endsWith('.cnmt.nca'));
    if (cnmtFiles.length > 0) {
        const { NSZConverter } = await import('./converter.js');
        const converter = new NSZConverter(keys);
        for (const cnmtFile of cnmtFiles) {
            const cnmtData = Buffer.alloc(cnmtFile.size);
            fs.readSync(inputFd, cnmtData, 0, cnmtFile.size, cnmtFile.offset);
            const hashes = await converter.extractCnmtHashes(cnmtData);
            hashes.forEach(h => cnmtHashes.add(h));
        }
        console.log(`  Found ${cnmtHashes.size} expected NCA hashes from CNMT`);
    }

    // First pass: determine output sizes
    const outputMeta = [];
    for (const f of files) {
        const isNcz = f.name.toLowerCase().endsWith('.ncz');
        const outputName = isNcz ? f.name.slice(0, -4) + '.nca' : f.name;
        if (isNcz) {
            console.log(`Reading NCZ header: ${f.name}`);
            const nczReader = new FileDescriptorReader(inputFd, f.offset, f.size);
            const tmpDecomp = new NCZDecompressor(nczReader, keys);
            const { ncaSize } = await tmpDecomp.getSections();
            outputMeta.push({ name: outputName, size: ncaSize, isNcz: true, offset: f.offset, compressedSize: f.size });
        } else {
            outputMeta.push({ name: outputName, size: f.size, isNcz: false, offset: f.offset });
        }
    }

    // Write output PFS0 header
    const writer = new PFS0Writer(fixPadding);
    for (const m of outputMeta) writer.add(m.name, m.size);
    const header = writer.buildHeader();
    const headerOutBuf = Buffer.from(header.buffer, header.byteOffset, header.byteLength);

    const outputFd = fs.openSync(outPath, 'w');
    try {
        fs.writeSync(outputFd, headerOutBuf, 0, header.length, 0);

        for (let idx = 0; idx < files.length; idx++) {
            const meta = outputMeta[idx];
            const f = files[idx];
            const absWritePos = header.length + writer.files[idx].offset;

            if (meta.isNcz) {
                console.log(`Decompressing: ${f.name} -> ${meta.name}`);
                const nczReader = new FileDescriptorReader(inputFd, f.offset, f.size);
                const decomp = new NCZDecompressor(nczReader, keys);
                const hasher = crypto.createHash('sha256');
                await decomp.decompress(null, async (chunk, offset) => {
                    hasher.update(chunk);
                    fs.writeSync(outputFd, chunk, 0, chunk.byteLength, absWritePos + offset);
                });
                const hash = hasher.digest('hex');
                console.log(`  SHA256: ${hash}`);
                if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                    if (cnmtHashes.size > 0) {
                        verifyHash(hash, meta.name, cnmtHashes);
                    } else {
                        verifyFileNameHash(hash, f.name, meta.name);
                    }
                }
                console.log(`  Size: ${meta.size} bytes`);
            } else {
                console.log(`Copying: ${f.name} -> ${meta.name}`);
                const buf = Buffer.alloc(f.size);
                fs.readSync(inputFd, buf, 0, f.size, f.offset);
                const hash = crypto.createHash('sha256').update(buf).digest('hex');
                console.log(`  SHA256: ${hash}`);
                if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                    if (cnmtHashes.size > 0) {
                        verifyHash(hash, meta.name, cnmtHashes);
                    } else {
                        verifyFileNameHash(hash, f.name, meta.name);
                    }
                }
                fs.writeSync(outputFd, buf, 0, f.size, absWritePos);
            }
        }
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
