#!/usr/bin/env node

import fs from 'fs';
import { PFS0, PFS0Writer } from './fs/pfs0.js';
import { NCZDecompressor, FileDescriptorReader, BufferReader } from './fs/ncz.js';
import { KeysParser } from './keys.js';
import { sha256 } from './crypto/sha256.js';

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
        console.log('Usage: node nsz-convert.js <input> [output] [keys.txt] [options]');
        console.log('');
        console.log('Input formats:');
        console.log('  .nsz, .nspz, .nsx   -> .nsp');
        console.log('  .ncz                -> .nca');
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

    const isNcz = inputPath.toLowerCase().endsWith('.ncz');
    const isXcz = inputPath.toLowerCase().endsWith('.xcz');
    const inStat = fs.statSync(inputPath);
    const inputSize = inStat.size;
    console.log('=== NSZ to NSP Converter ===');
    console.log(`Input: ${inputPath} (${formatBytes(inputSize)})`);

    const inputFd = fs.openSync(inputPath, 'r');
    const inReader = new FileDescriptorReader(inputFd, 0, inputSize);

    try {
        if (isNcz) {
            await convertNCZ(inReader, inputFd, inputPath, outputPath, keys);
        } else if (isXcz) {
            await convertXCZ(inReader, inputFd, inputPath, outputPath, keys);
        } else {
            await convertNSZ(inReader, inputFd, inputPath, outputPath, keys, fixPadding);
        }
    } finally {
        fs.closeSync(inputFd);
    }
}

async function convertNCZ(inReader, inputFd, inputPath, outputPath, keys) {
    console.log('Detected standalone NCZ file');
    const outPath = outputPath || inputPath.replace(/\.ncz$/i, '.nca');
    console.log(`Output: ${outPath}`);

    const decomp = new NCZDecompressor(inReader, keys);
    const { ncaSize } = await decomp.getSections();
    console.log(`NCA size: ${formatBytes(ncaSize)}`);

    const outputFd = fs.openSync(outPath, 'w');
    try {
        const hasher = new (await import('./crypto/sha256.js')).SHA256();
        await decomp.decompress(null, async (chunk, offset) => {
            hasher.update(chunk);
            const buf = Buffer.from(chunk);
            fs.writeSync(outputFd, buf, 0, buf.length, offset);
        });
        const hash = hasher.hexdigest();
        console.log(`NCA SHA256: ${hash}`);
    } finally {
        fs.closeSync(outputFd);
    }

    const outStat = fs.statSync(outPath);
    console.log('');
    console.log('=== DONE ===');
    console.log(`Output: ${outPath} (${formatBytes(outStat.size)})`);
}

async function convertXCZ(inReader, inputFd, inputPath, outputPath, keys) {
    console.log('Detected XCZ file');
    const { XCIReader, HFS0Writer, XCIWriter } = await import('./fs/xci.js');
    const outPath = outputPath || inputPath.replace(/\.xcz$/i, '.xci');
    console.log(`Output: ${outPath}`);

    const xci = new XCIReader(inReader);
    await xci.parse();
    const files = xci.getSecurePartition();
    console.log(`HFS0 files: ${files.length}`);

    // First pass: determine output sizes
    const outputMeta = [];
    for (const f of files) {
        const isNcz = f.name.toLowerCase().endsWith('.ncz');
        const outputName = isNcz ? f.name.replace(/\.ncz$/i, '.nca') : f.name;
        if (isNcz) {
            const nczReader = new FileDescriptorReader(inputFd, f.offset, f.size);
            const tmpDecomp = new NCZDecompressor(nczReader, keys);
            const { ncaSize } = await tmpDecomp.getSections();
            outputMeta.push({ name: outputName, size: ncaSize, isNcz: true, offset: f.offset, compressedSize: f.size });
        } else {
            outputMeta.push({ name: outputName, size: f.size, isNcz: false, offset: f.offset });
        }
    }

    // Build HFS0 header to determine total size
    let fileRelOffset = 0;
    for (const m of outputMeta) {
        m.fileOffset = fileRelOffset;
        fileRelOffset += m.size;
    }
    const stringTable = outputMeta.map(m => m.name).join('\0') + '\0';
    const stringTableBytes = Buffer.from(stringTable, 'utf-8');
    const hfs0HeaderBase = 0x10 + outputMeta.length * 0x40;
    const hfs0TotalHeader = hfs0HeaderBase + stringTableBytes.length;
    const hfs0TotalSize = hfs0TotalHeader + fileRelOffset;

    // Write output XCI
    const outputFd = fs.openSync(outPath, 'w');
    try {
        const xciHeader = await inReader.read(0, 0x200);
        const xciWriter = new XCIWriter(xciHeader);
        const hfs0Offset = 0x200;

        // Write XCI header
        const hdrView = new DataView(xciHeader.buffer, xciHeader.byteOffset, xciHeader.byteLength);

        // Build HFS0 header buffer
        const hfs0Header = Buffer.alloc(hfs0TotalHeader);
        hfs0Header[0] = 0x48; hfs0Header[1] = 0x46; hfs0Header[2] = 0x53; hfs0Header[3] = 0x30;
        hfs0Header.writeUInt32LE(outputMeta.length, 4);
        hfs0Header.writeUInt32LE(stringTableBytes.length, 8);
        hfs0Header.writeUInt32LE(0, 12);
        stringTableBytes.copy(hfs0Header, hfs0HeaderBase);

        for (let i = 0; i < outputMeta.length; i++) {
            const m = outputMeta[i];
            const pos = 0x10 + i * 0x40;
            const nameOffset = stringTable.indexOf(m.name);
            hfs0Header.writeBigUInt64LE(BigInt(m.fileOffset), pos);
            hfs0Header.writeBigUInt64LE(BigInt(m.size), pos + 8);
            hfs0Header.writeUInt32LE(nameOffset, pos + 16);
            hfs0Header.writeUInt32LE(0, pos + 20);
            hfs0Header.writeUInt32LE(0, pos + 24);
            hfs0Header.writeUInt32LE(0, pos + 28);
            hfs0Header.writeBigUInt64LE(0n, pos + 32);
        }

        // Write XCI header bytes with updated offsets
        const xciHeaderOut = Buffer.alloc(0x200);
        xciHeaderOut.set(xciHeader.slice(0, 0x200), 0);
        xciHeaderOut.writeBigUInt64LE(BigInt(hfs0Offset + hfs0TotalSize), 0x118);
        xciHeaderOut.writeBigUInt64LE(BigInt(hfs0Offset), 0x130);
        const hfs0HeaderSize = 0x10 + outputMeta.length * 0x40 + stringTableBytes.length;
        xciHeaderOut.writeBigUInt64LE(BigInt(hfs0HeaderSize), 0x138);
        fs.writeSync(outputFd, xciHeaderOut, 0, 0x200, 0);

        // Write HFS0 header
        fs.writeSync(outputFd, hfs0Header, 0, hfs0TotalHeader, hfs0Offset);

        // Write files
        let writePos = hfs0Offset + hfs0TotalHeader;
        for (let i = 0; i < files.length; i++) {
            const f = files[i];
            const m = outputMeta[i];
            if (m.isNcz) {
                console.log(`Decompressing: ${f.name} -> ${m.name}`);
                const nczReader = new FileDescriptorReader(inputFd, f.offset, f.size);
                const decomp = new NCZDecompressor(nczReader, keys);
                const hasher = new (await import('./crypto/sha256.js')).SHA256();
                await decomp.decompress(null, async (chunk, offset) => {
                    hasher.update(chunk);
                    const buf = Buffer.from(chunk);
                    fs.writeSync(outputFd, buf, 0, buf.length, writePos + offset);
                });
                console.log(`  SHA256: ${hasher.hexdigest()}`);
            } else {
                console.log(`Copying: ${f.name} -> ${m.name}`);
                const buf = Buffer.alloc(f.size);
                fs.readSync(inputFd, buf, 0, f.size, f.offset);
                fs.writeSync(outputFd, buf, 0, f.size, writePos);
            }
            writePos += m.size;
        }
    } finally {
        fs.closeSync(outputFd);
    }

    const outStat = fs.statSync(outPath);
    console.log('');
    console.log('=== DONE ===');
    console.log(`Output: ${outPath} (${formatBytes(outStat.size)})`);
}

async function convertNSZ(inReader, inputFd, inputPath, outputPath, keys, fixPadding) {
    const outPath = outputPath || inputPath.replace(/\.(nsz|nspz|nsx)$/i, '.nsp');
    console.log(`Output: ${outPath}`);

    // Read PFS0 header (first 4MB)
    const headerBuf = Buffer.alloc(1024 * 1024);
    fs.readSync(inputFd, headerBuf, 0, headerBuf.length, 0);
    const pfs0Reader = new PFS0(headerBuf);
    const files = pfs0Reader.getFiles();
    console.log(`PFS0 files: ${files.length}`);

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
                const hasher = new (await import('./crypto/sha256.js')).SHA256();
                await decomp.decompress(null, async (chunk, offset) => {
                    hasher.update(chunk);
                    const buf = Buffer.from(chunk);
                    fs.writeSync(outputFd, buf, 0, buf.length, absWritePos + offset);
                });
                const hash = hasher.hexdigest();
                console.log(`  SHA256: ${hash}`);
                console.log(`  Size: ${meta.size} bytes`);
            } else {
                console.log(`Copying: ${f.name} -> ${meta.name}`);
                const buf = Buffer.alloc(f.size);
                fs.readSync(inputFd, buf, 0, f.size, f.offset);
                const hash = sha256(buf);
                console.log(`  SHA256: ${hash}`);
                fs.writeSync(outputFd, buf, 0, f.size, absWritePos);
            }
        }
    } finally {
        fs.closeSync(outputFd);
    }

    const outStat = fs.statSync(outPath);
    console.log('');
    console.log('=== DONE ===');
    console.log(`Output: ${outPath} (${formatBytes(outStat.size)})`);
}

main().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
