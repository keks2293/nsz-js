#!/usr/bin/env node
/**
 * NSZ to NSP Converter - Standalone Node.js CLI
 * 
 * Downloads fzstd from CDN and uses it for zstd decompression
 * Works identically in Node.js and Browser
 * 
 * Usage: node nsz-convert.js <input.nsz> [output.nsp]
 */

import fs from 'fs';
import https from 'https';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const zstdModule = require('zstandard');

const FZSTD_URL = 'https://unpkg.com/fzstd@0.1.1/umd/index.js';
const FZSTD_CACHE = '/tmp/fzstd.mjs';

const PFS0_MAGIC = 0x30534650;
let fzstd = null;

async function main() {
    const args = process.argv.slice(2);
    const inputPath = args[0];
    const outputPath = args[1] || inputPath?.replace(/\.nsz$/i, '.nsp');
    
    if (!inputPath) {
        console.log('NSZ to NSP Converter');
        console.log('');
        console.log('Usage: node nsz-convert.js <input.nsz> [output.nsp]');
        console.log('');
        console.log('Examples:');
        console.log('  node nsz-convert.js game.nsz');
        console.log('  node nsz-convert.js game.nsz output.nsp');
        process.exit(1);
    }

    console.log('=== NSZ to NSP Converter ===');
    console.log(`Input: ${inputPath}`);
    
    // Download fzstd
    try {
        fzstd = await loadFzstd();
        console.log('fzstd loaded');
    } catch(e) {
        console.error('Failed to load fzstd:', e.message);
        process.exit(1);
    }
    
    // Read input
    const inputBuffer = fs.readFileSync(inputPath);
    console.log(`Input size: ${inputBuffer.length} bytes`);

    // Parse PFS0
    const pfs0 = parsePfs0Header(inputBuffer);
    console.log(`PFS0 files: ${pfs0.fileCount}`);
    
    // Find NCZ files
    const nczFiles = pfs0.files.filter(f => f.name.toLowerCase().endsWith('.ncz'));
    console.log(`NCZ files found: ${nczFiles.length}`);

    // Convert
    const outPath = outputPath || inputPath.replace(/\.nsz$/i, '.nsp');
    await convertNszToNsp(inputBuffer, pfs0, nczFiles, outPath);
    
    const stat = fs.statSync(outPath);
    console.log('');
    console.log('=== DONE ===');
    console.log(`Output: ${outPath}`);
    console.log(`Size: ${stat.size} bytes`);
}

async function loadFzstd() {
    // Try to load from cache first
    try {
        return await import(FZSTD_CACHE);
    } catch(e) {
        // Cache miss, download
    }
    
    console.log('Downloading fzstd from CDN...');
    
    // Download to temp file
    await downloadFile(FZSTD_URL, FZSTD_CACHE);
    
    // Dynamic import
    return import(FZSTD_CACHE);
}

function downloadFile(url, path) {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(path);
        const protocol = url.startsWith('https') ? https : require('http');
        
        protocol.get(url, (res) => {
            if (res.statusCode === 301 || res.statusCode === 302) {
                downloadFile(res.headers.location, path).then(resolve).catch(reject);
                return;
            }
            res.pipe(file);
            file.on('finish', () => { file.close(); resolve(); });
        }).on('error', reject);
    });
}

function parsePfs0Header(buffer) {
    const view = new DataView(buffer.buffer, buffer.byteOffset);
    const magic = view.getUint32(0, true);
    
    if (magic !== PFS0_MAGIC) {
        throw new Error(`Invalid PFS0 magic: 0x${magic.toString(16)}`);
    }

    const fileCount = view.getUint32(8, true);
    const stringTableSize = view.getUint32(12, true);

    const files = [];
    for (let i = 0; i < fileCount; i++) {
        const offset = 16 + i * 16;
        const dataOffset = view.getUint32(offset, true);
        const dataSize = view.getUint32(offset + 8, true);
        const nameOffset = view.getUint32(offset + 12, true);
        
        const nameStart = 16 + fileCount * 16 + nameOffset;
        let nameEnd = nameStart;
        while (buffer[nameEnd] !== 0 && nameEnd < buffer.length) nameEnd++;
        const name = buffer.slice(nameStart, nameEnd).toString('utf-8');
        
        files.push({ name, dataOffset, dataSize });
    }

    return { fileCount, stringTableSize, files };
}

async function convertNszToNsp(input, pfs0, nczFiles, outPath) {
    // Decompress NCZ files
    for (const ncz of nczFiles) {
        console.log(`Decompressing ${ncz.name}...`);
        
        const compressed = input.slice(ncz.dataOffset, ncz.dataOffset + ncz.dataSize);
        
        // Decompress using fzstd
        // fzstd.decompress returns Uint8Array
        const decompressed = fzstd.decompress(new Uint8Array(compressed));
        
        ncz.decompressedSize = decompressed.length;
        ncz.data = Buffer.from(decompressed);
        
        console.log(`  ${ncz.dataSize} -> ${decompressed.length} bytes`);
    }

    // Calculate output size
    let outputSize = 16 + pfs0.fileCount * 16 + pfs0.stringTableSize;
    for (const f of pfs0.files) {
        const ncz = nczFiles.find(n => n.name === f.name);
        outputSize += ncz ? ncz.decompressedSize : f.dataSize;
    }

    console.log(`Creating output (${outputSize} bytes)...`);
    
    const output = Buffer.alloc(outputSize);
    
    // PFS0 header: magic, version, fileCount, stringTableSize
    output.write('PFS0', 0);
    output.writeUInt32LE(0x700, 4);
    output.writeUInt32LE(pfs0.fileCount, 8);
    output.writeUInt32LE(pfs0.stringTableSize, 12);

    // String table (filenames)
    let stringPos = 16 + pfs0.fileCount * 16;
    for (const f of pfs0.files) {
        const nameBuf = Buffer.from(f.name);
        nameBuf.copy(output, stringPos);
        stringPos += nameBuf.length + 1;
    }

    // File entries and data
    const headerSize = 16 + pfs0.fileCount * 16 + pfs0.stringTableSize;
    let dataPos = headerSize;
    
    for (let i = 0; i < pfs0.files.length; i++) {
        const file = pfs0.files[i];
        const entryOffset = 16 + i * 16;
        const ncz = nczFiles.find(n => n.name === file.name);
        
        // Data offset
        output.writeUInt32LE(dataPos, entryOffset);
        
        // Data size
        const size = ncz ? ncz.decompressedSize : file.dataSize;
        output.writeUInt32LE(size, entryOffset + 8);
        
        // Copy data
        if (ncz) {
            ncz.data.copy(output, dataPos);
            dataPos += ncz.decompressedSize;
        } else {
            input.copy(output, dataPos, file.dataOffset, file.dataOffset + file.dataSize);
            dataPos += file.dataSize;
        }
    }

    fs.writeFileSync(outPath, output);
    console.log(`Written: ${dataPos} bytes`);
}

main().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});