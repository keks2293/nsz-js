#!/usr/bin/env node
/**
 * NSZ to NSP Converter - Standalone Node.js CLI
 * 
 * Uses the proper NCZDecompressor for NCZ files
 * Works identically to the browser version
 * 
 * Usage: node nsz-convert.js <input.nsz> [output.nsp] [keys.txt]
 */

import fs from 'fs';

// Import from the project modules
import { PFS0Reader } from './pfs0.js';
import { NCZDecompressor } from './ncz.js';
import { KeysParser } from './keys.js';
import { sha256 } from './crypto/sha256.js';

async function main() {
    const args = process.argv.slice(2);
    let inputPath = null;
    let outputPath = null;
    let keysPath = null;
    let fixPadding = false;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--fix-padding' || args[i] === '-p') {
            fixPadding = true;
        } else if (!inputPath) {
            inputPath = args[i];
        } else if (!outputPath && !args[i].startsWith('-')) {
            outputPath = args[i];
        } else if (!keysPath && !args[i].startsWith('-')) {
            keysPath = args[i];
        }
    }

    if (!inputPath) {
        console.log('NSZ to NSP Converter');
        console.log('');
        console.log('Usage: node nsz-convert.js <input.nsz> [output.nsp] [keys.txt] [options]');
        console.log('');
        console.log('Options:');
        console.log('  --fix-padding, -p    Pad PFS0 header to 16-byte boundary (match Python nsz)');
        console.log('');
        console.log('Examples:');
        console.log('  node nsz-convert.js game.nsz');
        console.log('  node nsz-convert.js game.nsz output.nsp');
        console.log('  node nsz-convert.js game.nsz output.nsp keys.txt');
        console.log('  node nsz-convert.js game.nsz --fix-padding');
        process.exit(1);
    }

    console.log('=== NSZ to NSP Converter ===');
    console.log(`Input: ${inputPath}`);
    
    // Load keys from provided path, or default location
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
        } catch(e) {
            // Continue to next location
        }
    }
    
    if (!keys) {
        console.log('Warning: No keys loaded - encrypted NCZ files may fail to decrypt');
    }
    
    // Read input
    const inputBuffer = fs.readFileSync(inputPath);
    console.log(`Input size: ${inputBuffer.length} bytes`);

    // Parse PFS0
    const pfs0Reader = new PFS0Reader(inputBuffer);
    const files = pfs0Reader.getFiles();
    console.log(`PFS0 files: ${files.length}`);
    files.forEach(f => console.log(`  ${f.name} (offset: ${f.offset}, size: ${f.size})`));
    
    // Find NCZ files
    const nczFiles = files.filter(f => f.name.toLowerCase().endsWith('.ncz'));
    console.log(`NCZ files found: ${nczFiles.length}`);

    // Decompress NCZ files and prepare output
    const outputFiles = [];
    
    for (let idx = 0; idx < files.length; idx++) {
        const f = files[idx];
        const isNcz = f.name.toLowerCase().endsWith('.ncz');
        const outputName = isNcz ? f.name.slice(0, -4) + '.nca' : f.name;
        
        console.log(`${isNcz ? 'Decompressing' : 'Copying'}: ${f.name} -> ${outputName}`);
        
        if (isNcz) {
            try {
                const nczData = await decompressNCZ(inputBuffer, f, keys);
                const hash = sha256(nczData);
                console.log(`  SHA256: ${hash}`);
                console.log(`  Size: ${nczData.byteLength} bytes`);
                outputFiles.push({ name: outputName, data: nczData, originalName: f.name });
            } catch(e) {
                console.error(`  ERROR: ${e.message}`);
                console.error(e.stack);
                process.exit(1);
            }
        } else {
            const data = inputBuffer.slice(f.offset, f.offset + f.size);
            const hash = sha256(data);
            console.log(`  SHA256: ${hash}`);
            outputFiles.push({ name: outputName, data, originalName: f.name });
        }
    }

    // Build output NSP
    const outPath = outputPath || inputPath.replace(/\.(nsz|nspz|nsx)$/i, '.nsp');
    await buildPFS0(outputFiles, outPath, fixPadding);
    
    const stat = fs.statSync(outPath);
    console.log('');
    console.log('=== DONE ===');
    console.log(`Output: ${outPath}`);
    console.log(`Size: ${stat.size} bytes (${(stat.size / 1024 / 1024).toFixed(2)} MB)`);
}

async function decompressNCZ(inputBuffer, nczFile, keys) {
    console.log(`  Reading NCZ: offset=${nczFile.offset}, size=${nczFile.size}`);
    const buffer = inputBuffer.slice(nczFile.offset, nczFile.offset + nczFile.size);
    
    try {
        const decompressor = new NCZDecompressor(buffer, keys);
        const result = await decompressor.decompress();
        return result;
    } catch(e) {
        console.error('NCZ decompression error:', e);
        throw e;
    }
}

function writeUInt64LE(buffer, value, offset) {
    buffer.writeUInt32LE(value & 0xFFFFFFFF, offset);
    buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4);
}

async function buildPFS0(files, outPath, fixPadding = false) {
    console.log(`\nBuilding PFS0 with ${files.length} files...`);
    
    // Build string table (null-terminated filenames)
    let stringTable = '';
    for (const f of files) {
        stringTable += f.name + '\0';
    }
    const stringTableBytes = Buffer.from(stringTable, 'utf-8');
    
    // Calculate sizes
    const headerSize = 0x10 + files.length * 0x18; // PFS0 header + file entries
    const rawHeaderSize = headerSize + stringTableBytes.length;
    const paddingSize = fixPadding ? (16 - (rawHeaderSize % 16)) % 16 : 0;
    const totalHeaderSize = rawHeaderSize + paddingSize;
    
    // File offsets are relative to end of PFS0 header (= start of data area)
    let fileRelOffset = 0;
    const fileEntries = files.map(f => {
        const entry = {
            name: f.name,
            offset: fileRelOffset,
            size: f.data.byteLength || f.data.length
        };
        fileRelOffset += entry.size;
        return entry;
    });
    
    // Create output buffer
    const totalSize = totalHeaderSize + fileRelOffset;
    const output = Buffer.alloc(totalSize);
    
    // Write PFS0 header (16 bytes)
    output.write('PFS0', 0);
    output.writeUInt32LE(files.length, 4);
    output.writeUInt32LE(stringTableBytes.length, 8);
    output.writeUInt32LE(0, 12);
    
    // Write string table after file entries
    stringTableBytes.copy(output, headerSize);
    
    // Write file entries (24 bytes each) and calculate string offsets
    for (let i = 0; i < fileEntries.length; i++) {
        const entry = fileEntries[i];
        const entryOffset = 0x10 + i * 0x18;
        
        const nameOffset = stringTable.indexOf(entry.name);
        
        writeUInt64LE(output, entry.offset, entryOffset);
        writeUInt64LE(output, entry.size, entryOffset + 8);
        output.writeUInt32LE(nameOffset, entryOffset + 16);
        output.writeUInt32LE(0, entryOffset + 20);
    }
    
    // Write file data (at absolute offsets = totalHeaderSize + relativeOffset)
    for (let i = 0; i < fileEntries.length; i++) {
        const entry = fileEntries[i];
        const data = files[i].data;
        const dataBytes = data instanceof Uint8Array ? Buffer.from(data) : Buffer.from(data);
        dataBytes.copy(output, totalHeaderSize + entry.offset);
        console.log(`  Written: ${entry.name} (${entry.size} bytes)`);
    }
    
    fs.writeFileSync(outPath, output);
    console.log(`PFS0 built: ${totalSize} bytes (padding: ${paddingSize})`);
}

main().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
