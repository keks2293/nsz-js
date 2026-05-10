#!/usr/bin/env node
import fs from 'fs';
import { PFS0 } from './fs/pfs0.js';
import { NCZDecompressor } from './fs/ncz.js';
import { sha256 } from './crypto/sha256.js';

async function convertNSZtoNSP(inputPath) {
    console.log(`Reading: ${inputPath}`);
    const data = new Uint8Array(fs.readFileSync(inputPath));

    const pfs0 = new PFS0(data);
    const files = pfs0.getFiles();
    console.log(`Found ${files.length} files`);

    const outputFiles = [];
    for (const file of files) {
        if (file.name.toLowerCase().endsWith('.ncz')) {
            console.log(`Decompressing: ${file.name}`);
            const nczData = data.slice(file.offset, file.offset + file.size);
            const decompressor = new NCZDecompressor(nczData, null);
            const decompressed = await decompressor.decompress();
            const hash = sha256(decompressed);
            console.log(`  SHA256: ${hash}`);
            const outName = file.name.replace(/\.ncz$/i, '.nca');
            outputFiles.push({ name: outName, data: decompressed });
        } else {
            const fileData = data.slice(file.offset, file.offset + file.size);
            outputFiles.push({ name: file.name, data: fileData });
        }
    }

    console.log('\nDecompressed files:');
    outputFiles.forEach(f => console.log(`  ${f.name}: ${f.data.length} bytes`));

    return outputFiles;
}

const args = process.argv.slice(2);
if (args.length < 1) {
    console.log('Usage: node test_convert.mjs <input.nsz>');
    process.exit(1);
}

const input = args[0];
convertNSZtoNSP(input).catch(e => console.error('Error:', e));
