#!/usr/bin/env node
import { PFS0Reader } from './pfs0.js';
import { NCZDecompressor } from './ncz.js';
import { sha256 } from './crypto/sha256.js';
import fs from 'fs';

const args = process.argv.slice(2);
const filePath = args[0];
const workingPath = args[1] || null;

if (!filePath) {
    console.log('Compare NCZ decompression output against a reference NSP.');
    console.log('');
    console.log('Usage: node test_decompress.mjs <input.nsz> [working.nsp]');
    console.log('');
    console.log('  input.nsz    - NSZ file to decompress');
    console.log('  working.nsp  - optional reference NSP to compare against');
    console.log('');
    console.log('If working.nsp is provided, compares SHA256 and finds first mismatch.');
    process.exit(1);
}

async function test() {
    console.log(`Reading NSZ: ${filePath}`);
    const data = new Uint8Array(fs.readFileSync(filePath));
    const reader = new PFS0Reader(data);
    const files = reader.getFiles();

    const nczFile = files.find(f => f.name.endsWith('.ncz'));
    if (!nczFile) {
        console.error('No NCZ file found in NSZ container');
        process.exit(1);
    }
    console.log('NCZ file:', nczFile.name, 'offset:', nczFile.offset, 'size:', nczFile.size);

    const nczData = data.slice(nczFile.offset, nczFile.offset + nczFile.size);
    console.log('NCZ data length:', nczData.length);

    const decompressor = new NCZDecompressor(nczData, null);
    const decompressed = new Uint8Array(await decompressor.decompress());

    console.log('Decompressed size:', decompressed.length);
    const hash = sha256(decompressed);
    console.log('Decompressed SHA256:', hash);

    if (!workingPath) {
        console.log('No working NSP provided — skipping comparison');
        return;
    }

    console.log(`\nReading working NSP: ${workingPath}`);
    const workingData = new Uint8Array(fs.readFileSync(workingPath));
    const workingReader = new PFS0Reader(workingData);
    const workingFiles = workingReader.getFiles();

    const ncaFile = workingFiles.find(f => f.name.endsWith('.nca') && !f.name.includes('cnmt'));
    if (!ncaFile) {
        console.log('No NCA file found in working NSP');
        return;
    }

    console.log('Working NCA:', ncaFile.name, 'offset:', ncaFile.offset, 'size:', ncaFile.size);
    const workingHash = sha256(workingData.slice(ncaFile.offset, ncaFile.offset + ncaFile.size));
    console.log('Working SHA256:', workingHash);

    const workingSlice = workingData.slice(ncaFile.offset, ncaFile.offset + ncaFile.size);
    console.log('\nFinding mismatch...');
    for (let i = 0; i < Math.min(decompressed.length, workingSlice.length); i++) {
        if (decompressed[i] !== workingSlice[i]) {
            console.log(`Mismatch at byte ${i} (0x${i.toString(16)})`);
            console.log('Decompressed:', Array.from(decompressed.slice(Math.max(0, i-16), i+16)).map(b => b.toString(16).padStart(2, '0')).join(' '));
            console.log('Working:    ', Array.from(workingSlice.slice(Math.max(0, i-16), i+16)).map(b => b.toString(16).padStart(2, '0')).join(' '));
            break;
        }
    }

    console.log('\nSHA256 match:', hash === workingHash ? '✅' : '❌');
}

test().catch(e => console.error('Error:', e));
