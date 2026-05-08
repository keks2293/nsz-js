#!/usr/bin/env node
import { PFS0Reader } from './pfs0.js';
import { NCZDecompressor } from './ncz.js';
import { sha256 } from './crypto/sha256.js';
import fs from 'fs';

async function test() {
    const filePath = './test.nsz';
    const workingPath = './test.nsp';
    
    // Read NSZ
    const data = new Uint8Array(fs.readFileSync(filePath));
    const reader = new PFS0Reader(data);
    const files = reader.getFiles();
    
    const nczFile = files.find(f => f.name.endsWith('.ncz'));
    console.log('NCZ file:', nczFile.name, 'offset:', nczFile.offset, 'size:', nczFile.size);
    
    // Extract NCZ data (starting at nczFile.offset within NSP)
    const nczData = data.slice(nczFile.offset, nczFile.offset + nczFile.size);
    console.log('NCZ data length:', nczData.length);
    console.log('NCZ first 16 bytes:', Array.from(nczData.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' '));
    
    // Decompress
    const decompressor = new NCZDecompressor(nczData, null);
    const decompressed = new Uint8Array(await decompressor.decompress());
    
    console.log('Decompressed size:', decompressed.length);
    const hash = sha256(decompressed);
    console.log('Decompressed SHA256:', hash);
    
    // Read working NSP
    const workingData = new Uint8Array(fs.readFileSync(workingPath));
    const workingReader = new PFS0Reader(workingData);
    const workingFiles = workingReader.getFiles();
    
    const ncaFile = workingFiles.find(f => f.name.endsWith('.nca') && !f.name.includes('cnmt'));
    if (ncaFile) {
        console.log('Working NCA:', ncaFile.name, 'offset:', ncaFile.offset, 'size:', ncaFile.size);
        const workingHash = sha256(workingData.slice(ncaFile.offset, ncaFile.offset + ncaFile.size));
        console.log('Working SHA256:', workingHash);
        
        // Find mismatch
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
}

test().catch(e => console.error('Error:', e));
