#!/usr/bin/env node
// Check base RomFS vs merged RomFS sizes
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { extractRomfs } from '../fs/nca-pack.js';
import { AesXts } from '../crypto/aes-ops.mjs';
import { PFS0 } from '../fs/pfs0.js';

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

const baseNsp = fs.readFileSync('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp');
const updateNsp = fs.readFileSync('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsp');
const yanuNsp = fs.readFileSync('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp');

function u32(b,o){return new DataView(b.buffer, b.byteOffset + o, 4).getUint32(0, true)}

// Find Program NCA in each
const findProg = (nsp) => {
    const pfs0 = new PFS0(nsp);
    const files = pfs0.getFiles();
    return files.find(f => f.name.endsWith('.nca') && !f.name.endsWith('.cnmt.nca') && !f.name.includes('af613') && !f.name.includes('99636'));
};

const baseProg = findProg(baseNsp);
const updateProg = findProg(updateNsp);
const yanuProg = findProg(yanuNsp);

console.log('=== NCA sizes ===');
console.log(`Base Program NCA:  ${baseProg ? baseProg.size : 'NOT FOUND'}`);
console.log(`Update Program NCA: ${updateProg ? updateProg.size : 'NOT FOUND'}`);
console.log(`Yanu Program NCA: ${yanuProg ? yanuProg.size : 'NOT FOUND'}`);

// Extract RomFS from each
async function romfsSize(ncaData, label) {
    if (!ncaData) { console.log(`${label}: NOT FOUND`); return; }
    try {
        const romfs = await extractRomfs(ncaData, keys);
        console.log(`${label} RomFS: ${romfs.length} bytes`);
        return romfs;
    } catch (e) {
        console.log(`${label} RomFS ERROR: ${e.message}`);
        return null;
    }
}

console.log('\n=== RomFS extraction ===');
const baseRomfs = await romfsSize(baseNsp.subarray(baseProg.offset, baseProg.offset + baseProg.size), 'Base');
const updateRomfs = await romfsSize(updateNsp.subarray(updateProg.offset, updateProg.offset + updateProg.size), 'Update');
const yanuRomfs = await romfsSize(yanuNsp.subarray(yanuProg.offset, yanuProg.offset + yanuProg.size), 'Yanu');

if (baseRomfs && yanuRomfs) {
    console.log(`\n=== RomFS comparison ===`);
    console.log(`Base RomFS:  ${baseRomfs.length} bytes`);
    console.log(`Yanu RomFS:  ${yanuRomfs.length} bytes`);
    console.log(`Difference:  ${yanuRomfs.length - baseRomfs.length} bytes`);
    
    // Check first 64 bytes
    console.log(`\nBase RomFS first 16 bytes: ${Array.from(baseRomfs.subarray(0, 16)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`Yanu RomFS first 16 bytes: ${Array.from(yanuRomfs.subarray(0, 16)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
}
