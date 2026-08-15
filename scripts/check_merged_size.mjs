#!/usr/bin/env node
// Check: how yanu calculates merged Program NCA size
// yanu uses update NCA size, not base NCA size

import fs from 'fs';
import { PFS0 } from '../fs/pfs0.js';

const yanuPath = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp';
const nsp = fs.readFileSync(yanuPath);

function u32(b,o){return new DataView(b.buffer, b.byteOffset + o, 4).getUint32(0, true)}
function u64(b,o){return new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, true)}

const pfs0 = new PFS0(nsp);
const files = pfs0.getFiles();

console.log('=== Yanu NSP members ===');
for (const f of files) {
    console.log(`  ${f.name} size=${f.size} (${(f.size/1048576).toFixed(1)} MB)`);
}

// Find program NCA
const prog = files.find(f => f.name.endsWith('.nca') && !f.name.endsWith('.cnmt.nca') && !f.name.includes('af613') && !f.name.includes('99636'));
console.log(`\n=== Program NCA analysis ===`);
console.log(`Total NCA size: ${prog.size} bytes`);

// Header: 0xC00
// Sec0: ExeFS - padded to 0x200
// Sec1: RomFS - padded to 0x200

// From earlier dump:
// sec[0] mediaOff=0xc00 mediaEnd=0x5738800
// sec[1] mediaOff=0x5738800 mediaEnd=0x29abc800

const sec0Size = (0x5738800 - 0xC00) * 0x200;
const sec1Size = (0x29abc800 - 0x5738800) * 0x200;
const totalSize = 0x29abc800 * 0x200;

console.log(`Header: 0xC00 (3072)`);
console.log(`Sec0 (ExeFS): 0xC00 to 0x5738800 = ${(0x5738800 - 0xC00) * 0x200} bytes`);
console.log(`Sec1 (RomFS): 0x5738800 to 0x29abc800 = ${(0x29abc800 - 0x5738800) * 0x200} bytes`);
console.log(`Total: 0x29abc800 * 0x200 = ${0x29abc800 * 0x200} bytes`);

// Check if our output matches
const ourPath = '/tmp/update_e2e_out.nsp';
const ourNsp = fs.readFileSync(ourPath);
const ourPfs0 = new PFS0(ourNsp);
const ourFiles = ourPfs0.getFiles();
const ourProg = ourFiles.find(f => f.name.endsWith('.nca') && !f.name.endsWith('.cnmt.nca') && !f.name.includes('af613') && !f.name.includes('99636'));

console.log(`\n=== Our output ===`);
console.log(`Total NCA size: ${ourProg.size} bytes`);
console.log(`Difference: ${ourProg.size - prog.size} bytes`);
