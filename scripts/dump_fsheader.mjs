import fs from 'fs';
import {PFS0} from '../fs/pfs0.js';
import {AesXts} from '../crypto/aes-ops.mjs';

const keysBuf = fs.readFileSync('../static/prod.keys');
const keys = {};
for (const line of keysBuf.toString().split('\n')) {
    const m = line.match(/^([^#=:]+)\s*[:=]\s*(.+)$/);
    if (m) keys[m[1].trim()] = m[2].trim();
}

const hdrKey = Buffer.from(keys.header_key, 'hex');
const xts = new AesXts(hdrKey);

function dumpFsHeader(path, label) {
    console.log(`\n=== ${label} ===`);
    const nsp = fs.readFileSync(path);
    const pfs0 = new PFS0(nsp);
    const files = pfs0.getFiles();
    const prog = files.find(f => f.name.endsWith('.nca') && !f.name.endsWith('.cnmt.nca'));
    const nca = nsp.subarray(prog.offset, prog.offset + prog.size);
    const dec = xts.decrypt(nca.subarray(0, 0xC00), 0);
    
    for (let i = 0; i < 2; i++) {
        const fh = dec.subarray(0x400 + i*0x200, 0x400 + i*0x200 + 0x200);
        console.log(`Sec${i}:`);
        console.log(`  [0x00:0x10]: ${Array.from(fh.subarray(0, 16)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
        console.log(`  [0x10:0x20]: ${Array.from(fh.subarray(0x10, 0x20)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
        console.log(`  [0x20:0x30]: ${Array.from(fh.subarray(0x20, 0x30)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
        console.log(`  [0x40:0x50]: ${Array.from(fh.subarray(0x40, 0x50)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
        console.log(`  [0xE0:0xF0]: ${Array.from(fh.subarray(0xE0, 0xF0)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    }
}

dumpFsHeader('/tmp/update_out/Stardew Valley [0100E65002BB8000][v0] (0.87 GB)_updated.nsp', 'OUR Merged');
dumpFsHeader('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp', 'YANU Merged');
