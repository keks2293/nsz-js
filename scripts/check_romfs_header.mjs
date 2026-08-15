#!/usr/bin/env node
// Check RomFS size in FsHeader vs actual decrypted size
import fs from 'fs';
import { AesXts } from '../crypto/aes-ops.mjs';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const hdrKey = Buffer.from(keys.header_key, 'hex');

function u32(b,o){return new DataView(b.buffer, b.byteOffset + o, 4).getUint32(0, true)}
function u64(b,o){return new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, true)}

const paths = [
    ['/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp', 'BASE'],
    ['/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp', 'YANU'],
];

for (const [path, label] of paths) {
    console.log(`\n=== ${label} ===`);
    const nsp = fs.readFileSync(path);
    const pfs0 = new PFS0(nsp);
    const files = pfs0.getFiles();
    const prog = files.find(f => f.name.endsWith('.nca') && !f.name.endsWith('.cnmt.nca') && !f.name.includes('af613') && !f.name.includes('99636'));
    if (!prog) { console.log('  No program NCA'); continue; }
    
    const nca = nsp.subarray(prog.offset, prog.offset + prog.size);
    const dec = new AesXts(hdrKey).decrypt(nca.subarray(0, 0xC00), 0);
    
    // NCA header
    const ncaSize = u64(dec, 0x208);
    console.log(`  NCA size from header: ${ncaSize}`);
    
    // Section entries
    for (let i = 0; i < 4; i++) {
        const base = 0x240 + i * 0x10;
        const mediaOff = u32(dec, base);
        const mediaEnd = u32(dec, base + 4);
        if (mediaOff || mediaEnd) {
            console.log(`  sec[${i}] mediaOff=${mediaOff} mediaEnd=${mediaEnd} size=${(mediaEnd - mediaOff) * 0x200} bytes (${((mediaEnd - mediaOff) * 0x200 / 1048576).toFixed(1)} MB)`);
        }
    }
    
    // FsHeaders
    for (let i = 0; i < 4; i++) {
        const fhOff = 0x400 + i * 0x200;
        const fh = dec.subarray(fhOff, fhOff + 0x200);
        const fsType = fh[0x02];
        const cryptType = fh[0x04];
        const hashType = fh[0x03];
        
        if (!fsType && !cryptType) continue;
        
        // Section start/size from FsHeader
        const secStart = u64(fh, 0x40);
        const secSize = u64(fh, 0x48);
        const secStart20 = u64(fh, 0x20);
        const secSize20 = u64(fh, 0x28);
        
        console.log(`  FsHeader[${i}] fsType=${fsType} cryptType=${cryptType} hashType=${hashType}`);
        console.log(`    @0x40: start=${secStart} size=${secSize}`);
        console.log(`    @0x20: start=${secStart20} size=${secSize20}`);
    }
}
