import fs from 'node:fs';
import { AesXts, AesCtr } from '../crypto/aes-ops.mjs';
import { PFS0 } from '../fs/pfs0.js';

const keysBuf = fs.readFileSync('../static/prod.keys');
const keys = {};
for (const line of keysBuf.toString().split('\n')) {
    const m = line.match(/^([^#=:]+)\s*[:=]\s*(.+)$/);
    if (m) keys[m[1].trim()] = m[2].trim();
}

function hexToBytes(hex) {
    const b = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) b[i/2] = parseInt(hex.substr(i,2), 16);
    return b;
}

// Read base program NCA
const baseNsp = fs.readFileSync('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp');
const basePfs0 = new PFS0(baseNsp);
const baseFiles = basePfs0.getFiles();
console.log('Base NSP files:');
for (const f of baseFiles) {
    console.log(`  ${f.name} (${f.size})`);
}

const progEntry = baseFiles.find(f => f.name.startsWith('4bfacc59'));
const baseNca = baseNsp.subarray(progEntry.offset, progEntry.offset + progEntry.size);
console.log(`\nBase Program NCA: ${baseNca.length} bytes`);

const hdrKey = Buffer.from(keys.header_key, 'hex');
const xts = new AesXts(hdrKey);
const dec = xts.decrypt(baseNca.subarray(0, 0xC00), 0);

// Dump section tables
for (let i = 0; i < 4; i++) {
    const fh = dec.subarray(0x400 + i * 0x200, 0x400 + i * 0x200 + 0x200);
    if (fh[0x00] === 0 && fh[0x01] === 0 && fh[0x02] === 0 && fh[0x03] === 0) continue;
    
    const mediaOffset = new DataView(dec.buffer, dec.byteOffset + 0x240 + i * 0x10, 4).getUint32(0, true);
    const mediaEnd = new DataView(dec.buffer, dec.byteOffset + 0x240 + i * 0x10 + 4, 4).getUint32(0, true);
    const sectionOffset = mediaOffset * 0x200;
    const sectionSize = mediaEnd * 0x200 - sectionOffset;
    const fsType = fh[0x03];
    const cryptType = fh[0x04];
    const partitionType = fh[0x02];
    const sectionStart = Number(new DataView(fh.buffer, fh.byteOffset + 0x40, 8).getBigUint64(0, true));
    const sectionSizeFs = Number(new DataView(fh.buffer, fh.byteOffset + 0x48, 8).getBigUint64(0, true));
    
    console.log(`\nSection ${i}: fsType=${fsType}, cryptType=${cryptType}, partitionType=${partitionType}`);
    console.log(`  mediaOffset=0x${mediaOffset.toString(16)} (0x${sectionOffset.toString(16)}), sectionSize=${sectionSize}`);
    console.log(`  sectionStart=${sectionStart}, sectionSizeFs=${sectionSizeFs}`);
    
    if (fsType === 3) { // RomFS
        const fsHdr = fh;
        console.log(`  FsHeader first 32 bytes: ${Array.from(fsHdr.subarray(0,32)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
        console.log(`  FsHeader 0x140 (section_ctr): ${Array.from(fsHdr.subarray(0x140,0x148)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
        
        // Check raw NCA at RomFS region
        console.log(`  Raw bytes at 0x${sectionOffset.toString(16)}: ${Array.from(baseNca.subarray(sectionOffset, sectionOffset+16)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
        console.log(`  Raw bytes at 0x${(sectionOffset + sectionStart).toString(16)}: ${Array.from(baseNca.subarray(sectionOffset+sectionStart, sectionOffset+sectionStart+16)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
        
        // Decrypt with seek(section.offset)
        const raw = baseNca.subarray(sectionOffset);
        const ctrRaw = fsHdr.subarray(0x140, 0x148);
        const ctrRev = new Uint8Array(8);
        for (let j = 0; j < 8; j++) ctrRev[j] = ctrRaw[7-j];
        const titlekey = hexToBytes(keys.titlekek_02); // placeholder - we need actual titlekey
        
        // Let's use tik to get titlekey
        const tikEntry = baseFiles.find(f => f.name.endsWith('.tik'));
        const tikData = baseNsp.subarray(tikEntry.offset, tikEntry.offset + tikEntry.size);
        console.log(`  Tik at ${tikEntry.name}, size ${tikData.length}`);
    }
}
