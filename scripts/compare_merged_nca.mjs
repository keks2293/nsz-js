import fs from 'node:fs';
import { AesXts } from '../crypto/aes-ops.mjs';
import { PFS0 } from '../fs/pfs0.js';

const keysBuf = fs.readFileSync('../static/prod.keys');
const keys = {};
for (const line of keysBuf.toString().split('\n')) {
    const m = line.match(/^([^#=:]+)\s*[:=]\s*(.+)$/);
    if (m) keys[m[1].trim()] = m[2].trim();
}

function dumpBytes(buf, offset, len) {
    return Array.from(buf.subarray(offset, offset + len)).map(b => b.toString(16).padStart(2,'0')).join(' ');
}

function extractAndDump(path, label) {
    console.log(`\n=== ${label} ===`);
    const nsp = fs.readFileSync(path);
    const pfs0 = new PFS0(nsp);
    const files = pfs0.getFiles();
    console.log(`NSP size: ${nsp.length}`);
    
    for (const f of files) {
        if (f.name.endsWith('.nca') && !f.name.endsWith('.cnmt.nca')) {
            console.log(`\n  NCA: ${f.name} (${f.size})`);
            const nca = nsp.subarray(f.offset, f.offset + f.size);
            const hdrKey = Buffer.from(keys.header_key, 'hex');
            const xts = new AesXts(hdrKey);
            const dec = xts.decrypt(nca.subarray(0, 0xC00), 0);

            const magic = String.fromCharCode(dec[0x200], dec[0x201], dec[0x202], dec[0x203]);
            const ncaSize = Number(new DataView(dec.buffer, dec.byteOffset + 0x208, 8).getBigUint64(0, true));
            const cryptoType = dec[0x206];
            
            console.log(`    Magic: ${magic}, CryptoType: ${cryptoType}, NCA Size: ${ncaSize}`);
            
            for (let i = 0; i < 4; i++) {
                const fh = dec.subarray(0x400 + i * 0x200, 0x400 + i * 0x200 + 0x200);
                if (fh[0x00] === 0 && fh[0x01] === 0 && fh[0x02] === 0 && fh[0x03] === 0) continue;
                const mediaOffset = new DataView(dec.buffer, dec.byteOffset + 0x240 + i * 0x10, 4).getUint32(0, true);
                const mediaEnd = new DataView(dec.buffer, dec.byteOffset + 0x240 + i * 0x10 + 4, 4).getUint32(0, true);
                const sectionOffset = mediaOffset * 0x200;
                const sectionSize = mediaEnd * 0x200 - sectionOffset;
                const fsType = fh[0x03];
                const cryptType = fh[0x04];
                const sectionStart20 = Number(new DataView(fh.buffer, fh.byteOffset + 0x20, 8).getBigUint64(0, true));
                const sectionSizeFs28 = Number(new DataView(fh.buffer, fh.byteOffset + 0x28, 8).getBigUint64(0, true));
                const sectionStart40 = Number(new DataView(fh.buffer, fh.byteOffset + 0x40, 8).getBigUint64(0, true));
                const sectionSizeFs48 = Number(new DataView(fh.buffer, fh.byteOffset + 0x48, 8).getBigUint64(0, true));
                const sectionStart = fsType === 3 ? (sectionStart20 !== 0 ? sectionStart20 : sectionStart40) : sectionStart40;
                const sectionSizeFs = fsType === 3 ? (sectionSizeFs28 !== 0 ? sectionSizeFs28 : sectionSizeFs48) : sectionSizeFs48;
                if (fsType === 3 && (sectionStart20 !== sectionStart40 || sectionSizeFs28 !== sectionSizeFs48)) {
                    console.log(`      [FsHeader: @0x20 start=${sectionStart20}/size=${sectionSizeFs28}, @0x40 start=${sectionStart40}/size=${sectionSizeFs48}]`);
                }
                
                const fsTypeNames = {2: 'ExeFS', 3: 'RomFS'};
                const cryptTypeNames = {0: 'None', 1: 'AesCtr', 3: 'AesXts', 4: 'BKTR'};
                
                console.log(`    Sec${i}: ${fsTypeNames[fsType]||fsType} ${cryptTypeNames[cryptType]||cryptType}, media=${sectionOffset}+${sectionSize}, secStart=${sectionStart}, secSize=${sectionSizeFs}`);
                
                if (fsType === 3 && sectionSize > 0) {
                    const romfsPos = sectionOffset + sectionStart;
                    if (romfsPos + 16 <= nca.length) {
                        const magicStr = String.fromCharCode(nca[romfsPos], nca[romfsPos+1], nca[romfsPos+2], nca[romfsPos+3]);
                        console.log(`      RomFS Magic at 0x${romfsPos.toString(16)}: "${magicStr}" (${dumpBytes(nca, romfsPos, 4)})`);
                        console.log(`      RomFS first 64 bytes: ${dumpBytes(nca, romfsPos, 64)}`);
                    }
                }
                
                if (fsType === 2 && sectionSize > 0) {
                    const exefsPos = sectionOffset + sectionStart;
                    if (exefsPos + 4 <= nca.length) {
                        const magicStr = String.fromCharCode(nca[exefsPos], nca[exefsPos+1], nca[exefsPos+2], nca[exefsPos+3]);
                        console.log(`      ExeFS Magic at 0x${exefsPos.toString(16)}: "${magicStr}"`);
                    }
                }
            }
        } else {
            console.log(`  ${f.name} (${f.size})`);
        }
    }
}

extractAndDump('/tmp/update_e2e_out.nsp', 'OUR UPDATE NSP');
extractAndDump('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp', 'YANU UPDATE NSP');
