import fs from 'node:fs';
import { AesXts, AesCtr } from '../crypto/aes-ops.mjs';
import { PFS0 } from '../fs/pfs0.js';
import { sha256 } from '../crypto/sha256.js';

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

function dumpBytes(buf, off, len) {
    return Array.from(buf.subarray(off, off + len)).map(b => b.toString(16).padStart(2,'0')).join(' ');
}

// Yanu merged NCA
const yanuNsp = fs.readFileSync('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp');
const yanuPfs0 = new PFS0(yanuNsp);
const yanuFiles = yanuPfs0.getFiles();
const yanuProg = yanuFiles.find(f => f.name.startsWith('8dc3f778'));
const yanuNca = yanuNsp.subarray(yanuProg.offset, yanuProg.offset + yanuProg.size);

const hdrKey = Buffer.from(keys.header_key, 'hex');
const xts = new AesXts(hdrKey);
const dec = xts.decrypt(yanuNca.subarray(0, 0xC00), 0);

// ExeFS FsHeader
const exeFsHdr = dec.subarray(0x400, 0x600);
const romFsHdr = dec.subarray(0x600, 0x800);

console.log('=== ExeFS FsHeader ===');
console.log('[0:16]:', dumpBytes(exeFsHdr, 0, 16));
console.log('[0x10:0x20]:', dumpBytes(exeFsHdr, 0x10, 16));
console.log('[0x40:0x48]:', dumpBytes(exeFsHdr, 0x40, 8), '(sectionStart)');
console.log('[0x48:0x50]:', dumpBytes(exeFsHdr, 0x48, 8), '(sectionSizeFs)');
console.log('[0x140:0x148]:', dumpBytes(exeFsHdr, 0x140, 8), '(section_ctr)');

const exeMediaOffset = new DataView(dec.buffer, dec.byteOffset + 0x240, 4).getUint32(0, true);
const exeMediaEnd = new DataView(dec.buffer, dec.byteOffset + 0x240 + 4, 4).getUint32(0, true);
const exeSecOffset = exeMediaOffset * 0x200;
const exeSecStart = Number(new DataView(exeFsHdr.buffer, exeFsHdr.byteOffset + 0x40, 8).getBigUint64(0, true));
const exeSecSizeFs = Number(new DataView(exeFsHdr.buffer, exeFsHdr.byteOffset + 0x48, 8).getBigUint64(0, true));
console.log(`mediaOffset=0x${exeMediaOffset.toString(16)} (0x${exeSecOffset.toString(16)})`);
console.log(`sectionStart=${exeSecStart}, sectionSizeFs=${exeSecSizeFs}`);
console.log(`raw at 0x${exeSecOffset.toString(16)}: ${dumpBytes(yanuNca, exeSecOffset, 16)}`);
console.log(`raw at 0x${(exeSecOffset + exeSecStart).toString(16)}: ${dumpBytes(yanuNca, exeSecOffset + exeSecStart, 16)}`);

console.log('\n=== RomFS FsHeader ===');
console.log('[0:16]:', dumpBytes(romFsHdr, 0, 16));
console.log('[0x10:0x20]:', dumpBytes(romFsHdr, 0x10, 16));
console.log('[0x40:0x48]:', dumpBytes(romFsHdr, 0x40, 8), '(sectionStart)');
console.log('[0x48:0x50]:', dumpBytes(romFsHdr, 0x48, 8), '(sectionSizeFs)');
console.log('[0x140:0x148]:', dumpBytes(romFsHdr, 0x140, 8), '(section_ctr)');

const romMediaOffset = new DataView(dec.buffer, dec.byteOffset + 0x240 + 0x10, 4).getUint32(0, true);
const romMediaEnd = new DataView(dec.buffer, dec.byteOffset + 0x240 + 0x10 + 4, 4).getUint32(0, true);
const romSecOffset = romMediaOffset * 0x200;
const romSecStart = Number(new DataView(romFsHdr.buffer, romFsHdr.byteOffset + 0x40, 8).getBigUint64(0, true));
const romSecSizeFs = Number(new DataView(romFsHdr.buffer, romFsHdr.byteOffset + 0x48, 8).getBigUint64(0, true));
console.log(`mediaOffset=0x${romMediaOffset.toString(16)} (0x${romSecOffset.toString(16)})`);
console.log(`sectionStart=${romSecStart}, sectionSizeFs=${romSecSizeFs}`);
console.log(`raw at 0x${romSecOffset.toString(16)}: ${dumpBytes(yanuNca, romSecOffset, 16)}`);

// KeyArea - check what keys yanu used
console.log('\n=== KeyArea ===');
const keyArea = dec.subarray(0x300, 0x340);
for (let i = 0; i < 4; i++) {
    console.log(`slot[${i}]: ${dumpBytes(keyArea, i*0x10, 0x10)}`);
}

// Now decrypt section with the key from keyArea
console.log('\n=== Decrypted ExeFS section ===');
const exeKey = keyArea.subarray(0x00, 0x10);
const exeCtrRaw = exeFsHdr.subarray(0x140, 0x148);
const exeCtrRev = new Uint8Array(8);
for (let j = 0; j < 8; j++) exeCtrRev[j] = exeCtrRaw[7-j];

const exeRaw = yanuNca.subarray(exeSecOffset, exeSecOffset + 0x10000);
const c = new AesCtr(exeKey, exeCtrRev);
c.seek(exeSecOffset);
const exeDec = await c.decrypt(exeRaw);
console.log(`decrypted at 0x00: ${dumpBytes(exeDec, 0, 16)}`);
console.log(`decrypted at 0xB000: ${dumpBytes(exeDec, 0xB000, 16)}`);

// The key at slot 0 is probably all zeros - yanu uses cryptoType=0 header with dummy keys
console.log('\n=== Checking: are keys all zeros? ===');
const allZeros = Array.from(keyArea).every(b => b === 0);
console.log('KeyArea all zeros?', allZeros);

// Try decrypting with section_ctr=0
console.log('\n=== Try decrypting RomFS with key=0, ctr=0 ===');
const romKey = keyArea.subarray(0x10, 0x20);
const romCtrRaw = romFsHdr.subarray(0x140, 0x148);
const romCtrRev = new Uint8Array(8);
for (let j = 0; j < 8; j++) romCtrRev[j] = romCtrRaw[7-j];

if (romKey.every(b => b === 0)) {
    console.log('RomFS key is all zeros - plaintext!');
    console.log(`raw at 0x${romSecOffset.toString(16)}: ${dumpBytes(yanuNca, romSecOffset, 16)}`);
    console.log(`raw at 0x${(romSecOffset + romSecStart).toString(16)}: ${dumpBytes(yanuNca, romSecOffset + romSecStart, 16)}`);
}

// Dump IVFC header at FsHeader+0x08
console.log('\n=== FsHeader IVFC header (offset 0x08) ===');
console.log('RomFS[0x00:0x10]:', dumpBytes(romFsHdr, 0x00, 16));
console.log('RomFS[0x10:0x20]:', dumpBytes(romFsHdr, 0x10, 16));
console.log('RomFS[0x20:0x30]:', dumpBytes(romFsHdr, 0x20, 16));
console.log('RomFS[0xE0:0x100]:', dumpBytes(romFsHdr, 0xE0, 32));
