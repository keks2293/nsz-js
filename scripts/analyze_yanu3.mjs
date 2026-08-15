import { AesXts, AesCtr } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';
import fs from 'fs';

function parseKeys(path) {
    const keys = {};
    const lines = fs.readFileSync(path, 'utf-8').split('\n');
    for (const line of lines) {
        const [name, value] = line.split('=');
        if (name && value) keys[name.trim()] = value.trim();
    }
    return keys;
}

function hexToBytes(hex) {
    const b = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
    return b;
}

function readPfs0(file) {
    const v = new DataView(file.buffer);
    const fileCount = v.getUint32(0x04, true);
    const stringTableSize = v.getUint32(0x08, true);
    const headerSize = 0x10 + fileCount * 0x18 + stringTableSize;
    const entries = [];
    const stBase = headerSize - stringTableSize;
    for (let i = 0; i < fileCount; i++) {
        const off = 0x10 + i * 0x18;
        const fileOff = Number(v.getBigUint64(off, true));
        const fileSize = Number(v.getBigUint64(off + 8, true));
        const nameOffset = v.getUint32(off + 16, true);
        let name = '';
        for (let j = stBase + nameOffset; j < file.length && file[j] !== 0; j++) name += String.fromCharCode(file[j]);
        entries.push({ name, offset: fileOff + headerSize, size: fileSize });
    }
    return { headerSize, entries };
}

function decryptNcaHeader(data, keys) {
    const hdrKey = hexToBytes(keys.header_key);
    const xts = new AesXts(hdrKey);
    return xts.decrypt(data.subarray(0, 0xC00), 0);
}

async function main() {
    const keys = parseKeys('../static/prod.keys');
    const base = fs.readFileSync('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp');
    const yanu = fs.readFileSync('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp');

    // Extract base titlekey
    const basePfs0 = readPfs0(base);
    const tikEntry = basePfs0.entries.find(e => e.name.endsWith('.tik'));
    const tik = base.subarray(tikEntry.offset, tikEntry.offset + tikEntry.size);
    const titlekek = hexToBytes(keys.titlekek_02);
    const titlekey = new AesEcb(titlekek).decrypt(tik.subarray(0x180, 0x190));
    console.log('Base titlekey:', Array.from(titlekey).map(b => b.toString(16).padStart(2, '0')).join(''));

    // yanu merged NCA
    const yanuPfs0 = readPfs0(yanu);
    const ncaData = yanu.subarray(yanuPfs0.entries[0].offset, yanuPfs0.entries[0].offset + yanuPfs0.entries[0].size);

    const decHeader = decryptNcaHeader(ncaData, keys);
    console.log('\n=== yanu NCA decrypted header ===');
    const v = new DataView(decHeader.buffer, decHeader.byteOffset);
    console.log('magic:', String.fromCharCode(decHeader[0x200], decHeader[0x201], decHeader[0x202], decHeader[0x203]));
    console.log('contentType:', decHeader[0x205], 'cryptoType:', decHeader[0x206]);
    console.log('size:', v.getBigUint64(0x208, true).toString());

    // Check key block
    console.log('\nKey block (0x300-0x340):');
    console.log(Array.from(decHeader.subarray(0x300, 0x320)).map(b => b.toString(16).padStart(2, '0')).join(' '));

    // Section tables
    for (let s = 0; s < 4; s++) {
        const base = 0x240 + s * 0x10;
        const mediaOff = v.getUint32(base, true);
        const mediaEnd = v.getUint32(base + 4, true);
        if (mediaOff === 0 && mediaEnd === 0) break;
        const secOff = mediaOff * 0x200;
        const secSize = (mediaEnd - mediaOff) * 0x200;
        console.log(`\nSection ${s}: mediaOff=${mediaOff}, secOff=${secOff}, size=${secSize}`);

        // FsHeader
        const fhOff = yanuPfs0.entries[0].offset + secOff + 0x400;
        const fhData = yanu.subarray(fhOff, fhOff + 0x10);
        console.log('  Raw FsHeader:', Array.from(fhData).map(b => b.toString(16).padStart(2, '0')).join(' '));

        // Try decrypting section data with titlekey
        const sectionData = ncaData.subarray(secOff, secOff + Math.min(0x1000, secSize));
        const sectionCtrRaw = decHeader.subarray(0x400 + s * 0x200 + 0x140, 0x400 + s * 0x200 + 0x148);
        const sectionCtrRev = new Uint8Array(8);
        for (let i = 0; i < 8; i++) sectionCtrRev[i] = sectionCtrRaw[7 - i];

        console.log('  sectionCtrRaw:', Array.from(sectionCtrRaw).map(b => b.toString(16).padStart(2, '0')).join(' '));

        const ctr = new AesCtr(titlekey, sectionCtrRev);
        ctr.seek(secOff);
        const decSection = await ctr.decrypt(sectionData);
        console.log('  Decrypted @secOff:', String.fromCharCode(decSection[0], decSection[1], decSection[2], decSection[3]));
        console.log('  Decrypted @0x400 (FsHeader):', String.fromCharCode(decSection[0x400], decSection[0x401], decSection[0x402], decSection[0x403]));

        // Check for PFS0
        for (let i = 0; i < decSection.length - 4; i++) {
            if (String.fromCharCode(decSection[i], decSection[i + 1], decSection[i + 2], decSection[i + 3]) === 'PFS0') {
                console.log('  PFS0 found at decrypted offset:', i.toString(16));
                break;
            }
        }
    }
}

await main();
