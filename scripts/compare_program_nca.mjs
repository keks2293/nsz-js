#!/usr/bin/env node
// Deep comparison of Program NCA between our output and yanu reference.
// Usage: node probe/compare_program_nca.mjs [our.nsp] [yanu.nsp] [keys]
import fs from 'node:fs';
import { AesXts } from '../crypto/aes-ops.mjs';
import { PFS0 } from '../fs/pfs0.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { KeysParser } from '../keys.js';

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

const ourPath = process.argv[2] || '/tmp/update_e2e_out.nsp';
const yanuPath = process.argv[3] || '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp';

function u32(b,o){return new DataView(b.buffer, b.byteOffset + o, 4).getUint32(0, true)}
function u64(b,o){return new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, true)}

function dumpNca(nspPath, label) {
    console.log(`\n=== ${label} ===`);
    const nsp = fs.readFileSync(nspPath);
    const pfs0 = new PFS0(nsp);
    const files = pfs0.getFiles();
    const prog = files.find(f => f.name.endsWith('.nca') && !f.name.endsWith('.cnmt.nca') && !f.name.includes('af613') && !f.name.includes('99636'));
    if (!prog) { console.log('  No program NCA found'); return; }
    console.log(`  NCA: ${prog.name} size=${prog.size}`);
    const nca = nsp.subarray(prog.offset, prog.offset + prog.size);
    const hdrKey = Buffer.from(keys.header_key, 'hex');
    const xts = new AesXts(hdrKey);
    const dec = xts.decrypt(nca.subarray(0, 0xC00), 0);

    const titleId = new DataView(dec.buffer, dec.byteOffset + 0x210, 8).getBigUint64(0, false).toString(16);
    const contentType = dec[0x205];
    const cryptoType = dec[0x206];
    const ncaSize = u64(dec, 0x208);
    console.log(`  titleId=${titleId} contentType=${contentType} cryptoType=${cryptoType} ncaSize=${ncaSize}`);

    // Section entries
    for (let i = 0; i < 4; i++) {
        const base = 0x240 + i * 0x10;
        const off = u32(dec, base);
        const end = u32(dec, base + 4);
        if (off || end) {
            console.log(`  sec[${i}] mediaOff=0x${(off*0x200).toString(16)} mediaEnd=0x${(end*0x200).toString(16)}`);
        }
    }

    // FsHeaders
    for (let i = 0; i < 4; i++) {
        const fhOff = 0x400 + i * 0x200;
        const fh = dec.subarray(fhOff, fhOff + 0x200);
        const ver = u32(fh, 0);
        const fsType = fh[0x02];
        const hashType = fh[0x03];
        const cryptType = fh[0x04];
        if (!ver && !fsType && !hashType && !cryptType) continue;

        const fsTypes = ['','PFS0','ExeFS','RomFS','HFS0'];
        const cryptTypes = ['NONE','AesCtr','AesXts','CTR','BKTR'];
        const hashTypes = ['','PFS0','SHA256','IVFC'];

        console.log(`\n  --- FsHeader[${i}] ---`);
        console.log(`  version=${ver} fsType=${fsType}(${fsTypes[fsType]||'?'}) hashType=${hashType}(${hashTypes[hashType]||'?'}) cryptType=${cryptType}(${cryptTypes[cryptType]||'?'})`);

        const masterHash = fh.subarray(0x08, 0x28).toString('hex').slice(0, 32);
        console.log(`  masterHash=${masterHash}...`);

        const blockSize = u32(fh, 0x28);
        const always2 = u32(fh, 0x2C);
        const htableSize = u64(fh, 0x38);
        const pfs0Offset = u64(fh, 0x40);
        const pfs0Size = u64(fh, 0x48);
        console.log(`  blockSize=0x${blockSize.toString(16)} always2=${always2} htableSize=${htableSize} pfs0Offset=${pfs0Offset} pfs0Size=${pfs0Size}`);

        // Section offsets from FsHeader
        const secStart20 = u64(fh, 0x20);
        const secSize20 = u64(fh, 0x28);
        const secStart40 = u64(fh, 0x40);
        const secSize48 = u64(fh, 0x48);
        const secStart = fsType === 3 ? (secStart20 !== 0 ? secStart20 : secStart40) : secStart40;
        const secSize = fsType === 3 ? (secSize20 !== 0 ? secSize20 : secSize48) : secSize48;
        console.log(`  sectionStart=${secStart}(0x${secStart.toString(16)}) sectionSize=${secSize}(0x${secSize.toString(16)})`);

        // IVFC specific
        if (hashType === 3 || fsType === 3) {
            const ivfcMagic = u32(fh, 0x08);
            const ivfcId = u32(fh, 0x0C);
            const ivfcHashSize = u32(fh, 0x10);
            const ivfcNumLevels = u32(fh, 0x0C); // Actually at 0x0C per nca.h
            console.log(`  IVFC magic=0x${ivfcMagic.toString(16)}`);

            // Read num_levels from IVFC header @0x0C
            const numLevels = u32(fh, 0x0C) & 0xFFFF;
            console.log(`  IVFC numLevels=${numLevels}`);

            // Read level headers
            for (let l = 0; l < Math.min(6, numLevels); l++) {
                const lb = 0x10 + l * 0x18;
                const logOff = u64(fh, lb);
                const hds = u64(fh, lb + 8);
                const bs = u32(fh, lb + 16);
                console.log(`  Lvl${l}: logical_offset=${logOff.toString(16)}(${logOff}) hash_data_size=${hds.toString(16)}(${hds}) block_size=${bs}(${bs})`);
            }
        }
    }

    // Compare raw bytes at specific offsets
    console.log(`\n  --- Raw comparison at key offsets ---`);
    const yProg = fs.readFileSync(yanuPath);
    const yPfs0 = new PFS0(yProg);
    const yFiles = yPfs0.getFiles();
    const yProgFile = yFiles.find(f => f.name.endsWith('.nca') && !f.name.endsWith('.cnmt.nca') && !f.name.includes('af613') && !f.name.includes('99636'));
    if (!yProgFile) { console.log('  No yanu program NCA'); return; }
    const yNca = yProg.subarray(yProgFile.offset, yProgFile.offset + yProgFile.size);
    const yDec = xts.decrypt(yNca.subarray(0, 0xC00), 0);

    // Compare headers
    const headerDiff = [];
    for (let i = 0; i < 0xC00; i += 0x10) {
        const ourChunk = dec.subarray(i, i + 0x10);
        const yanuChunk = yDec.subarray(i, i + 0x10);
        if (!ourChunk.every((b, j) => b === yanuChunk[j])) {
            const ourHex = Array.from(ourChunk).map(b => b.toString(16).padStart(2,'0').toUpperCase()).join(' ');
            const yanuHex = Array.from(yanuChunk).map(b => b.toString(16).padStart(2,'0').toUpperCase()).join(' ');
            headerDiff.push(`  @0x${i.toString(16).padStart(4,'0')}: OUR=${ourHex} YANU=${yanuHex}`);
        }
    }
    if (headerDiff.length > 0) {
        console.log(`  ${headerDiff.length} header differences found:`);
        for (const d of headerDiff.slice(0, 20)) console.log(d);
        if (headerDiff.length > 20) console.log(`  ... and ${headerDiff.length - 20} more`);
    } else {
        console.log('  Headers are byte-identical');
    }
}

dumpNca(ourPath, 'OUR');
dumpNca(yanuPath, 'YANU');
