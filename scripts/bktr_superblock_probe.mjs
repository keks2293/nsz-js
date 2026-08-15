import fs from 'fs';
import { createHash } from 'crypto';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesCtr, AesXts } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp`;
const updatePath = `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsp`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const sh = b => createHash('sha256').update(b).digest();

function members(path) {
    const d = fs.readFileSync(path);
    const pfs0 = new PFS0(d);
    return { d, entries: pfs0.getFiles() };
}

function titlekey(tikData) {
    const block = Buffer.from(tikData.subarray(0x180, 0x190));
    return Buffer.from(new AesEcb(Buffer.from(keys.titlekek_02, 'hex')).decrypt(block));
}

function hex(b, o, n) {
    return b.subarray(o, o + n).toString('hex').replace(/(..)/g, '$1 ').trim();
}

function dumpFsHeader(label, fh) {
    console.log(`\n=== ${label} ===`);
    for (let row = 0; row < 0x200; row += 0x10) {
        const b = fh.subarray(row, row + 0x10);
        let ascii = '';
        for (let i = 0; i < 0x10; i++) {
            const c = b[i];
            ascii += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
        }
        console.log(`${row.toString(16).padStart(3, '0')}: ${hex(b, 0, 0x10)}  ${ascii}`);
    }
}

function getProgramNca(d, entries, name) {
    const e = entries.find(x => x.name.toLowerCase().endsWith('.nca') && !x.name.toLowerCase().endsWith('.cnmt.nca'));
    return { e, raw: d.subarray(e.offset, e.offset + e.size) };
}

const base = members(basePath);
const upd = members(updatePath);
const baseProg = getProgramNca(base.d, base.entries);
const updProg = getProgramNca(upd.d, upd.entries);

const hdrKey = Buffer.from(keys.header_key, 'hex');
const baseHdr = decryptNcaHeader(baseProg.raw.subarray(0, 0xC00), keys);
const updHdr = decryptNcaHeader(updProg.raw.subarray(0, 0xC00), keys);

const baseTik = base.entries.find(t => t.name.toLowerCase().endsWith('.tik'));
const updTik = upd.entries.find(t => t.name.toLowerCase().endsWith('.tik'));
const baseTitlekey = titlekey(base.d.subarray(baseTik.offset, baseTik.offset + baseTik.size));
const updTitlekey = titlekey(upd.d.subarray(updTik.offset, updTik.offset + updTik.size));

const xts = new AesXts(hdrKey);
const baseDec = Buffer.from(xts.decrypt(baseProg.raw.subarray(0, 0xC00), 0));
const updDec = Buffer.from(xts.decrypt(updProg.raw.subarray(0, 0xC00), 0));

console.log(`base romfs secIdx=${baseHdr.sections.findIndex(s => s.fsType === 3)}`);
console.log(`update romfs secIdx=${updHdr.sections.findIndex(s => s.fsType === 3)}`);

const baseRomfsIdx = baseHdr.sections.findIndex(s => s.fsType === 3);
const updRomfsIdx = updHdr.sections.findIndex(s => s.fsType === 3);
const baseFh = baseDec.subarray(0x400 + baseRomfsIdx * 0x200, 0x400 + baseRomfsIdx * 0x200 + 0x200);
const updFh = updDec.subarray(0x400 + updRomfsIdx * 0x200, 0x400 + updRomfsIdx * 0x200 + 0x200);
dumpFsHeader(`BASE RomFS FsHeader (idx ${baseRomfsIdx})`, baseFh);
dumpFsHeader(`UPDATE RomFS FsHeader (idx ${updRomfsIdx})`, updFh);

function readU64(b, o) { return Number(b.readBigUInt64LE(o)); }

// Parse IVFC superblock at given offset
function parseIvfc(label, fh, off) {
    const magic = fh.toString('ascii', off, off + 4);
    console.log(`\n${label}: IVFC magic at ${magic === 'IVFC' ? 'YES' : 'NO'} (off 0x${off.toString(16)})`);
    if (magic !== 'IVFC') return null;
    console.log(`${label}: id=0x${fh.readUInt32LE(off + 4).toString(16)} masterHashSize=${fh.readUInt32LE(off + 8)} numLevels=${fh.readUInt32LE(off + 12)}`);
    const lv = off + 0x18;
    for (let i = 0; i < 7; i++) {
        const o = readU64(fh, lv + i * 0x18);
        const sz = readU64(fh, lv + i * 0x18 + 8);
        console.log(`${label}: level[${i}] = {offset 0x${o.toString(16)}, size 0x${sz.toString(16)}}`);
    }
    const mh = off + 0xC8;
    console.log(`${label}: masterHash = ${fh.subarray(mh, mh + 0x20).toString('hex')}`);
    return { mh: fh.subarray(mh, mh + 0x20) };
}

const baseIvfc = parseIvfc('BASE', baseFh, 0x08);
const updIvfc = parseIvfc('UPDATE', updFh, 0x08);

// Now decrypt base romfs media and check: does the base level[5] data start with IVFC?
const baseSec = baseHdr.sections[baseRomfsIdx];
const baseNonce = Buffer.alloc(8);
const baseCtrRaw = baseFh.subarray(0x140, 0x148);
for (let j = 0; j < 8; j++) baseNonce[j] = baseCtrRaw[7 - j];
const bc = new AesCtr(baseTitlekey, baseNonce);
bc.seek(baseSec.offset);
const baseMedia = Buffer.from(await bc.decrypt(baseProg.raw.subarray(baseSec.offset, baseSec.offset + baseSec.size)));
console.log(`\nbase romfs section: offset=0x${baseSec.offset.toString(16)} size=0x${baseSec.size.toString(16)} (${baseSec.size})`);
console.log(`base media[0:0x20] = ${hex(baseMedia, 0, 0x20)}  magic='${baseMedia.toString('ascii', 0, 4)}'`);
console.log(`base media len=0x${baseMedia.length.toString(16)}`);

// IVFC inside the base media? The actual romfs starts with IVFC
for (let off = 0; off < Math.min(baseMedia.length, 0x200000); off += 0x10) {
    if (baseMedia.toString('ascii', off, off + 4) === 'IVFC') {
        console.log(`base media: 'IVFC' at 0x${off.toString(16)}`);
        console.log(`  base media[0x${off.toString(16)}:0x${(off + 0xE0).toString(16)}] = ${hex(baseMedia, off, 0xE0)}`);
        break;
    }
}

// Check base level4 (hash) relationship: level4[0] should equal sha256(level5 data block 0)?
// Using baseIvfc levels relative to section start.
if (baseIvfc) {
    // baseIvfc levels are relative to section start? For base, sectionStart (0x40) = 0xe?? Let's just read level offsets directly from media
    const l5o = baseIvfc && readU64(baseFh, 0x88 + 5 * 0x18);
    const l5s = baseIvfc && readU64(baseFh, 0x88 + 5 * 0x18 + 8);
    console.log(`\nbase level[5] = {0x${l5o.toString(16)}, 0x${l5s.toString(16)}}`);
    if (l5s < baseMedia.length) {
        console.log(`base media[l5o..l5o+0x10] = ${hex(baseMedia, l5o, 0x10)} magic='${baseMedia.toString('ascii', l5o, l5o + 4)}'`);
        // hash of first 0x4000 block of l5
        const h = sh(baseMedia.subarray(l5o, l5o + 0x4000));
        const l4o = readU64(baseFh, 0x88 + 4 * 0x18);
        const l4s = readU64(baseFh, 0x88 + 4 * 0x18 + 8);
        console.log(`base level[4] = {0x${l4o.toString(16)}, 0x${l4s.toString(16)}}`);
        console.log(`base l4[0] = ${baseMedia.subarray(l4o, l4o + 0x20).toString('hex')}`);
        console.log(`base sha256(l5[0:0x4000]) = ${h.toString('hex')}`);
        console.log(`base l4[0] == sha256(l5 block 0): ${baseMedia.subarray(l4o, l4o + 0x20).equals(h)}`);
        // master hash check
        const mh = baseIvfc.mh;
        console.log(`base masterHash == sha256(l5[0:0x4000]): ${mh.equals(h)}`);
    }
}

// Update: decrypt BKTR section? No — for the virtual image we need the merged result.
// Instead: check yanu's NCA FsHeader — how did yanu pack the merged romfs?
const yanuPath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp`;
if (fs.existsSync(yanuPath)) {
    const yanu = members(yanuPath);
    const yProg = yanu.entries.find(x => x.name.toLowerCase().endsWith('.nca') && !x.name.toLowerCase().endsWith('.cnmt.nca'));
    const yRaw = yanu.d.subarray(yProg.offset, yProg.offset + yProg.size);
    const yHdr = decryptNcaHeader(yRaw.subarray(0, 0xC00), keys);
    const yDec = Buffer.from(xts.decrypt(yRaw.subarray(0, 0xC00), 0));
    const yRomfsIdx = yHdr.sections.findIndex(s => s.fsType === 3);
    console.log(`\nyanu program: ${yProg.name} size=${yProg.size} romfsIdx=${yRomfsIdx}`);
    if (yRomfsIdx >= 0) {
        const yFh = yDec.subarray(0x400 + yRomfsIdx * 0x200, 0x400 + yRomfsIdx * 0x200 + 0x200);
        dumpFsHeader('YANU RomFS FsHeader', yFh);
        parseIvfc('YANU', yFh, 0x08);
        const ys = yHdr.sections[yRomfsIdx];
        console.log(`yanu romfs sec: offset=0x${ys.offset.toString(16)} size=0x${ys.size.toString(16)} crypto=${ys.cryptoType}`);
        // dump section table
        for (let i = 0; i < 4; i++) {
            const s = yHdr.sections[i];
            if (s) console.log(`  yanu sec[${i}] fs=${s.fsType} crypto=${s.cryptoType} offset=0x${s.offset.toString(16)} size=0x${s.size.toString(16)}`);
        }
    }
}
