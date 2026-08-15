import fs from 'fs';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { AesXts } from '../crypto/aes-ops.mjs';
import { mergeRomFS } from '../fs/bktr-merge.js';
import { AesEcb } from '../crypto/aes128.js';

function extractTitlekeyFromTik(tikData, keys) {
    const kekRaw = keys.titlekek_02 || keys.titlekek_source;
    const kek = typeof kekRaw === 'string' ? Buffer.from(kekRaw, 'hex') : Buffer.from(kekRaw);
    return new AesEcb(kek).decrypt(Buffer.from(tikData.subarray(0x180, 0x190)));
}

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

function readNsp(path) {
    const buf = fs.readFileSync(path);
    const files = new PFS0(buf).getFiles();
    return { buf, files };
}

const baseNsp = readNsp(`${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp`);
const updateNsp = readNsp(`${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsp`);
const yanuNsp = readNsp(`${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp`);

const baseNca = baseNsp.files.find(e => e.name.endsWith('.nca') && !e.name.endsWith('.cnmt.nca'));
const updateNca = updateNsp.files.find(e => e.name.endsWith('.nca') && !e.name.endsWith('.cnmt.nca'));
const yanuNca = yanuNsp.files.find(e => !e.name.endsWith('.cnmt.nca'));

const baseNcaData = baseNsp.buf.subarray(baseNca.offset, baseNca.offset + baseNca.size);
const updateNcaData = updateNsp.buf.subarray(updateNca.offset, updateNca.offset + updateNca.size);
const yanuNcaData = yanuNsp.buf.subarray(yanuNca.offset, yanuNca.offset + yanuNca.size);

const baseTik = baseNsp.files.find(t => t.name.endsWith('.tik'));
const updateTik = updateNsp.files.find(t => t.name.endsWith('.tik'));

const baseTitlekey = extractTitlekeyFromTik(baseNsp.buf.subarray(baseTik.offset, baseTik.offset + baseTik.size), keys);
const updateTitlekey = extractTitlekeyFromTik(updateNsp.buf.subarray(updateTik.offset, updateTik.offset + updateTik.size), keys);

console.log('baseTitlekey:', Buffer.from(baseTitlekey).toString('hex'));
console.log('updateTitlekey:', Buffer.from(updateTitlekey).toString('hex'));

const { merged, mergedData, relocEntries, subsectionEntries } = await mergeRomFS(baseNcaData, updateNcaData, {
    keys, baseTitlekey, updateTitlekey,
});

console.log(`merged size: 0x${merged.length.toString(16)} (${merged.length})`);
console.log(`mergedData (IVFC level-5 data only) size: 0x${mergedData.length.toString(16)} (${mergedData.length})`);
console.log(`reloc=${relocEntries} subsection=${subsectionEntries}`);
console.log(`merged[0:0x40]: ${Buffer.from(merged.subarray(0, 0x40)).toString('hex')}`);
console.log(`merged[0x1b8000:0x1b8000+0x40]: ${Buffer.from(merged.subarray(0x1b8000, 0x1b8000 + 0x40)).toString('hex')}`);
console.log(`mergedData[0:0x10]: ${Buffer.from(mergedData.subarray(0, 0x10)).toString('hex')} (romfs header_size=0x50 expected)`);
console.log(`mergedData == merged[0x134000:0x134000+len]: ${Buffer.from(mergedData).equals(Buffer.from(merged.subarray(0x134000, 0x134000 + mergedData.length)))}`);

// yanu media
const yHdr = Buffer.from(new AesXts(Buffer.from(keys.header_key, 'hex')).decrypt(yanuNcaData.subarray(0, 0xC00), 0));
const yMs = yHdr.readUInt32LE(0x250);
const yMe = yHdr.readUInt32LE(0x254);
const yMedia = yanuNcaData.subarray(yMs * 0x200, yMe * 0x200);
console.log(`\nyanu media: 0x${yMedia.length.toString(16)} (${yMedia.length})`);
console.log(`yanu media[0:0x40]: ${Buffer.from(yMedia.subarray(0, 0x40)).toString('hex')}`);
console.log(`yanu media[0x1b8000:0x1b8000+0x40]: ${Buffer.from(yMedia.subarray(0x1b8000, 0x1b8000 + 0x40)).toString('hex')}`);

// compare hash region 0..0x1b8000
const hashRegion = Math.min(0x1b8000, merged.length, yMedia.length);
const hSame = Buffer.from(merged.subarray(0, hashRegion)).equals(Buffer.from(yMedia.subarray(0, hashRegion)));
console.log(`\nhash region (0..0x${hashRegion.toString(16)}) identical: ${hSame}`);

// find first differing offset in the overlap
const overlap = Math.min(merged.length, yMedia.length);
let firstDiff = -1;
for (let i = 0; i < overlap; i++) {
    if (merged[i] !== yMedia[i]) { firstDiff = i; break; }
}
console.log(`first diff at: ${firstDiff < 0 ? 'none' : '0x' + firstDiff.toString(16)}`);

// dump update FsHeader[1]
const uHdr = Buffer.from(new AesXts(Buffer.from(keys.header_key, 'hex')).decrypt(updateNcaData.subarray(0, 0xC00), 0));
console.log(`\nUPDATE FsHeader[1] full:`);
const fsOff = 0x400 + 0x200;
for (let i = 0; i < 0x200; i += 0x10) {
    console.log(`  ${(fsOff + i).toString(16).padStart(3, '0')}: ${Buffer.from(uHdr.subarray(fsOff + i, fsOff + i + 0x10)).toString('hex')}`);
}

// dump base FsHeader[1] for comparison
const bHdr = Buffer.from(new AesXts(Buffer.from(keys.header_key, 'hex')).decrypt(baseNcaData.subarray(0, 0xC00), 0));
console.log(`\nBASE FsHeader[1] full:`);
for (let i = 0; i < 0x200; i += 0x10) {
    console.log(`  ${(fsOff + i).toString(16).padStart(3, '0')}: ${Buffer.from(bHdr.subarray(fsOff + i, fsOff + i + 0x10)).toString('hex')}`);
}
