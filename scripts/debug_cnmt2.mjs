import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader, decryptNcaSection, parseCnmtFromDecryptedSection } from '../fs/nca.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesXts, AesCtr } from '../crypto/aes-ops.mjs';
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

const yanu = fs.readFileSync('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp');
const ours = fs.readFileSync('/tmp/Stardew Valley [0100E65002BB8000][v0] (0.87 GB)_updated.nsp');

const pYanu = new PFS0(yanu);
const pOurs = new PFS0(ours);
const fYanu = pYanu.getFiles();
const fOurs = pOurs.getFiles();

const cnmtYanu = fYanu.find(f => f.name.endsWith('.cnmt.nca'));
const cnmtOurs = fOurs.find(f => f.name.endsWith('.cnmt.nca'));

const yanuCnmt = yanu.subarray(cnmtYanu.offset, cnmtYanu.offset + cnmtYanu.size);
const oursCnmt = ours.subarray(cnmtOurs.offset, cnmtOurs.offset + cnmtOurs.size);

console.log('Yanu CNMT NCA size:', yanuCnmt.length, 'Ours:', oursCnmt.length);

console.log('\n=== HEADER BYTES 0x200-0x240 ===');
console.log('Yanu:', yanuCnmt.subarray(0x200, 0x240).map(b => b.toString(16).padStart(2,'0')).join(' '));
console.log('Ours: ', oursCnmt.subarray(0x200, 0x240).map(b => b.toString(16).padStart(2,'0')).join(' '));

// Section headers at 0x400
console.log('\n=== SECTION HEADERS ===');
console.log('Yanu [0x400]:', yanuCnmt.subarray(0x400, 0x410).map(b => b.toString(16).padStart(2,'0')).join(' '));
console.log('Ours [0x400]:', oursCnmt.subarray(0x400, 0x410).map(b => b.toString(16).padStart(2,'0')).join(' '));
console.log('Yanu [0x420]:', yanuCnmt.subarray(0x420, 0x430).map(b => b.toString(16).padStart(2,'0')).join(' '));
console.log('Ours [0x420]:', oursCnmt.subarray(0x420, 0x430).map(b => b.toString(16).padStart(2,'0')).join(' '));

// Parse headers
const yanuHeader = decryptNcaHeader(yanuCnmt, keys);
const oursHeader = decryptNcaHeader(oursCnmt, keys);

console.log('\nYanu header: titleId=' + yanuHeader.titleId + ' cryptoType=' + yanuHeader.cryptoType + ' sections=' + (yanuHeader.sections?.length || 0));
console.log('Ours header: titleId=' + oursHeader.titleId + ' cryptoType=' + oursHeader.cryptoType + ' sections=' + (oursHeader.sections?.length || 0));

if (!yanuHeader.sections?.[0] || !oursHeader.sections?.[0]) {
  console.log('NO SECTIONS');
  process.exit(0);
}

const yanuSec = yanuHeader.sections[0];
const oursSec = oursHeader.sections[0];

console.log('\nYanu sec[0]: offset=0x' + yanuSec.offset.toString(16) + ' size=0x' + yanuSec.size.toString(16) + ' cryptoType=' + yanuSec.cryptoType + ' sectionStart=0x' + yanuSec.sectionStart.toString(16));
console.log('Ours sec[0]: offset=0x' + oursSec.offset.toString(16) + ' size=0x' + oursSec.size.toString(16) + ' cryptoType=' + oursSec.cryptoType + ' sectionStart=0x' + oursSec.sectionStart.toString(16));

// Decrypt sections
const yanuSecRaw = yanuCnmt.subarray(yanuSec.offset, yanuSec.offset + yanuSec.size);
const oursSecRaw = oursCnmt.subarray(oursSec.offset, oursSec.offset + oursSec.size);

const yanuSecData = await decryptNcaSection(yanuSecRaw, yanuSec);
const oursSecData = await decryptNcaSection(oursSecRaw, oursSec);

console.log('\nYanu decrypted section: ' + yanuSecData.length + ' bytes');
console.log('Ours decrypted section: ' + oursSecData.length + ' bytes');

// Parse CNMT
const yanuCnmtParsed = parseCnmtFromDecryptedSection(yanuSecData, yanuSec);
const oursCnmtParsed = parseCnmtFromDecryptedSection(oursSecData, oursSec);

if (yanuCnmtParsed) {
  console.log('\nYanu CNMT: titleType=' + yanuCnmtParsed.titleType + ' version=' + yanuCnmtParsed.version + ' entries=' + yanuCnmtParsed.contentEntries.length);
  for (const e of yanuCnmtParsed.contentEntries) {
    console.log('  type=' + e.type + ' ncaId=' + e.ncaId);
  }
} else {
  console.log('\nYanu CNMT PARSE FAILED');
}

if (oursCnmtParsed) {
  console.log('\nOurs CNMT: titleType=' + oursCnmtParsed.titleType + ' version=' + oursCnmtParsed.version + ' entries=' + oursCnmtParsed.contentEntries.length);
  for (const e of oursCnmtParsed.contentEntries) {
    console.log('  type=' + e.type + ' ncaId=' + e.ncaId);
  }
} else {
  console.log('\nOurs CNMT PARSE FAILED');
}

// Check PFS0 at sectionStart
const yanuPs = yanuSec.sectionStart;
const oursPs = oursSec.sectionStart;
console.log('\n=== PFS0 AT sectionStart ===');
console.log('Yanu PFS0@0x' + yanuPs.toString(16) + ': ' + yanuSecData.subarray(yanuPs, yanuPs+4).map(b => String.fromCharCode(b)).join(''));
console.log('Ours PFS0@0x' + oursPs.toString(16) + ': ' + oursSecData.subarray(oursPs, oursPs+4).map(b => String.fromCharCode(b)).join(''));

// Compare CNMT binary
console.log('\n=== CNMT BINARY (first 64 bytes from offset 0x20) ===');
const yBin = yanuSecData.subarray(0x20, 0x60);
const oBin = oursSecData.subarray(0x20, 0x60);
console.log('Yanu:', yBin.map(b => b.toString(16).padStart(2,'0')).join(' '));
console.log('Ours: ', oBin.map(b => b.toString(16).padStart(2,'0')).join(' '));
