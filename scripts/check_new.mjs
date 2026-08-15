import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader, decryptNcaSection, parseCnmtFromDecryptedSection } from '../fs/nca.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesXts, AesCtr } from '../crypto/aes-ops.mjs';
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const ours = fs.readFileSync('/tmp/Stardew Valley [0100E65002BB8000][v0] (0.87 GB)_updated.nsp');
const pfs0 = new PFS0(ours);
const files = pfs0.getFiles();
const cnmtFile = files.find(f => f.name.endsWith('.cnmt.nca'));
console.log('CNMT NCA:', cnmtFile.name, cnmtFile.size);
const raw = ours.subarray(cnmtFile.offset, cnmtFile.offset + cnmtFile.size);
const header = decryptNcaHeader(raw, keys);
console.log('Header OK:', header ? 'YES' : 'NO');
if (header) {
  console.log('  titleId:', header.titleId);
  console.log('  cryptoType:', header.cryptoType);
  console.log('  sections:', header.sections.length);
  if (header.sections[0]) {
    const sec = header.sections[0];
    console.log('  sec[0]: offset=0x' + sec.offset.toString(16) + ' size=0x' + sec.size.toString(16) + ' cryptoType=' + sec.cryptoType + ' sectionStart=0x' + sec.sectionStart.toString(16));
    const secData = await decryptNcaSection(raw.subarray(sec.offset, sec.offset + sec.size), sec);
    console.log('  Decrypted section: ' + secData.length + ' bytes');
    const cnmt = parseCnmtFromDecryptedSection(secData, sec);
    if (cnmt) {
      console.log('  CNMT: titleType=' + cnmt.titleType + ' version=' + cnmt.version);
      for (const e of cnmt.contentEntries) {
        console.log('    type=' + e.type + ' ncaId=' + e.ncaId);
      }
    } else {
      console.log('  CNMT PARSE FAILED');
    }
  }
}
