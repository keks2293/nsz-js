import fs from 'fs';
import { PFS0 } from '../fs/pfs0.js';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { AesXts } from '../crypto/aes-ops.mjs';

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const base = fs.readFileSync('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp');
const files = new PFS0(base).getFiles();
const cf = files.find(f => f.name.endsWith('.cnmt.nca'));
console.log('base cnmt file:', cf.name, cf.size);
const raw = base.subarray(cf.offset, cf.offset + cf.size);
console.log('base CNMT hdr[0x440..0x450]:', Array.from(raw.subarray(0x440, 0x450)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
const h = decryptNcaHeader(raw.subarray(0, 0xC00), keys);
if (h && h.sections[0]) {
  const s = h.sections[0];
  console.log('base CNMT sec[0] offset=0x'+s.offset.toString(16)+' size=0x'+s.size.toString(16)+' cryptoType='+s.cryptoType+' sectionStart=0x'+s.sectionStart.toString(16)+' sectionSize=0x'+s.sectionSize.toString(16));
}
// the header is XTS-decrypted? check cryptoType
console.log('raw hdr[0x206]:', raw[0x206]);
// decrypt header and check 0x440
const hk = typeof keys.header_key === 'string' ? keys.header_key : keys.header_key;
const hdrKey = Buffer.from(hk, 'hex');
const xts = new AesXts(hdrKey);
const dec = xts.decrypt(raw.subarray(0, 0xC00), 0);
console.log('dec base CNMT hdr[0x440..0x450]:', Array.from(dec.subarray(0x440, 0x450)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
