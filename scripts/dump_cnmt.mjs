import fs from 'fs';
import { PFS0 } from '../fs/pfs0.js';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { AesCtr } from '../crypto/aes-ops.mjs';

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const ours = fs.readFileSync('/tmp/update_e2e_out.nsp');
const yanu = fs.readFileSync('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp');

for (const [label, buf] of [['Ours', ours], ['Yanu', yanu]]) {
  const files = new PFS0(buf).getFiles();
  const cf = files.find(f => f.name.endsWith('.cnmt.nca'));
  const raw = buf.subarray(cf.offset, cf.offset + cf.size);
  console.log(`\n=== ${label} CNMT ${cf.name} (${cf.size} B) ===`);
  const h = decryptNcaHeader(raw.subarray(0, 0xC00), keys);
  const dv = new DataView(raw.buffer, raw.byteOffset + cf.offset);
  console.log('hdr[0x440..0x44F]:', Array.from(raw.subarray(0x440, 0x450)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
  console.log('sec[0] offset=0x'+h.sections[0].offset.toString(16)+' size=0x'+h.sections[0].size.toString(16)+' sectionStart=0x'+h.sections[0].sectionStart.toString(16));
  console.log('enc sect FsHeader region 0xC00+0x400..0x460:', Array.from(raw.subarray(0x1000, 0x1060)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
  // decrypt section
  const sec = h.sections[0];
  const ctr = new AesCtr(h.titleKeyDec, sec.cryptoCounter);
  ctr.seek(sec.offset);
  const dec = await ctr.decrypt(raw.subarray(sec.offset, sec.offset + sec.size));
  console.log('dec sect[0x00..0x20]:', Array.from(dec.subarray(0,0x20)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
  console.log('dec sect[0x200..0x220]:', Array.from(dec.subarray(0x200,0x220)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
  console.log('dec sect[0x400..0x460]:', Array.from(dec.subarray(0x400,0x460)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
  console.log('dec sect[0x440..0x450]:', Array.from(dec.subarray(0x440,0x450)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
  console.log('PFS0 magic @ dec 0x200:', String.fromCharCode(dec[0x200],dec[0x201],dec[0x202],dec[0x203]));
  console.log('PFS0 magic @ dec 0x400:', String.fromCharCode(dec[0x400],dec[0x401],dec[0x402],dec[0x403]));
}
