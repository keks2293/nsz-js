import fs from 'fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { decryptNcaHeader, decryptNcaSection, parseCnmtFromDecryptedSection } from '../fs/nca.js';

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

const outPath = '/tmp/update_nsz_out/Stardew Valley [0100E65002BB8000][v0] (0.87 GB)_updated.nsp';
const yanuPath = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp';

function pfs0Files(buf) {
  const pfs0 = new PFS0(buf);
  return pfs0.getFiles();
}

const out = fs.readFileSync(outPath);
const outFiles = pfs0Files(out);
console.log(`Ours: ${out.length} bytes, ${outFiles.length} members`);

const yanu = fs.readFileSync(yanuPath);
const yanuFiles = pfs0Files(yanu);
console.log(`Yanu: ${yanu.length} bytes, ${yanuFiles.length} members`);
const byName = new Map(outFiles.map(f => [f.name, f]));
console.log('\n=== member compare ===');
for (const yf of yanuFiles) {
  const of = byName.get(yf.name);
  if (!of) { console.log(`  MISSING vs yanu: ${yf.name}`); continue; }
  const same = of.size === yf.size && out.subarray(of.offset, of.offset + of.size).equals(yanu.subarray(yf.offset, yf.offset + yf.size));
  console.log(`  ${same ? 'OK   ' : 'DIFF '} ${yf.name} ours=${of.size} yanu=${yf.size}`);
}

const programFile = outFiles.find(f => f.name.toLowerCase().endsWith('.nca') && !f.name.toLowerCase().endsWith('.cnmt.nca') && f.size > 100 * 1024 * 1024);
if (programFile) {
  const raw = out.subarray(programFile.offset, programFile.offset + programFile.size);
  const h = decryptNcaHeader(raw.subarray(0, Math.min(programFile.size, 0xC00)), keys);
  console.log(`\n=== Merged Program NCA (${programFile.size} bytes) ===`);
  if (h) {
    console.log(`titleId: ${h.titleId} rightsId: ${h.rightsId || '(none)'}`);
    for (const [i, s] of h.sections.entries()) {
      console.log(`  [${i}] offset=0x${s.offset.toString(16)} size=0x${s.size.toString(16)} (${(s.size / 1048576).toFixed(1)} MB) fsType=${s.fsType} cryptoType=${s.cryptoType}`);
    }
    const bktr = h.sections.find(s => s.fsType === 3 && s.cryptoType === 4);
    if (bktr) console.log('  BKTR RomFS present: YES');
    else console.log('  BKTR RomFS present: NO');
  } else {
    console.log('header decrypt FAILED');
  }
}

const cnmtFile = outFiles.find(f => f.name.endsWith('.cnmt.nca'));
if (cnmtFile) {
  const raw = out.subarray(cnmtFile.offset, cnmtFile.offset + cnmtFile.size);
  const header = decryptNcaHeader(raw.subarray(0, Math.min(cnmtFile.size, 0xC00)), keys);
  const section = header.sections[0];
  const fsData = await decryptNcaSection(raw.subarray(section.offset, section.offset + section.size), section);
  const cnmt = parseCnmtFromDecryptedSection(fsData, section);
  console.log(`\n=== Output CNMT ===`);
  console.log(`titleId: ${cnmt.titleId} v${cnmt.version}, ${cnmt.contentEntryCount} contents`);
  for (const e of cnmt.contentEntries) {
    console.log(`  type=${e.type} ncaId=${e.ncaId} size=${e.size}`);
  }
}
