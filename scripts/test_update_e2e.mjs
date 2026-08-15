import fs from 'fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';
import { PFS0 } from '../fs/pfs0.js';
import { decryptNcaHeader, decryptNcaSection, parseCnmtFromDecryptedSection } from '../fs/nca.js';

class FileReader {
  constructor(path) {
    this.path = path;
    this.fd = fs.openSync(path, 'r');
    this.size = fs.statSync(path).size;
  }
  async read(offset, size) {
    const buf = Buffer.alloc(size);
    fs.readSync(this.fd, buf, 0, size, offset);
    return buf;
  }
  close() {
    fs.closeSync(this.fd);
  }
}

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp`;
const updatePath = `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsp`;
const yanuPath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp`;
const outputPath = '/tmp/update_e2e_out.nsp';

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const log = (level, msg) => console.log(`[${level.toUpperCase()}] ${msg}`);
const progress = () => {};

const baseReader = { name: 'Stardew Valley base.nsp', reader: new FileReader(basePath) };
const updateReader = { name: 'Stardew Valley update.nsp', reader: new FileReader(updatePath) };
const outputFd = fs.openSync(outputPath, 'w');

function pfs0Files(buf) {
  const pfs0 = new PFS0(buf);
  return pfs0.getFiles();
}

function fileSha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

console.log('=== E2E BKTR merge update test ===\n');

try {
  const result = await update([baseReader, updateReader], { fd: outputFd }, {
    keys,
    log,
    progress,
    bktrMerge: true,
  });
  fs.closeSync(outputFd);

  console.log(`\nOutput: ${outputPath}`);
  console.log(`Size: ${result.size} bytes (${(result.size / 1024 / 1024).toFixed(1)} MB), members: ${result.memberCount}`);

  const out = fs.readFileSync(outputPath);
  const outFiles = pfs0Files(out);

  if (fs.existsSync(yanuPath)) {
    console.log('\n=== Compare with yanu reference ===');
    const yanu = fs.readFileSync(yanuPath);
    const yanuFiles = pfs0Files(yanu);
    const byName = new Map(outFiles.map(f => [f.name, f]));
    for (const yf of yanuFiles) {
      const of = byName.get(yf.name);
      if (!of) { console.log(`  MISSING vs yanu: ${yf.name}`); continue; }
      if (of.size !== yf.size) { console.log(`  SIZE DIFF ${yf.name}: ours=${of.size} yanu=${yf.size}`); continue; }
      const same = out.subarray(of.offset, of.offset + of.size).equals(yanu.subarray(yf.offset, yf.offset + yf.size));
      console.log(`  ${same ? 'OK   ' : 'DIFF '} ${yf.name} (${of.size})`);
    }
  }

  const cnmtFile = outFiles.find(f => f.name.endsWith('.cnmt.nca'));
  if (cnmtFile) {
    const raw = out.subarray(cnmtFile.offset, cnmtFile.offset + cnmtFile.size);
    const header = decryptNcaHeader(raw.subarray(0, Math.min(cnmtFile.size, 0xC00)), keys);
    const section = header.sections[0];
    const fsData = await decryptNcaSection(raw.subarray(section.offset, section.offset + section.size), section);
    const cnmt = parseCnmtFromDecryptedSection(fsData, section);
    console.log('\n=== Output CNMT ===');
    console.log(`titleId: ${cnmt.titleId} v${cnmt.version} type ${cnmt.titleType}, ${cnmt.contentEntryCount} contents`);
    for (const e of cnmt.contentEntries) {
      console.log(`  type=${e.type} ncaId=${e.ncaId} size=${e.size}`);
    }
  }

  const programFile = outFiles.find(f => f.name.toLowerCase().endsWith('.nca') && !f.name.toLowerCase().endsWith('.cnmt.nca') && f.size > 100 * 1024 * 1024);
  if (programFile) {
    console.log('\n=== Merged Program NCA ===');
    console.log(`size: ${programFile.size}`);
    const raw = out.subarray(programFile.offset, programFile.offset + programFile.size);
    const h = decryptNcaHeader(raw.subarray(0, Math.min(programFile.size, 0xC00)), keys);
    if (h) {
      console.log(`titleId: ${h.titleId} rightsId: ${h.rightsId || '(none)'}`);
      for (const [i, s] of h.sections.entries()) {
        console.log(`  [${i}] offset=0x${s.offset.toString(16)} size=0x${s.size.toString(16)} (${(s.size / 1048576).toFixed(1)} MB) fsType=${s.fsType} cryptoType=${s.cryptoType}`);
      }
    } else {
      console.log('header decrypt FAILED (plaintext?)');
    }
  }
} catch (err) {
  console.error('Error:', err.message);
  console.error(err.stack);
  fs.closeSync(outputFd);
  try { fs.unlinkSync(outputPath); } catch {}
} finally {
  baseReader.reader.close();
  updateReader.reader.close();
}
