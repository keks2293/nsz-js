// Simulates the browser File System Access API writable (seek + positioned
// write, NO read — MDN: FileSystemWritableFileStream only has
// write/seek/truncate) and runs the full two-pass BKTR update on the real
// Stardew NSZ files. Verifies the output is byte-identical to the verified
// reference (which has the same 272-byte PFS0 header layout).
//
// This covers the seekable-no-read two-pass branch: NCA written first,
// real PFS0 header overwrites offset 0 at the end (no placeholder).
//
// Run: node scripts/test_twopass_fsa_sim.mjs
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';

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
  close() { fs.closeSync(this.fd); }
}

// Faithful FSA simulation: positioned writes, may be called in ANY order
// (including backward), no read(). Gaps are implicitly zeros. Tracks
// backward writes (legal here) for reporting.
class FsaSim {
  constructor(outPath) {
    this.outPath = outPath;
    this.data = null;
    this.pos = 0;
    this.backward = [];
  }
  async seek(pos) { this.pos = pos; }
  async write(entry) {
    const pos = entry.position;
    const view = entry.data;
    if (pos < this.pos) this.backward.push({ at: pos, len: view.byteLength, delta: pos - this.pos });
    const end = pos + view.byteLength;
    if (!this.data || this.data.byteLength < end) {
      const nd = new Uint8Array(Math.max(this.data ? this.data.byteLength : 0, end));
      if (this.data) nd.set(this.data);
      this.data = nd;
    }
    this.data.set(view, pos);
    this.pos = end;
  }
  close() {
    fs.writeFileSync(this.outPath, this.data);
  }
}

function compareFiles(a, b) {
  const sizeA = fs.statSync(a).size;
  const sizeB = fs.statSync(b).size;
  if (sizeA !== sizeB) return { same: false, firstDiff: -1, sizeA, sizeB };
  const fdA = fs.openSync(a, 'r');
  const fdB = fs.openSync(b, 'r');
  const CHUNK = 16 * 1024 * 1024;
  let off = 0;
  let firstDiff = -1;
  while (off < sizeA && firstDiff === -1) {
    const n = Math.min(CHUNK, sizeA - off);
    const ba = Buffer.alloc(n);
    const bb = Buffer.alloc(n);
    fs.readSync(fdA, ba, 0, n, off);
    fs.readSync(fdB, bb, 0, n, off);
    if (!ba.equals(bb)) {
      for (let i = 0; i < n; i++) if (ba[i] !== bb[i]) { firstDiff = off + i; break; }
    }
    off += n;
  }
  fs.closeSync(fdA);
  fs.closeSync(fdB);
  return { same: firstDiff === -1 && sizeA === sizeB, firstDiff, sizeA, sizeB };
}

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = process.env.BASE_PATH || `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsz`;
const updatePath = process.env.UPDATE_PATH || `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz`;
// Reference = our verified output (272-byte PFS0 header) — same format as the
// FSA output, so the comparison is a plain byte-for-byte match.
const refPath = process.env.REF_PATH || `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB)_updated.nsp`;

const keys = KeysParser.parse(fs.readFileSync('static/prod.keys', 'utf8'));
const log = (level, msg) => { if (!process.env.QUIET) console.log(`[${level.toUpperCase()}] ${msg}`); };
const progress = () => {};

const outPath = '/tmp/twopass_fsa_sim.nsp';
const fsa = new FsaSim(outPath);
const readers = [
  { name: 'base.nsz', reader: new FileReader(basePath) },
  { name: 'update.nsz', reader: new FileReader(updatePath) },
];
const result = await update(readers, { writable: fsa }, { keys, log, progress });
fsa.close();
for (const r of readers) r.reader.close();

const size = fs.statSync(outPath).size;
const refSize = fs.statSync(refPath).size;
console.log(`\n=== RESULT (FSA sim) ===`);
console.log(`size: ${size}  ref: ${refSize}  result.size: ${result.size}`);
console.log(`backward writes (legal on FSA): ${fsa.backward.length}`);
for (const b of fsa.backward.slice(0, 5)) console.log(`  backward at pos=0x${b.at.toString(16)} len=${b.len}`);

let ok = true;
if (size !== refSize) { console.log(`FAIL: size ${size} != ref ${refSize}`); ok = false; }
if (result.size !== size) { console.log(`FAIL: result.size ${result.size} != file ${size}`); ok = false; }

const cmp = compareFiles(outPath, refPath);
if (cmp.same) {
  console.log(`content: byte-identical to reference (${cmp.sizeA} B)`);
} else {
  console.log(`FAIL: content diff at 0x${cmp.firstDiff.toString(16)} (sizes ${cmp.sizeA}/${cmp.sizeB})`);
  ok = false;
}
console.log(ok ? '\nPASS: all checks' : '\nFAIL');
process.exit(ok ? 0 : 1);
