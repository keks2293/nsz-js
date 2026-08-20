// Simulates the browser SW download adapter (sequential append + zero gap-fill)
// and runs the full two-pass BKTR update on the real Stardew NSZ files.
// Verifies the output is byte-identical to the yanu reference.
//
// Run: node scripts/test_twopass_sw_sim.mjs
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

// Faithful SWDownloader.write simulation: data is APPENDED to a sequential
// stream; gaps (position > #pos) are filled with zeros; #pos = position + len.
// Backward writes (position < #pos) append at the current stream position while
// #pos is set backwards — corrupting everything after, exactly like the real SW.
//
// detach=true simulates the OLD SWDownloader, which transferred (detached) the
// caller's full-buffer views via postMessage — zeroing .length on the caller's
// reference after the write. The fixed SW always posts a copy (detach=false),
// but the two-pass loop also captures lengths before writing, so the pipeline
// must survive BOTH modes.
class SwSim {
  constructor(outPath, { detach = false } = {}) {
    this.outPath = outPath;
    this.detach = detach;
    this.fd = fs.openSync(outPath, 'w');
    this.pos = 0;
    this.streamLen = 0;
    this.gapFills = [];
    this.backward = [];
  }
  async write(position, data) {
    const view = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    const gap = position - this.pos;
    if (gap > 0) {
      if (gap >= 0x1000) this.gapFills.push({ at: position, size: gap, streamPos: this.pos });
      fs.writeSync(this.fd, Buffer.alloc(gap), 0, gap, this.streamLen);
      this.streamLen += gap;
    } else if (gap < 0) {
      this.backward.push({ at: position, len: view.byteLength, streamPos: this.streamLen, delta: gap });
    }
    const len = view.byteLength;
    if (this.detach && view.byteLength === view.buffer.byteLength) {
      // old SW: postMessage transferred the ORIGINAL buffer → bytes arrive at
      // the stream, caller's buffer is detached (length becomes 0).
      fs.writeSync(this.fd, view, 0, len, this.streamLen);
      view.buffer.transfer(0);
    } else {
      // fixed SW: always post a copy — caller's buffer survives.
      const chunk = view.slice(0);
      fs.writeSync(this.fd, chunk, 0, len, this.streamLen);
    }
    this.streamLen += len;
    this.pos = position + len;
  }
  close() { fs.closeSync(this.fd); }
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
// Reference = our earlier verified blob output (288-byte PFS0 header, pre 0x10-padding fix).
// The new output has a 272-byte header (0x10-aligned, matches yanu/Nintendo), so the
// content after the header must equal the old output shifted by 16 bytes.
const refPath = process.env.REF_PATH || `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB)_updated.nsp`;
const refHeaderSize = process.env.REF_HDR ? Number(process.env.REF_HDR) : 288;
const yanuPath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp`;

const keys = KeysParser.parse(fs.readFileSync('static/prod.keys', 'utf8'));
const log = (level, msg) => { if (!process.env.QUIET) console.log(`[${level.toUpperCase()}] ${msg}`); };
const progress = () => {};

async function runSwSim(runOutPath, detach) {
  const sw = new SwSim(runOutPath, { detach });
  const readers = [
    { name: 'base.nsz', reader: new FileReader(basePath) },
    { name: 'update.nsz', reader: new FileReader(updatePath) },
  ];
  const result = await update(readers, { writable: sw }, { keys, log, progress });
  sw.close();
  for (const r of readers) r.reader.close();
  return { sw, result };
}

// Run 1 (detach=true): the STRICT case — mimics the OLD SWDownloader whose
// postMessage transfer detached the caller's buffers (zeroing .length after
// the write). Passes only if the pipeline never touches a buffer post-write.
// Run 2 (detach=false): the FIXED SWDownloader behavior (always posts a copy).
const runs = [];
for (const detach of [true, false]) {
  console.log(`\n===== SwSim run: detach=${detach} =====`);
  const p = `/tmp/twopass_sw_sim_${detach ? 'detach' : 'copy'}.nsp`;
  runs.push({ detach, path: p, ...await runSwSim(p, detach) });
}

function compareShifted(outPath, refPath, outHdr, refHdr) {
  // Compare out[outHdr..] with ref[refHdr..] — content after the PFS0 header.
  const sizeA = fs.statSync(outPath).size - outHdr;
  const sizeB = fs.statSync(refPath).size - refHdr;
  if (sizeA !== sizeB) return { same: false, firstDiff: -1, sizeA, sizeB };
  const fdA = fs.openSync(outPath, 'r');
  const fdB = fs.openSync(refPath, 'r');
  const CHUNK = 16 * 1024 * 1024;
  let off = 0;
  let firstDiff = -1;
  while (off < sizeA && firstDiff === -1) {
    const n = Math.min(CHUNK, sizeA - off);
    const ba = Buffer.alloc(n);
    const bb = Buffer.alloc(n);
    fs.readSync(fdA, ba, 0, n, off + outHdr);
    fs.readSync(fdB, bb, 0, n, off + refHdr);
    if (!ba.equals(bb)) {
      for (let i = 0; i < n; i++) if (ba[i] !== bb[i]) { firstDiff = off + i; break; }
    }
    off += n;
  }
  fs.closeSync(fdA);
  fs.closeSync(fdB);
  return { same: firstDiff === -1, firstDiff, sizeA, sizeB };
}

// New output must have a 0x10-aligned (272-byte) PFS0 header and yanu's total size.
function hdrSizeOf(path) {
  const fd = fs.openSync(path, 'r');
  const head = Buffer.alloc(16);
  fs.readSync(fd, head, 0, 16, 0);
  fs.closeSync(fd);
  return 0x10 + head.readUInt32LE(4) * 0x18 + head.readUInt32LE(8);
}

const yanuSize = fs.statSync(yanuPath).size;
let ok = true;
for (const run of runs) {
  console.log(`\n=== RESULT (detach=${run.detach}) ===`);
  const hdr = hdrSizeOf(run.path);
  const size = fs.statSync(run.path).size;
  console.log(`header: ${hdr} (0x${hdr.toString(16)})  [expect 272 (0x110)]`);
  console.log(`size: ${size}  yanu: ${yanuSize}`);
  console.log(`SW sim: gapFills(>=0x1000)=${run.sw.gapFills.length}  backward=${run.sw.backward.length}`);
  for (const g of run.sw.gapFills) console.log(`  gap at pos=0x${g.at.toString(16)} size=${g.size} (streamPos=0x${g.streamPos.toString(16)})`);
  for (const b of run.sw.backward.slice(0, 10)) console.log(`  backward at pos=0x${b.at.toString(16)} len=${b.len} delta=${b.delta}`);

  if (hdr !== 272) { console.log(`FAIL: PFS0 header is ${hdr}, expected 272`); ok = false; }
  if (size !== yanuSize) { console.log(`FAIL: total size ${size} != yanu ${yanuSize}`); ok = false; }
  if (run.sw.gapFills.length || run.sw.backward.length) { console.log(`FAIL: SW sim detected non-sequential writes`); ok = false; }

  const cmp = compareShifted(run.path, refPath, hdr, refHeaderSize);
  if (cmp.same) {
    console.log(`content after header: byte-identical to verified blob output (shifted by ${refHeaderSize - hdr} B)`);
  } else {
    console.log(`FAIL: content diff at offset 0x${cmp.firstDiff === -1 ? 'size-mismatch' : cmp.firstDiff.toString(16)} (post-header relative)`);
    ok = false;
  }
}

// Both runs must be byte-identical to each other.
if (runs[0].path !== runs[1].path) {
  const both = compareShifted(runs[0].path, runs[1].path, 0, 0);
  if (both.same) console.log('\ndetach run ≡ copy run: byte-identical');
  else { console.log(`\nFAIL: detach vs copy run differ at 0x${both.firstDiff === -1 ? 'size' : both.firstDiff.toString(16)}`); ok = false; }
}

if (ok) console.log('\nPASS: all checks');
else process.exit(1);
