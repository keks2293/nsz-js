#!/usr/bin/env node
// Progress protocol test for the update pipeline (real Stardew base + update NSZ):
// each path reports per-phase fractions (p in [0,1], stable phase label, phase byte
// total), monotonic within a phase, each phase ends at exactly 1.0 — so the bar can
// never regress across phases. Write phases are continuous (program + tail form one
// bar: two-pass = 'Computing contentId (1/2)' + 'Writing output (2/2)',
// streaming = 'Writing output (1/1)'). Also re-verifies streaming ≡ two-pass
// byte-identity. In-memory outputs only (no disk writes).
import fs from 'fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { update } from '../fs/update.js';

class FileReader {
  constructor(path) { this.path = path; this.fd = fs.openSync(path, 'r'); this.size = fs.statSync(path).size; }
  async read(offset, size) { const buf = Buffer.alloc(size); fs.readSync(this.fd, buf, 0, size, offset); return buf; }
  close() { fs.closeSync(this.fd); }
}

// Sequential writer with gap-fill, mirrors SWDownloader (adapter API: write(position, data)).
class SequentialWriter {
  #pos = 0;
  chunks = [];
  write(position, data) {
    const gap = position - this.#pos;
    if (gap > 0) this.chunks.push(new Uint8Array(gap));
    this.chunks.push(new Uint8Array(data));
    this.#pos = position + data.byteLength;
  }
  build() {
    const buf = new Uint8Array(this.#pos);
    let off = 0;
    for (const c of this.chunks) { buf.set(c, off); off += c.byteLength; }
    return buf;
  }
}

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = process.env.BASE_PATH || `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsz`;
const updatePath = process.env.UPDATE_PATH || `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const log = () => {};

let failures = 0;
function assert(cond, msg) {
  if (cond) console.log(`  ok - ${msg}`);
  else { failures++; console.log(`  FAIL - ${msg}`); }
}

function checkProtocol(name, events, expectedLabels, buf) {
  console.log(`\n== ${name} (${events.length} progress events) ==`);
  const segments = [];
  for (const e of events) {
    const last = segments[segments.length - 1];
    if (last && last.label === e.label) last.events.push(e);
    else segments.push({ label: e.label, events: [e] });
  }
  const labels = segments.map(s => s.label);
  assert(labels.join(' | ') === expectedLabels.join(' | '), `phase order: ${labels.join(' -> ')}`);

  // Tail phase byte total must equal the sum of the non-Program, non-CNMT output members.
  const files = new PFS0(buf).getFiles();
  const cnmt = files.find(f => f.name.endsWith('.cnmt.nca'));
  const program = files.find(f => f.name.toLowerCase().endsWith('.nca') && f !== cnmt);
  const tailExpected = files.filter(f => f !== cnmt && f !== program).reduce((s, f) => s + f.size, 0);

  for (const s of segments) {
    const evs = s.events;
    assert(evs.length > 0, `${s.label}: events reported`);
    assert(evs.every(e => e.p >= 0 && e.p <= 1 + 1e-9), `${s.label}: p within [0,1]`);
    assert(evs.every((e, i) => i === 0 || evs[i - 1].p <= e.p + 1e-12), `${s.label}: monotonic within phase (program→tail continuity)`);
    assert(evs[evs.length - 1].p === 1, `${s.label}: phase ends at exactly 1.0 (got ${evs[evs.length - 1].p})`);
    assert(evs.every(e => typeof e.phaseBytes === 'number' && e.phaseBytes > 0), `${s.label}: phaseBytes reported`);
    assert(new Set(evs.map(e => e.phaseBytes)).size === 1, `${s.label}: phaseBytes constant within phase`);
    const bytes = evs[0].phaseBytes;
    if (s.label === 'Writing output (2/2)') {
      assert(bytes === program.size + tailExpected, `${s.label}: phaseBytes (${bytes}) == Program NCA (${program.size}) + tail (${tailExpected})`);
    } else if (s.label === 'Writing output (1/1)') {
      // streaming phase = exefs + romfs writes + full-NCA re-read + tail
      assert(bytes > program.size + tailExpected, `${s.label}: phaseBytes (${bytes}) > Program NCA + tail (${program.size + tailExpected}) (re-read included)`);
    }
  }
  // The read-only pass-1 phase (two-pass only) does more work than the write phase.
  const p1 = segments.find(s => s.label.startsWith('Computing contentId'));
  const p2 = segments.find(s => s.label.startsWith('Writing output'));
  if (p1 && p2) {
    assert(p1.events[0].phaseBytes > p2.events[0].phaseBytes,
      `pass-1 phaseBytes (${p1.events[0].phaseBytes}) > write phase (${p2.events[0].phaseBytes})`);
  }
}

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

// Run 1: streaming (memory output has read-back → seekback path, 2 phases)
{
  const events = [];
  const base = { name: 'base.nsp', reader: new FileReader(basePath) };
  const upd = { name: 'update.nsp', reader: new FileReader(updatePath) };
  const res = await update([base, upd], { memory: true }, {
    keys, log, bktrMerge: true,
    progress: (p, label, phaseBytes) => events.push({ p, label, phaseBytes }),
  });
  base.reader.close(); upd.reader.close();
  const buf = new Uint8Array(await res.blob.arrayBuffer());
  checkProtocol('streaming (memory, seekback)', events, ['Writing output (1/1)'], buf);
  globalThis.__refSha = sha(buf);
  globalThis.__refLen = buf.length;
}

// Run 2: two-pass (sequential writer, no read-back → appendOnly, 3 phases)
{
  const events = [];
  const base = { name: 'base.nsp', reader: new FileReader(basePath) };
  const upd = { name: 'update.nsp', reader: new FileReader(updatePath) };
  const sw = new SequentialWriter();
  await update([base, upd], { writable: sw }, {
    keys, log, bktrMerge: true,
    progress: (p, label, phaseBytes) => events.push({ p, label, phaseBytes }),
  });
  base.reader.close(); upd.reader.close();
  const buf = sw.build();
  checkProtocol('two-pass (sw-sim, appendOnly)', events, ['Computing contentId (1/2)', 'Writing output (2/2)'], buf);

  console.log(`\nstreaming sha256=${globalThis.__refSha} (${globalThis.__refLen})`);
  console.log(`two-pass  sha256=${sha(buf)} (${buf.length})`);
  assert(globalThis.__refSha === sha(buf) && globalThis.__refLen === buf.length, 'streaming ≡ two-pass byte-identical');
}

console.log(failures === 0 ? '\nALL PASSED' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
