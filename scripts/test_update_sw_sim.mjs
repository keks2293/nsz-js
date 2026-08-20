// Simulates the browser SW download path (sequential-only stream + gap-fill) and
// verifies the result is byte-identical to the seekable fd output. The SW cannot
// seek, so SWDownloader fills gaps between writes with zeros; this writer mirrors
// that exact logic and collects the stream in order.
import fs from 'fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';

class FileReader {
  constructor(path) { this.path = path; this.fd = fs.openSync(path, 'r'); this.size = fs.statSync(path).size; }
  async read(offset, size) { const buf = Buffer.alloc(size); fs.readSync(this.fd, buf, 0, size, offset); return buf; }
  close() { fs.closeSync(this.fd); }
}

// Mirrors SWDownloader: sequential, fills gaps with zeros, tracks position.
class SequentialWriter {
  #pos = 0;
  chunks = [];
  // Mirrors SWDownloader.write exactly (adapter API: write(position, data)).
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
const basePath = process.env.BASE_PATH || `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp`;
const updatePath = process.env.UPDATE_PATH || `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsp`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const log = () => {};
const progress = () => {};

const baseReader = { name: 'base.nsp', reader: new FileReader(basePath) };
const updateReader = { name: 'update.nsp', reader: new FileReader(updatePath) };

// Reference: seekable fd output (known-good)
const refPath = '/tmp/update_sw_sim_ref.nsp';
const refFd = fs.openSync(refPath, 'w+');
await update([baseReader, updateReader], { fd: refFd }, { keys, log, progress, bktrMerge: true });
fs.closeSync(refFd);
baseReader.reader.close(); updateReader.reader.close();
const ref = new Uint8Array(fs.readFileSync(refPath));

// SW-simulated: sequential writer with gap-fill
const base2 = { name: 'base.nsp', reader: new FileReader(basePath) };
const update2 = { name: 'update.nsp', reader: new FileReader(updatePath) };
const sw = new SequentialWriter();
const result = await update([base2, update2], { writable: sw }, { keys, log, progress, bktrMerge: true });
base2.reader.close(); update2.reader.close();
const sim = sw.build();

const refSha = crypto.createHash('sha256').update(ref).digest('hex');
const simSha = crypto.createHash('sha256').update(sim).digest('hex');
console.log('ref (fd)       :', ref.length, 'sha256=' + refSha);
console.log('sim (sw-seq)   :', sim.length, 'sha256=' + simSha);
console.log('result.size    :', result.size);
if (refSha === simSha && ref.length === sim.length) {
  console.log('MATCH — SW sequential+gap-fill is byte-identical to fd');
} else {
  console.log('MISMATCH');
  let i = 0; const n = Math.min(ref.length, sim.length);
  while (i < n && ref[i] === sim[i]) i++;
  console.log('first diff at', i, '0x' + i.toString(16), 'len ref=' + ref.length + ' sim=' + sim.length);
}
