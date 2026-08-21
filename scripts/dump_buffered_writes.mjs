// Run the buffered update path against an SW-like sequential writer and log
// every write (position, length, gap, backward?) to find out-of-order writes.
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';

class FileReader {
  constructor(path) { this.path = path; this.fd = fs.openSync(path, 'r'); this.size = fs.statSync(path).size; }
  async read(offset, size) { const buf = Buffer.alloc(size); fs.readSync(this.fd, buf, 0, size, offset); return buf; }
  close() { fs.closeSync(this.fd); }
}

class SequentialWriter {
  #pos = 0;
  writes = [];
  write(position, data) {
    const gap = position - this.#pos;
    this.writes.push({ position, len: data.byteLength, gap, backward: gap < 0 });
    if (gap > 0) { /* gap fill */ }
    this.#pos = position + data.byteLength;
  }
  get end() { return this.#pos; }
}

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = process.env.BASE_PATH || `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp`;
const updatePath = process.env.UPDATE_PATH || `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

const base = { name: 'base.nsp', reader: new FileReader(basePath) };
const upd = { name: 'update.nsz', reader: new FileReader(updatePath) };
const sw = new SequentialWriter();
const result = await update([base, upd], { writable: sw }, { keys, log: () => {}, progress: () => {}, bktrMerge: true, updateMode: 'buffered' });
base.reader.close(); upd.reader.close();

console.log(`result.size=${result.size} writer.end=${sw.end}`);
let i = 0;
for (const w of sw.writes) {
  i++;
  const end = w.position + w.len;
  console.log(`  #${i} pos=0x${w.position.toString(16)} len=0x${w.len.toString(16)} (${w.len}) end=0x${end.toString(16)} gap=${w.gap}${w.backward ? ' BACKWARD' : ''}`);
}
const nonZeroGap = sw.writes.filter(w => w.gap !== 0).length;
const backward = sw.writes.filter(w => w.backward).length;
console.log(`total writes=${sw.writes.length}, non-zero gap=${nonZeroGap}, backward=${backward}`);
if (sw.end !== result.size) {
  console.log('WRITER END != RESULT SIZE');
  process.exit(1);
}
