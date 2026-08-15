import fs from 'fs';
import { decompressStream } from '../crypto/zstd.js';
import { zstdDecompressSync } from 'node:zlib';

const path = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz';
const fd = fs.openSync(path, 'r');
const read = (o, s) => { const b = Buffer.alloc(s); fs.readSync(fd, b, 0, s, o); return b; };
const abs = 464, headerEnd = 56912;

// 1) find first frame boundary via sync
let lo = 0x100000, hi = 0x4000000;
const compAt = (n) => read(abs + headerEnd, n);
for (let i = 0; i < 8; i++) {
  const mid = Math.floor((lo + hi) / 2);
  try { zstdDecompressSync(compAt(mid)); hi = mid; } catch { lo = mid; }
}
console.log('first frame compressed size ~=', hi, 'decompresses OK?');
try { console.log('  out bytes:', zstdDecompressSync(compAt(hi)).length); } catch (e) { console.log('  err at hi:', e.message); }

// 2) stream feed FIRST 3MB only, bounded
let pos = headerEnd, fed = 0;
const LIMIT = 0x300000;
let outTotal = 0, n = 0;
console.log('\nfeeding first', LIMIT, 'compressed bytes...');
for await (const c of decompressStream(async () => {
  if (fed >= LIMIT) return null;
  const s = Math.min(0x10000, LIMIT - fed);
  const b = read(abs + pos, s); pos += s; fed += s;
  return b;
})) {
  n++; outTotal += c.byteLength;
  if (n <= 5 || n % 50 === 0) console.log('  out', n, 'len', c.byteLength, 'total', outTotal);
}
console.log('done. chunks', n, 'outTotal', outTotal);
fs.closeSync(fd);
