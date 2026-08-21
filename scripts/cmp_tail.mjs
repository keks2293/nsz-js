// Compare common region of two NSPs and analyze the tail of the bigger one.
// Usage: node scripts/cmp_tail.mjs <bigger.nsp> <smaller.nsp>
import fs from 'node:fs';

const [,, bigPath, smallPath] = process.argv;
const bigTotal = fs.statSync(bigPath).size;
const smallTotal = fs.statSync(smallPath).size;
console.log(`big=${bigTotal} small=${smallTotal} diff=${bigTotal - smallTotal}`);

const CHUNK = 64 * 1024 * 1024;
const bFd = fs.openSync(bigPath, 'r');
const sFd = fs.openSync(smallPath, 'r');

// 1. Compare common region (chunk-wise Buffer.compare for speed)
let firstDiff = -1;
let diffCount = 0;
for (let pos = 0; pos < smallTotal; pos += CHUNK) {
    const n = Math.min(CHUNK, smallTotal - pos);
    const a = Buffer.alloc(n), b = Buffer.alloc(n);
    fs.readSync(bFd, a, 0, n, pos);
    fs.readSync(sFd, b, 0, n, pos);
    if (a.equals(b)) continue;
    let lo = 0, hi = n;
    while (lo < hi) {
        const mid = (lo + hi) >> 1;
        if (a[mid] !== b[mid]) hi = mid; else lo = mid + 1;
    }
    if (firstDiff < 0) firstDiff = pos + lo;
    diffCount++;
    if (diffCount <= 5) console.log(`  first diff in chunk at 0x${(pos + lo).toString(16)}: big=0x${a[lo].toString(16)} small=0x${b[lo].toString(16)}`);
}
console.log(`common region [0,0x${smallTotal.toString(16)}): ${diffCount} chunks differ, first byte diff=0x${firstDiff >= 0 ? firstDiff.toString(16) : '-'}`);

// 2. Tail of big file
const tailOff = smallTotal;
const tailLen = bigTotal - smallTotal;
const tail = Buffer.alloc(tailLen);
fs.readSync(bFd, tail, 0, tailLen, tailOff);
let zeros = 0;
for (const x of tail) if (x === 0) zeros++;
console.log(`tail [0x${tailOff.toString(16)},0x${bigTotal.toString(16)}): ${tailLen} B, zeros=${zeros} (${(100 * zeros / tailLen).toFixed(1)}%)`);
console.log(`tail head: ${tail.subarray(0, 32).toString('hex')}`);
console.log(`tail tail: ${tail.subarray(-32).toString('hex')}`);

// 3. Find where a 64 B slice of the tail occurs elsewhere in the big file (data duplicate?)
const needle = tail.subarray(0, 64);
console.log(`searching 64 B tail-head needle in [0,0x${tailOff.toString(16)})...`);
let found = [];
for (let pos = 0; pos < tailOff - 64; pos += CHUNK) {
    const n = Math.min(CHUNK, tailOff - pos);
    const a = Buffer.alloc(n);
    fs.readSync(bFd, a, 0, n, pos);
    const idx = a.indexOf(needle);
    if (idx >= 0) found.push(pos + idx);
    if (found.length >= 5) break;
}
console.log(`needle found at: ${found.map(f => '0x' + f.toString(16)).join(', ') || 'not found'}`);

fs.closeSync(bFd); fs.closeSync(sFd);
