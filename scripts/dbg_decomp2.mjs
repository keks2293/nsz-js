import fs from 'fs';
import { NCZDecompressor, parseNczSections } from '../fs/ncz.js';

process.on('unhandledRejection', (r) => { console.log('UNHANDLED REJECTION:', r && r.message || r); });
process.on('uncaughtException', (e) => { console.log('UNCAUGHT EXCEPTION:', e); });

const NSZ = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz';
const data = fs.readFileSync(NSZ);
const fileCount = data.readUInt32LE(4);
const headerSize = 0x10 + fileCount * 0x18 + data.readUInt32LE(8);
const stringTable = data.subarray(0x10 + fileCount * 0x18, headerSize);
let target = null;
for (let i = 0; i < fileCount; i++) {
    const nameOff = data.readUInt32LE(0x10 + i * 0x18 + 16);
    let name = '';
    let j = nameOff;
    while (stringTable[j] !== 0) name += String.fromCharCode(stringTable[j++]);
    if (name.toLowerCase().includes('.ncz')) {
        target = { offset: Number(data.readBigUInt64LE(0x10 + i * 0x18)) + headerSize, size: Number(data.readBigUInt64LE(0x10 + i * 0x18 + 8)) };
        break;
    }
}
class NSZReader {
    get length() { return target.size; }
    async read(offset, size) { return data.subarray(target.offset + offset, target.offset + offset + size); }
}
const reader = new NSZReader();
const parsed = await parseNczSections(reader);
const decomp = new NCZDecompressor(reader);
let written = 0, calls = 0;
let t0 = Date.now();
console.log('calling decompress...');
const p = decomp.decompress(
    (p) => {},
    async (chunk, pos) => { written += chunk.length; calls++; },
    parsed);
const timer = setTimeout(() => { console.log('TIMEOUT after', Date.now()-t0, 'ms, written', written, 'calls', calls); process.exit(0); }, 15000);
try {
    const r = await p;
    clearTimeout(timer);
    console.log('RESOLVED in', Date.now()-t0, 'ms written', written, 'calls', calls, 'r=', r);
} catch (e) {
    clearTimeout(timer);
    console.log('THREW in', Date.now()-t0, 'ms:', e.message);
}
console.log('script end');
