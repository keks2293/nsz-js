import fs from 'fs';
import { parseNczSections } from '../fs/ncz.js';
import { decompressStream } from '../crypto/zstd.js';
import { AesCtr, aesBackend } from '../crypto/aes-ops.mjs';

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
const { sections, ncaSize, headerEnd } = parsed;

const sortedSections = [...sections].sort((a, b) => a.offset - b.offset);
const sectionAesCtrs = new Map();
for (const s of sortedSections) {
    if (s.cryptoType === 3 || s.cryptoType === 4) {
        sectionAesCtrs.set(s, new AesCtr(s.cryptoKey, s.cryptoCounter, 0, aesBackend()));
    }
}
const READ_CHUNK_SIZE = 0x1000000;
let pos = headerEnd;
let toRead = reader.length - headerEnd;
let sectionIdx = 0;
let lastAesCtr = null;
let lastDecryptEnd = -1;
let chunkCount = 0;
let decompOffset = 0x4000;
let written = 0;
let progressCount = 0;
let t0 = Date.now();
for await (const chunk of decompressStream(async () => {
    if (toRead <= 0) return null;
    const size = Math.min(toRead, READ_CHUNK_SIZE);
    const c = await reader.read(pos, size);
    pos += c.length;
    toRead -= c.length;
    return c;
})) {
    chunkCount++;
    let offset = 0;
    while (offset < chunk.length) {
        const ncaPos = decompOffset + offset;
        while (sectionIdx < sortedSections.length - 1 &&
               ncaPos >= sortedSections[sectionIdx].offset + sortedSections[sectionIdx].size) {
            sectionIdx++;
        }
        let aesCtr = null;
        let boundary = chunk.length;
        if (sectionIdx < sortedSections.length) {
            const s = sortedSections[sectionIdx];
            aesCtr = sectionAesCtrs.get(s) || null;
            boundary = Math.min(chunk.length, offset + (s.offset + s.size - ncaPos));
        }
        const subSize = boundary - offset;
        let d = chunk.subarray(offset, offset + subSize);
        if (aesCtr) {
            if (aesCtr !== lastAesCtr || ncaPos !== lastDecryptEnd) aesCtr.seek(ncaPos);
            d = await aesCtr.decrypt(d);
            lastDecryptEnd = ncaPos + d.length;
            lastAesCtr = aesCtr;
        }
        await (async (chunk2, p) => { written += chunk2.length; })(d, ncaPos);
        offset += subSize;
        progressCount++;
    }
    decompOffset += chunk.length;
}
console.log('done in', Date.now()-t0, 'ms, chunks', chunkCount, 'written', written, 'progressCount', progressCount);
