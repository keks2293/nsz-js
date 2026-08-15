import { parseNczSections, AdapterNCZReader, NCZDecompressor } from '../fs/ncz.js';
import fs from 'fs';

const data = fs.readFileSync('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz');

const nczReader = new AdapterNCZReader({ read: async (off, sz) => data.subarray(off, off+sz) }, 0x1d0, 0x22039c18);
const parsed = await parseNczSections(nczReader);

console.log('Parsed sections:');
console.log('  Total:', parsed.sections.length);
console.log('  ncaSize:', parsed.ncaSize);
console.log('  headerEnd:', parsed.headerEnd);
console.log('  ncaHeader:', parsed.ncaHeader ? parsed.ncaHeader.length + ' bytes' : 'null');

for (let i = 0; i < Math.min(5, parsed.sections.length); i++) {
  const s = parsed.sections[i];
  console.log('  Section ' + i + ': offset=' + s.offset + ' size=' + s.size + ' cryptoType=' + s.cryptoType);
}

// Check what our decompressor actually outputs
const nczReader2 = new AdapterNCZReader({ read: async (off, sz) => data.subarray(off, off+sz) }, 0x1d0, 0x22039c18);
const decomp = new NCZDecompressor(nczReader2);
const output = await decomp.decompress();

console.log('\nDecompressed output:');
console.log('  Length:', output.length);
console.log('  First 16 bytes:', output.subarray(0, 16).toString('hex'));
console.log('  Bytes at 0x200:', output.subarray(0x200, 0x204).toString('hex'));
console.log('  Bytes at 0x4000:', output.subarray(0x4000, 0x4000+16).toString('hex'));
