// Inspect CNMT NCA section cryptoType/counter and verify titleKeyDec decrypts
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { NCZDecompressor, AdapterNCZReader, parseNczSections } from '../fs/ncz.js';
import { AesCtr } from '../crypto/aes-ops.mjs';

const NSZ = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz';
const keysText = fs.readFileSync('../static/prod.keys', 'utf8');
const keys = KeysParser.parse(keysText);
const data = fs.readFileSync(NSZ);

const fileCount = data.readUInt32LE(4);
const headerSize = 0x10 + fileCount * 0x18 + data.readUInt32LE(8);
const stringTable = data.subarray(0x10 + fileCount * 0x18, headerSize);
for (let i = 0; i < fileCount; i++) {
    const nameOff = data.readUInt32LE(0x10 + i * 0x18 + 16);
    let name = '';
    let j = nameOff;
    while (stringTable[j] !== 0) name += String.fromCharCode(stringTable[j++]);
    if (!name.toLowerCase().includes('.nca')) continue;
    const offset = Number(data.readBigUInt64LE(0x10 + i * 0x18)) + headerSize;
    const size = Number(data.readBigUInt64LE(0x10 + i * 0x18 + 8));
    console.log('member:', name, size);
    if (!name.toLowerCase().endsWith('.cnmt.nca')) continue;
    const raw = data.subarray(offset, offset + size);
    const header = decryptNcaHeader(raw.subarray(0, Math.min(size, 0xC00)), keys);
    console.log('  content type', header.contentType, 'rightsId', header.rightsId, 'mk', header.masterKey);
    for (const s of header.sections) {
        console.log('  section offset 0x' + s.offset.toString(16), 'size 0x' + s.size.toString(16),
            'fsType', s.fsType, 'cryptoType', s.cryptoType,
            'counter', Buffer.from(s.cryptoCounter).toString('hex'), 'sectionStart', s.sectionStart);
    }
    const sec = header.sections[0];
    const d = raw.subarray(sec.offset, sec.offset + sec.size);
    const aes = new AesCtr(sec.cryptoKey, sec.cryptoCounter);
    aes.seek(sec.offset);
    const dec = await aes.decrypt(d);
    console.log('  decrypted section0 starts with:', JSON.stringify(String.fromCharCode(dec[0], dec[1], dec[2], dec[3])));
    break;
}
