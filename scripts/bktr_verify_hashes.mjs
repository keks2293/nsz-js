import fs from 'fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesXts } from '../crypto/aes-ops.mjs';
import { mergeRomFS } from '../fs/bktr-merge.js';
import { AesEcb } from '../crypto/aes128.js';

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const sh = b => crypto.createHash('sha256').update(b).digest();

function readNsp(path) {
    const buf = fs.readFileSync(path);
    return { buf, files: new PFS0(buf).getFiles() };
}
function tikKey(nsp, keys) {
    const tik = nsp.files.find(t => t.name.endsWith('.tik'));
    const kek = Buffer.from(keys.titlekek_02, 'hex');
    return new AesEcb(kek).decrypt(Buffer.from(nsp.buf.subarray(tik.offset, tik.offset + tik.size).subarray(0x180, 0x190)));
}

const baseNsp = readNsp(`${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp`);
const updateNsp = readNsp(`${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsp`);
const bNca = baseNsp.files.find(e => e.name.endsWith('.nca') && !e.name.endsWith('.cnmt.nca'));
const uNca = updateNsp.files.find(e => e.name.endsWith('.nca') && !e.name.endsWith('.cnmt.nca'));
const baseNcaData = baseNsp.buf.subarray(bNca.offset, bNca.offset + bNca.size);
const updateNcaData = updateNsp.buf.subarray(uNca.offset, uNca.offset + uNca.size);

const { merged } = await mergeRomFS(baseNcaData, updateNcaData, {
    keys,
    baseTitlekey: tikKey(baseNsp, keys),
    updateTitlekey: tikKey(updateNsp, keys),
});

const uHdr = Buffer.from(new AesXts(Buffer.from(keys.header_key, 'hex')).decrypt(updateNcaData.subarray(0, 0xC00), 0));
const fsH = uHdr.subarray(0x400 + 0x200);
const level = (i) => {
    const off = 0x18 + i * 0x18;
    return {
        lo: Number(fsH.readBigUInt64LE(off)),
        hds: Number(fsH.readBigUInt64LE(off + 8)),
        bs: fsH.readUInt32LE(off + 16),
    };
};
const levels = [level(0), level(1), level(2), level(3), level(4), level(5), level(6)];
console.log('update levels:');
for (const [i, l] of levels.entries()) console.log(`  l[${i}]: lo=0x${l.lo.toString(16)} hds=0x${l.hds.toString(16)} bs=0x${l.bs.toString(16)}`);

const DATA_OFF = levels[5].lo;
const DATA_SIZE = merged.length - DATA_OFF;
console.log(`\ndata region: 0x${DATA_OFF.toString(16)}..0x${merged.length.toString(16)} (0x${DATA_SIZE.toString(16)})`);
console.log(`data[0:0x60] = ${Buffer.from(merged.subarray(DATA_OFF, DATA_OFF + 0x60)).toString('hex')}`);

function verifyLevelAbove(belowLevel, belowSize, aboveLevel) {
    const nBelowBlocks = Math.ceil(belowSize / 0x4000);
    let ok = 0;
    const maxBlocks = Math.min(nBelowBlocks, 2000);
    for (let i = 0; i < maxBlocks; i++) {
        const start = belowLevel.lo + i * 0x4000;
        const len = Math.min(0x4000, merged.length - start);
        if (len <= 0) break;
        const hash = sh(merged.subarray(start, start + len));
        const stored = merged.subarray(aboveLevel.lo + i * 0x20, aboveLevel.lo + i * 0x20 + 0x20);
        if (hash.equals(stored)) ok++;
    }
    console.log(`  level@0x${aboveLevel.lo.toString(16)} hashes level@0x${belowLevel.lo.toString(16)}: ${ok}/${maxBlocks} match`);
}

// Verify full chain: data <- l4 <- l3 <- l2 <- l1 <- l0
verifyLevelAbove(levels[5], DATA_SIZE, levels[4]);
verifyLevelAbove(levels[4], levels[4].hds, levels[3]);
verifyLevelAbove(levels[3], levels[3].hds, levels[2]);
verifyLevelAbove(levels[2], levels[2].hds, levels[1]);
verifyLevelAbove(levels[1], levels[1].hds, levels[0]);

const masterHash = sh(merged.subarray(0, 0x4000));
const storedMaster = Buffer.from(fsH.subarray(0xC8, 0xE8));
console.log(`\nmaster hash vs FsHeader@0xC8: ${masterHash.equals(storedMaster) ? 'MATCH' : 'MISMATCH'}`);
console.log(`master hash = ${masterHash.toString('hex')}`);
