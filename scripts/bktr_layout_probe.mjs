import fs from 'fs';
import { createHash } from 'crypto';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesCtr, AesXts } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const sh = b => createHash('sha256').update(b).digest();

async function getBaseDecryptedSection() {
    const pfs0 = fs.readFileSync(`${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp`);
    const entries = new PFS0(pfs0).getFiles();
    const tik = entries.find(t => t.name.toLowerCase().endsWith('.tik'));
    const tikData = pfs0.subarray(tik.offset, tik.offset + tik.size);
    const bKek = Buffer.from(keys.titlekek_02, 'hex');
    const bKey = new AesEcb(bKek).decrypt(Buffer.from(tikData.subarray(0x180, 0x190)));
    const prog = entries.find(e => e.name.toLowerCase().endsWith('.nca') && !e.name.toLowerCase().endsWith('.cnmt.nca'));
    const raw = pfs0.subarray(prog.offset, prog.offset + prog.size);
    const h = decryptNcaHeader(raw.subarray(0, 0xC00), keys);
    const xts = new AesXts(Buffer.isBuffer(keys.header_key) ? keys.header_key : Buffer.from(keys.header_key, 'hex'));
    const dec = Buffer.from(xts.decrypt(raw.subarray(0, 0xC00), 0));
    const s = h.sections[1];
    const nonceRaw = dec.subarray(0x400 + 0x200 + 0x140, 0x400 + 0x200 + 0x148);
    const nonce = Buffer.alloc(8);
    for (let j = 0; j < 8; j++) nonce[j] = nonceRaw[7 - j];
    const c = new AesCtr(bKey, nonce);
    c.seek(s.offset);
    return { raw, s, c, label: 'BASE' };
}

function getYanuMedia() {
    const pfs0 = fs.readFileSync(`${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp`);
    const entries = new PFS0(pfs0).getFiles();
    const prog = entries.find(e => !e.name.toLowerCase().endsWith('.cnmt.nca'));
    const raw = pfs0.subarray(prog.offset, prog.offset + prog.size);
    const xts = new AesXts(Buffer.isBuffer(keys.header_key) ? keys.header_key : Buffer.from(keys.header_key, 'hex'));
    const dec = Buffer.from(xts.decrypt(raw.subarray(0, 0xC00), 0));
    const ms = dec.readUInt32LE(0x250);
    const me = dec.readUInt32LE(0x254);
    return { media: raw.subarray(ms * 0x200, me * 0x200), secStart: ms * 0x200, label: 'YANU' };
}

async function verifyLevels(base) {
    const { raw, s, c, label } = base;
    // read hash regions in 16KB chunks
    async function readAt(off, len) {
        const out = Buffer.alloc(len);
        for (let o = 0; o < len; o += 0x4000) {
            const chunk = raw.subarray(s.offset + off + o, Math.min(s.offset + off + o + 0x4000, s.offset + s.size));
            const d = await c.decrypt(chunk);
            Buffer.from(d).copy(out, o, 0, chunk.length);
        }
        return out;
    }
    const lvl4 = await readAt(0x10000, 0x2000);
    const data0 = await readAt(0x1b8000, 0x4000);
    console.log(`${label}: level4[0] = ${lvl4.subarray(0, 0x20).toString('hex')}`);
    console.log(`${label}: sha256(data[0x1b8000..0x1bc000]) = ${sh(data0).toString('hex')}`);
    const match = lvl4.subarray(0, 0x20).equals(sh(data0));
    console.log(`${label}: data block 0 hash MATCHES level4[0]: ${match}`);
    // also try data at 0x1b8000+0xE0 (skip a possible IVFC header inside data)
    const dataE = await readAt(0x1b8000 + 0xE0, 0x4000 - 0xE0);
    const dataEFull = Buffer.concat([Buffer.alloc(0xE0), dataE]);
    console.log(`${label}: sha256(headerless-shift data block 0) matches: ${lvl4.subarray(0, 0x20).equals(sh(dataEFull))}`);
    return lvl4;
}

async function main() {
    const base = await getBaseDecryptedSection();
    await verifyLevels(base);

    const yanu = getYanuMedia();
    const media = yanu.media;
    console.log(`\n${yanu.label}: media len=0x${media.length.toString(16)}`);
    console.log(`sha256(yanu data[0x1b8000..0x1bc000]) = ${sh(media.subarray(0x1b8000, 0x1b8000 + 0x4000)).toString('hex')}`);
    console.log(`yanu level4[0] (0x10000) = ${Buffer.from(media.subarray(0x10000, 0x10020)).toString('hex')}`);
    console.log(`yanu data block0 match: ${Buffer.from(media.subarray(0x10000, 0x10020)).equals(sh(media.subarray(0x1b8000, 0x1b8000 + 0x4000)))}`);
    console.log(`yanu media[0x1b8000:0x1b8000+0x40] = ${Buffer.from(media.subarray(0x1b8000, 0x1b8000 + 0x40)).toString('hex')}`);
    // scan whole yanu media for IVFC
    const finds = [];
    for (let off = 0; off < media.length - 4; off += 0x10) {
        if (media[off] === 0x49 && media[off + 1] === 0x56 && media[off + 2] === 0x46 && media[off + 3] === 0x43) {
            finds.push('0x' + off.toString(16));
            if (finds.length >= 10) break;
        }
    }
    console.log(`yanu 'IVFC' in FULL media: ${finds.join(', ') || 'none'}`);
    // find first big non-zero run after 0x1b8000 (data start) - sample ranges
    let dataStart = -1;
    for (let off = 0x1b8000; off < media.length; off += 0x1000) {
        const block = media.subarray(off, off + 0x1000);
        if (block.some(b => b !== 0)) { dataStart = off; break; }
    }
    console.log(`yanu first non-zero block at/after 0x1b8000: 0x${dataStart.toString(16)}`);
    // find last non-zero position in media
    let lastNZ = -1;
    for (let off = media.length - 0x1000; off >= 0x1b8000; off -= 0x1000) {
        const block = media.subarray(off, off + 0x1000);
        if (block.some(b => b !== 0)) { lastNZ = off + 0x1000; break; }
    }
    console.log(`yanu data region approx end: 0x${lastNZ.toString(16)} (len=0x${(lastNZ - dataStart).toString(16)})`);
    const p = await verifyLevels(base);
    console.log(`\nbase level4[0] full = ${p.subarray(0, 0x20).toString('hex')}`);
}

main().catch(e => { console.error(e); process.exit(1); });
