import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesCtr, AesXts } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp`;
const updatePath = `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsp`;
const yanuPath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

function hexBuf(b) {
    return b.toString('hex').replace(/(..)/g, '$1 ').trim();
}

function getTik(pfs0, entries) {
    for (const t of entries) if (t.name.toLowerCase().endsWith('.tik')) return pfs0.subarray(t.offset, t.offset + t.size);
    return null;
}

function getTitlekey(tikData) {
    if (!tikData || tikData.length < 0x190) return null;
    const kekRaw = keys.titlekek_02 || keys.titlekek_source;
    const kek = typeof kekRaw === 'string' ? Buffer.from(kekRaw, 'hex') : Buffer.from(kekRaw);
    return new AesEcb(kek).decrypt(Buffer.from(tikData.subarray(0x180, 0x190)));
}

function ctrDecrypt(raw, titlekey, nonce, seek) {
    const c = new AesCtr(titlekey, nonce);
    c.seek(seek);
    return c.decrypt(raw);
}

// --- Test base program NCA sections ---
{
    const pfs0 = fs.readFileSync(basePath);
    const entries = new PFS0(pfs0).getFiles();
    const tik = getTik(pfs0, entries);
    const titlekey = getTitlekey(tik);
    console.log(`base titlekey: ${titlekey ? titlekey.toString('hex') : 'N/A'}`);

    for (const e of entries) {
        if (!e.name.toLowerCase().endsWith('.nca') || e.name.toLowerCase().endsWith('.cnmt.nca')) continue;
        const raw = pfs0.subarray(e.offset, e.offset + e.size);
        const h = decryptNcaHeader(raw.subarray(0, 0xC00), keys);
        if (!h || h.contentType !== 0) continue;
        console.log(`\n### BASE program ${e.name}`);
        for (let i = 0; i < 4; i++) {
            const s = h.sections[i];
            if (!s || s.size === 0) continue;
            const fh = new Uint8Array(h.fsHeader || raw.subarray(0, 0xC00));
            // get section ctr from raw decrypted header
            const xts = new AesXts(Buffer.isBuffer(keys.header_key) ? keys.header_key : Buffer.from(keys.header_key, 'hex'));
            const dec = xts.decrypt(raw.subarray(0, 0xC00), 0);
            const nonceRaw = dec.subarray(0x400 + i * 0x200 + 0x140, 0x400 + i * 0x200 + 0x148);
            const nonce = Buffer.alloc(8);
            for (let j = 0; j < 8; j++) nonce[j] = nonceRaw[7 - j];
            const sectData = raw.subarray(s.offset, s.offset + Math.min(s.size, 0x1000000));
            const decd = await ctrDecrypt(sectData, titlekey, nonce, s.offset);
            const m = decd.toString('ascii', 0, 4);
            const decd2 = await ctrDecrypt(sectData, titlekey, nonce, s.offset);
            console.log(`  sec[${i}] fsType=${s.fsType} crypto=${s.cryptoType} off=0x${s.offset.toString(16)} size=0x${s.size.toString(16)} first4='${m}'`);
            console.log(`    nonce=${nonce.toString('hex')}`);
            if (m === 'PFS0' || m === 'IVFC') {
                const firstBlock = Buffer.from(decd2.subarray(0, 0x100));
                console.log(`    OK! ${m} @ 0: ${hexBuf(firstBlock.subarray(0, 0x40))}`);
            }
        }
    }
}

// --- Update BKTR FsHeader ---
{
    const pfs0 = fs.readFileSync(updatePath);
    const entries = new PFS0(pfs0).getFiles();
    for (const e of entries) {
        if (!e.name.toLowerCase().endsWith('.nca') || e.name.toLowerCase().endsWith('.cnmt.nca')) continue;
        const raw = pfs0.subarray(e.offset, e.offset + e.size);
        const h = decryptNcaHeader(raw.subarray(0, 0xC00), keys);
        if (!h || h.contentType !== 0) continue;
        console.log(`\n### UPDATE program ${e.name}`);
        const xts = new AesXts(Buffer.isBuffer(keys.header_key) ? keys.header_key : Buffer.from(keys.header_key, 'hex'));
        const dec = xts.decrypt(raw.subarray(0, 0xC00), 0);
        for (let i = 0; i < 4; i++) {
            const s = h.sections[i];
            if (!s || s.size === 0) continue;
            if (s.fsType !== 3) continue;
            const fh = dec.subarray(0x400 + i * 0x200, 0x400 + i * 0x200 + 0x200);
            console.log(`  sec[${i}] fsType=${s.fsType} crypto=${s.cryptoType} off=0x${s.offset.toString(16)} size=0x${s.size.toString(16)}`);
            for (let off = 0xf0; off < 0x148; off += 0x10) {
                console.log(`    FsHeader+0x${off.toString(16)}: ${hexBuf(Buffer.from(fh.subarray(off, off + 0x10)))}`);
            }
        }
    }
}

// --- Yanu merged NCA RomFS FsHeader + first bytes ---
{
    const pfs0 = fs.readFileSync(yanuPath);
    const entries = new PFS0(pfs0).getFiles();
    console.log(`\n### YANU merged NSP: ${entries.length} entries`);
    for (const e of entries) console.log(`  ${e.name} size=${e.size}`);
    const prog = entries.find(e => !e.name.toLowerCase().endsWith('.cnmt.nca') && e.size > 100_000_000);
    if (prog) {
        const raw = pfs0.subarray(prog.offset, prog.offset + prog.size);
        const xts = new AesXts(Buffer.isBuffer(keys.header_key) ? keys.header_key : Buffer.from(keys.header_key, 'hex'));
        const dec = xts.decrypt(raw.subarray(0, 0xC00), 0);
        console.log(`  yanu program ${prog.name} size=${raw.length}`);
        for (let i = 0; i < 4; i++) {
            const fh = dec.subarray(0x400 + i * 0x200, 0x400 + i * 0x200 + 0x200);
            const fsType = fh[0x03];
            if (fsType === 3) {
                console.log(`  RomFS sec[${i}] FsHeader:`);
                for (let off = 0x00; off < 0x60; off += 0x10) {
                    console.log(`    0x${off.toString(16).padStart(3, '0')}: ${hexBuf(Buffer.from(fh.subarray(off, off + 0x10)))}`);
                }
                console.log(`    0x140: ${hexBuf(Buffer.from(fh.subarray(0x140, 0x150)))}`);
                // section table
                for (let si = 0; si < 4; si++) {
                    const off = 0x240 + si * 0x10;
                    console.log(`    sectable[${si}] @0x${off.toString(16)}: ${hexBuf(Buffer.from(dec.subarray(off, off + 0x10)))}`);
                }
                const secNum = i;
                const mediaOffset = dec.readUInt32LE(0x240 + secNum * 0x10);
                const mediaEnd = dec.readUInt32LE(0x240 + secNum * 0x10 + 4);
                const secOff = mediaOffset * 0x200;
                const secSize = mediaEnd * 0x200 - secOff;
                console.log(`  mediaOffset=${mediaOffset} (0x${secOff.toString(16)}) mediaEnd=${mediaEnd} size=0x${secSize.toString(16)}`);
                const firstBytes = raw.subarray(secOff, secOff + 0x40);
                console.log(`  section media[0:0x40]: ${hexBuf(Buffer.from(firstBytes))}`);
            }
        }
    }
}
