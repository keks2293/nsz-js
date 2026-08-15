import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesCtr, AesXts } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp`;
const updatePath = `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsp`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

function readPfs0Files(buf) {
    const pfs0 = new PFS0(buf);
    return pfs0.getFiles();
}

function findNca(pfs0, entries, kind) {
    // kind: 'base program', 'update program'
    const candidates = entries.filter(e => e.name.toLowerCase().endsWith('.nca') && !e.name.toLowerCase().endsWith('.cnmt.nca'));
    for (const e of candidates) {
        const raw = pfs0.subarray(e.offset, e.offset + e.size);
        const h = decryptNcaHeader(raw.subarray(0, 0xC00), keys);
        if (!h) continue;
        if (h.contentType !== 0) continue;
        const tid = h.titleId ? h.titleId.toString(16) : '?';
        return { e, h, raw };
    }
    return null;
}

function u64le(b, o) {
    return Number(b.readBigUInt64LE(o));
}
function u32le(b, o) {
    return b.readUInt32LE(o);
}
function hex(b, o, n) {
    return b.subarray(o, o + n).toString('hex').replace(/(..)/g, '$1 ').trim();
}

function dumpFsHeader(dec, secIdx, label) {
    const fh = dec.subarray(0x400 + secIdx * 0x200, 0x400 + secIdx * 0x200 + 0x200);
    console.log(`\n=== ${label}: FsHeader section ${secIdx} ===`);
    for (let row = 0; row < 0x200; row += 0x10) {
        const b = fh.subarray(row, row + 0x10);
        let ascii = '';
        for (let i = 0; i < 0x10; i++) {
            const c = b[i];
            ascii += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
        }
        console.log(`${row.toString(16).padStart(3, '0')}: ${hex(b, 0, 0x10)}  ${ascii}`);
    }
    return fh;
}

for (const [label, path] of [['BASE', basePath], ['UPDATE', updatePath]]) {
    const pfs0 = fs.readFileSync(path);
    const entries = readPfs0Files(pfs0);
    console.log(`\n########## ${label}: ${pfs0.length} bytes, ${entries.length} entries ##########`);
    for (const e of entries) console.log(`  ${e.name}  offset=0x${e.offset.toString(16)} size=0x${e.size.toString(16)} (${e.size})`);

    for (const e of entries) {
        if (!e.name.toLowerCase().endsWith('.nca') || e.name.toLowerCase().endsWith('.cnmt.nca')) continue;
        const raw = pfs0.subarray(e.offset, e.offset + e.size);
        const h = decryptNcaHeader(raw.subarray(0, 0xC00), keys);
        if (!h) continue;
        const isProgram = h.contentType === 0;
        const isMeta = h.contentType === 1;
        if (!isProgram) continue;
        const tid = h.titleId ? h.titleId.toString(16).toUpperCase() : '?';
        console.log(`\n### ${label} Program NCA: ${e.name}`);
        console.log(`  contentType=${h.contentType} cryptoType=${h.cryptoType} titleId=${tid} size=${e.size}`);
        for (let i = 0; i < 4; i++) {
            const s = h.sections[i];
            if (!s || s.size === 0) continue;
            console.log(`  sec[${i}]: fsType=${s.fsType} crypto=${s.cryptoType} offset=0x${s.offset.toString(16)} size=0x${s.size.toString(16)} sectionStart=0x${s.sectionStart?.toString(16)} sectionSize=0x${s.sectionSize?.toString(16)}`);
        }
    }
}

// Deep-dive on the base program's RomFS FsHeader + CTR decrypt test
{
    const pfs0 = fs.readFileSync(basePath);
    const entries = readPfs0Files(pfs0);
    for (const e of entries) {
        if (!e.name.toLowerCase().endsWith('.nca') || e.name.toLowerCase().endsWith('.cnmt.nca')) continue;
        const raw = pfs0.subarray(e.offset, e.offset + e.size);
        const h = decryptNcaHeader(raw.subarray(0, 0xC00), keys);
        if (!h || h.contentType !== 0) continue;

        // find tik
        let tikData = null;
        for (const t of entries) {
            if (t.name.toLowerCase().endsWith('.tik')) { tikData = pfs0.subarray(t.offset, t.offset + t.size); break; }
        }

        const hdrKey = Buffer.isBuffer(keys.header_key) ? keys.header_key : Buffer.from(keys.header_key, 'hex');
        const xts = new AesXts(hdrKey);
        const dec = xts.decrypt(raw.subarray(0, 0xC00), 0);

        for (let i = 0; i < 4; i++) {
            const s = h.sections[i];
            if (!s || s.size === 0 || s.fsType !== 3) continue;
            dumpFsHeader(dec, i, `BASE program RomFS sec[${i}]`);

            // titlekey
            let titlekey = null;
            if (tikData && tikData.length >= 0x190) {
                const kekRaw = keys.titlekek_02 || keys.titlekek_source;
                const kek = typeof kekRaw === 'string' ? Buffer.from(kekRaw, 'hex') : Buffer.from(kekRaw);
                titlekey = new AesEcb(kek).decrypt(Buffer.from(tikData.subarray(0x180, 0x190)));
            }
            console.log(`  base titlekey: ${titlekey ? titlekey.toString('hex') : 'N/A'}`);

            // CTR decrypt first 0x100 bytes of section media
            const nonceRaw = dec.subarray(0x400 + i * 0x200 + 0x140, 0x400 + i * 0x200 + 0x148);
            const nonce = Buffer.alloc(8);
            for (let j = 0; j < 8; j++) nonce[j] = nonceRaw[7 - j];
            console.log(`  section_ctr(raw)=${nonceRaw.toString('hex')} nonce=${nonce.toString('hex')}`);

            const c = new AesCtr(titlekey, nonce);
            c.seek(s.offset);
            const first = await c.decrypt(raw.subarray(s.offset, s.offset + 0x100));
            console.log(`  CTR-decrypted media[0:0x100]: ${hex(Buffer.from(first), 0, 0x80)}`);
            const str = Buffer.from(first).toString('ascii', 0, 4);
            console.log(`  -> magic: '${str}'`);

            // check for BKTR magics in FsHeader 0x100/0x110/0x120/0x128
            const fh = dec.subarray(0x400 + i * 0x200, 0x400 + i * 0x200 + 0x200);
            for (const off of [0xF8, 0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130]) {
                const m = fh.toString('ascii', off, off + 4);
                if (m === 'BKTR' || m === 'IVFC') console.log(`  FsHeader+0x${off.toString(16)}: '${m}'`);
            }
        }
    }
}
