#!/usr/bin/env node
// Compare our output NSP with yanu reference, field by field.
// Usage: node probe/compare_with_yanu.mjs <our.nsp> <yanu.nsp> [keys.txt]
import fs from 'node:fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader, decryptNcaSection } from '../fs/nca.js';
import { AesXts, AesCtr } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';
import { sha256 } from '../crypto/sha256.js';

function hexToBytes(hex) {
    const buf = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) buf[i / 2] = parseInt(hex.substr(i, 2), 16);
    return buf;
}

function u32(b, o) { return b.readUInt32LE(o); }
function u64(b, o) { return Number(b.readBigUint64LE(o)); }

const NCA_HDR = 0xC00;

async function readNca(header, keys) {
    const dec = Buffer.from(new AesXts(keys.hdrKey).decrypt(header, 0));
    const hdr = {
        magic: String.fromCharCode(dec[0x200], dec[0x201], dec[0x202], dec[0x203]),
        distribution: dec[0x204],
        contentType: dec[0x205],
        cryptoType: dec[0x206],
        kaekInd: dec[0x207],
        ncaSize: u64(dec, 0x208),
        titleId: dec.readBigUint64BE(0x210).toString(16),
        sdkVersion: u32(dec, 0x21C),
        cryptoType2: dec[0x220],
        rightsId: dec.subarray(0x230, 0x240).toString('hex'),
        fixedKeySig: dec.subarray(0, 0x10).toString('hex'),
        npdmKeySig: dec.subarray(0x100, 0x110).toString('hex'),
    };
    for (let i = 0; i < 4; i++) {
        const base = 0x240 + i * 0x10;
        hdr[`sec${i}MediaOff`] = u32(dec, base);
        hdr[`sec${i}MediaEnd`] = u32(dec, base + 4);
        hdr[`sec${i}_0x8`] = dec.subarray(base + 8, base + 0x10).toString('hex');
    }
    hdr.sectionHash0 = dec.subarray(0x280, 0x2A0).toString('hex');
    hdr.sectionHash1 = dec.subarray(0x2A0, 0x2C0).toString('hex');
    hdr.encryptedKeys = dec.subarray(0x300, 0x340).toString('hex');

    // FsHeaders
    for (let i = 0; i < 4; i++) {
        const off = 0x400 + i * 0x200;
        hdr[`fh${i}ver`] = u32(dec, off);
        hdr[`fh${i}fsType`] = dec[off + 2];
        hdr[`fh${i}hashType`] = dec[off + 3];
        hdr[`fh${i}cryptType`] = dec[off + 4];
        hdr[`fh${i}sectionStart`] = u64(dec, off + 0x40);
        hdr[`fh${i}sectionSize`] = u64(dec, off + 0x48);
        hdr[`fh${i}sectionCtr`] = dec.subarray(off + 0x140, off + 0x148).toString('hex');
    }
    // PFS0/IVFC superblock
    for (let i = 0; i < 4; i++) {
        const off = 0x408 + i * 0x200;
        hdr[`fh${i}masterHash`] = dec.subarray(off, off + 0x20).toString('hex');
        hdr[`fh${i}blockSize`] = u32(dec, off + 0x28);
        hdr[`fh${i}always2`] = u32(dec, off + 0x2C);
        hdr[`fh${i}htableSize`] = u64(dec, off + 0x38);
        hdr[`fh${i}pfs0Offset`] = u64(dec, off + 0x40);
        hdr[`fh${i}pfs0Size`] = u64(dec, off + 0x48);
    }
    // IVFC
    for (let i = 0; i < 4; i++) {
        const ivfcOff = 0x408 + i * 0x200;
        hdr[`fh${i}ivfcMagic`] = u32(dec, ivfcOff);
        hdr[`fh${i}ivfcId`] = u32(dec, ivfcOff + 4);
        hdr[`fh${i}ivfcNumLevels`] = u32(dec, ivfcOff + 12);
        hdr[`fh${i}ivfcMasterHash`] = dec.subarray(ivfcOff + 0xC0, ivfcOff + 0xE0).toString('hex');
        for (let l = 0; l < 6; l++) {
            const lb = ivfcOff + 0x10 + l * 0x18;
            hdr[`fh${i}lvl${l}_log`] = u64(dec, lb);
            hdr[`fh${i}lvl${l}_hds`] = u64(dec, lb + 8);
            hdr[`fh${i}lvl${l}_bs`] = u32(dec, lb + 16);
        }
    }
    return hdr;
}

async function main() {
    const ourPath = process.argv[2] || '/tmp/update_e2e_out.nsp';
    const yanuPath = process.argv[3] || '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp';
    const keysPath = process.argv[4] || '../static/prod.keys';

    const keysRaw = fs.readFileSync(keysPath, 'utf8');
    const keys = KeysParser.parse(keysRaw);
    keys.hdrKey = typeof keys.header_key === 'string' ? Buffer.from(keys.header_key, 'hex') : keys.header_key;

    const ourNsp = fs.readFileSync(ourPath);
    const yanuNsp = fs.readFileSync(yanuPath);

    const u32nsp = (b, o) => b.readUInt32LE(o);
    const u64nsp = (b, o) => Number(b.readBigUint64LE(o));

    const getMember = (nsp, idx) => {
        const nf = u32nsp(nsp, 4);
        const st = u32nsp(nsp, 8);
        if (idx >= nf) return null;
        const e = 0x10 + idx * 0x18;
        const no = u32nsp(nsp, e + 16);
        let nm = '';
        for (let j = no; j < st; j++) { const c = nsp[0x10 + nf * 0x18 + j]; if (!c) break; nm += String.fromCharCode(c); }
        const size = u64nsp(nsp, e + 8);
        const off = u64nsp(nsp, e) + 0x10 + nf * 0x18 + st;
        return { name: nm, size, offset: off, data: nsp.subarray(off, off + Math.min(size, 0xC00)) };
    };

    // Compare member count
    const ourNf = u32nsp(ourNsp, 4);
    const yanuNf = u32nsp(yanuNsp, 4);
    console.log(`=== Members: our=${ourNf} yanu=${yanuNf} ${ourNf === yanuNf ? 'OK' : 'MISMATCH'} ===`);

    // Compare each member
    for (let i = 0; i < Math.max(ourNf, yanuNf); i++) {
        const our = getMember(ourNsp, i);
        const yanu = getMember(yanuNsp, i);
        if (!our || !yanu) {
            console.log(`\nMember[${i}] MISMATCH: ${our ? our.name : 'MISSING'} vs ${yanu ? yanu.name : 'MISSING'}`);
            continue;
        }
        console.log(`\n=== Member[${i}] ${our.name} ===`);
        const sizeMatch = our.size === yanu.size ? 'OK' : `MISMATCH ${our.size} vs ${yanu.size}`;
        console.log(`  size: ${sizeMatch}`);

        // Compare headers
        const ourHdr = await readNca(our.data, keys);
        const yanuHdr = await readNca(yanu.data, keys);

        const fields = [
            'magic', 'contentType', 'cryptoType', 'kaekInd', 'ncaSize', 'titleId',
            'sdkVersion', 'cryptoType2', 'rightsId', 'fixedKeySig', 'npdmKeySig',
        ];
        for (const f of fields) {
            const v1 = ourHdr[f];
            const v2 = yanuHdr[f];
            if (v1 === v2) {
                // console.log(`  ${f}: OK`);
            } else {
                console.log(`  ${f}: OUR=${JSON.stringify(v1)} YANU=${JSON.stringify(v2)} MISMATCH`);
            }
        }

        // Section entries
        for (let s = 0; s < 4; s++) {
            const prefix = `sec${s}`;
            const oOff = ourHdr[`${prefix}MediaOff`];
            const yOff = yanuHdr[`${prefix}MediaOff`];
            const oEnd = ourHdr[`${prefix}MediaEnd`];
            const yEnd = yanuHdr[`${prefix}MediaEnd`];
            if (oOff === yOff && oEnd === yEnd) continue;
            console.log(`  ${prefix}: off OUR=${oOff} YANU=${yOff} end OUR=${oEnd} YANU=${yEnd} MISMATCH`);
        }

        // FsHeaders
        for (let s = 0; s < 4; s++) {
            const prefix = `fh${s}`;
            const checks = [
                ['fsType', ourHdr[`${prefix}fsType`], yanuHdr[`${prefix}fsType`]],
                ['hashType', ourHdr[`${prefix}hashType`], yanuHdr[`${prefix}hashType`]],
                ['cryptType', ourHdr[`${prefix}cryptType`], yanuHdr[`${prefix}cryptType`]],
                ['sectionStart', ourHdr[`${prefix}sectionStart`], yanuHdr[`${prefix}sectionStart`]],
                ['sectionSize', ourHdr[`${prefix}sectionSize`], yanuHdr[`${prefix}sectionSize`]],
                ['blockSize', ourHdr[`${prefix}blockSize`], yanuHdr[`${prefix}blockSize`]],
                ['htableSize', ourHdr[`${prefix}htableSize`], yanuHdr[`${prefix}htableSize`]],
                ['pfs0Offset', ourHdr[`${prefix}pfs0Offset`], yanuHdr[`${prefix}pfs0Offset`]],
                ['pfs0Size', ourHdr[`${prefix}pfs0Size`], yanuHdr[`${prefix}pfs0Size`]],
            ];
            for (const [name, ov, yv] of checks) {
                if (ov !== yv) {
                    console.log(`  ${prefix}.${name}: OUR=${ov} YANU=${yv} MISMATCH`);
                }
            }
            if (ourHdr[`${prefix}masterHash`] !== yanuHdr[`${prefix}masterHash`] && ourHdr[`${prefix}masterHash`]) {
                console.log(`  ${prefix}.masterHash: OUR=${ourHdr[`${prefix}masterHash`].slice(0, 32)}... YANU=${yanuHdr[`${prefix}masterHash`].slice(0, 32)}...`);
            }
            // IVFC
            if (ourHdr[`${prefix}ivfcMagic`] !== yanuHdr[`${prefix}ivfcMagic`]) {
                console.log(`  ${prefix}.ivfcMagic: OUR=${ourHdr[`${prefix}ivfcMagic`]} YANU=${yanuHdr[`${prefix}ivfcMagic`]}`);
            }
            if (ourHdr[`${prefix}ivfcNumLevels`] !== yanuHdr[`${prefix}ivfcNumLevels`] && ourHdr[`${prefix}ivfcNumLevels`]) {
                console.log(`  ${prefix}.ivfcNumLevels: OUR=${ourHdr[`${prefix}ivfcNumLevels`]} YANU=${yanuHdr[`${prefix}ivfcNumLevels`]}`);
            }
            for (let l = 0; l < 6; l++) {
                if (ourHdr[`${prefix}lvl${l}_log`] !== yanuHdr[`${prefix}lvl${l}_log`]) {
                    console.log(`  ${prefix}.lvl${l}_log: OUR=${ourHdr[`${prefix}lvl${l}_log`].toString(16)} YANU=${yanuHdr[`${prefix}lvl${l}_log`].toString(16)}`);
                }
                if (ourHdr[`${prefix}lvl${l}_hds`] !== yanuHdr[`${prefix}lvl${l}_hds`] && ourHdr[`${prefix}lvl${l}_log`]) {
                    console.log(`  ${prefix}.lvl${l}_hds: OUR=${ourHdr[`${prefix}lvl${l}_hds`].toString(16)} YANU=${yanuHdr[`${prefix}lvl${l}_hds`].toString(16)}`);
                }
            }
        }

        // encrypted_keys
        if (ourHdr.encryptedKeys !== yanuHdr.encryptedKeys && ourHdr.encryptedKeys) {
            console.log(`  encrypted_keys: MISMATCH`);
        }

        // Section hashes
        if (ourHdr.sectionHash0 && ourHdr.sectionHash0 !== yanuHdr.sectionHash0) {
            console.log(`  sectionHash0: OUR=${ourHdr.sectionHash0.slice(0, 32)} YANU=${yanuHdr.sectionHash0.slice(0, 32)}`);
        }
    }
}

main();
