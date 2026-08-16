#!/usr/bin/env node
// Compare the main.npdm (NPDM / ACID) extracted from the Program NCA of two NSPs.
// Shows the NPDM header offsets (aci0_offset / acid_offset) and the byte-level
// diff ranges — used to document why yanu zeroes the ACID key pair in a
// plaintext --update repack while we keep the update NCA's original ACID.
//
// Usage: node analyze_npdm.mjs <our.nsp> <yanu.nsp> [keys.txt]
import fs from 'node:fs';
import { PFS0 } from '../fs/pfs0.js';
import { AesXts } from '../crypto/aes-ops.mjs';

function parseKeys(path) {
    const keys = {};
    for (const line of fs.readFileSync(path, 'utf-8').split('\n')) {
        const [name, value] = line.split('=');
        if (name && value) keys[name.trim()] = value.trim();
    }
    return keys;
}

function hexToBytes(hex) {
    const b = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
    return b;
}

// Extract main.npdm from the largest NSP member (the Program NCA). The Program
// NCA is --plaintext, so its ExeFS section is unencrypted; only the 0xC00 NCA
// header needs AesXts(header_key) to locate the ExeFS PFS0.
function getNpdm(nspBuf, keys, label) {
    const pfs0 = new PFS0(nspBuf);
    const prog = pfs0.getFiles().reduce((a, b) => (b.size > a.size ? b : a));
    const nca = nspBuf.subarray(prog.offset, prog.offset + prog.size);
    const decHeader = new AesXts(hexToBytes(keys.header_key)).decrypt(nca.subarray(0, 0xC00), 0);
    const v = new DataView(decHeader.buffer, decHeader.byteOffset);
    // section[0] = ExeFS: media offset @0x240, FsHeader @0x400 (sectionStart @ +0x40)
    const secOff = v.getUint32(0x240, true) * 0x200;
    const sectionStart = Number(v.getBigUint64(0x400 + 0x40, true));
    const exefs = new PFS0(nca.subarray(secOff + sectionStart));
    const npdm = exefs.getFiles().find(e => e.name === 'main.npdm');
    if (!npdm) throw new Error(label + ': main.npdm not found in ExeFS');
    const npdmData = nca.subarray(secOff + sectionStart + npdm.offset, secOff + sectionStart + npdm.offset + npdm.size);
    const dv = new DataView(npdmData.buffer, npdmData.byteOffset);
    console.log(`\n=== ${label} ===  main.npdm size=0x${npdmData.length.toString(16)}`);
    console.log('magic:        ' + String.fromCharCode(npdmData[0], npdmData[1], npdmData[2], npdmData[3]));
    console.log('aci0: offset=0x' + dv.getUint32(0x70, true).toString(16) + ' size=0x' + dv.getUint32(0x74, true).toString(16));
    console.log('acid: offset=0x' + dv.getUint32(0x78, true).toString(16) + ' size=0x' + dv.getUint32(0x7c, true).toString(16)
        + '   (signature[0x100] @ +0x00, modulus[0x100] @ +0x100)');
    return npdmData;
}

function dump(buf, from, to) {
    for (let row = from; row < to; row += 16) {
        let hex = '', asc = '';
        for (let i = 0; i < 16; i++) { const b = buf[row + i]; hex += b.toString(16).padStart(2, '0') + ' '; asc += (b >= 32 && b < 127 ? String.fromCharCode(b) : '.'); }
        console.log('0x' + row.toString(16).padStart(4, '0') + '  ' + hex + ' ' + asc);
    }
}

function main() {
    const ourPath = process.argv[2] || '/tmp/update_e2e_out.nsp';
    const yanuPath = process.argv[3] || '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp';
    const keysPath = process.argv[4] || '../static/prod.keys';
    const keys = parseKeys(keysPath);
    const a = getNpdm(fs.readFileSync(ourPath), keys, 'OURS');
    const b = getNpdm(fs.readFileSync(yanuPath), keys, 'YANU');

    const diffs = [];
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) diffs.push(i);
    console.log(`\nDiffering bytes: ${diffs.length} of ${a.length}`);
    if (!diffs.length) { console.log('main.npdm is byte-identical.'); return; }
    console.log('Diff ranges:');
    for (let k = 0; k < diffs.length; ) {
        let j = k;
        while (j + 1 < diffs.length && diffs[j + 1] === diffs[j] + 1) j++;
        const s = diffs[k], e = diffs[j] + 1;
        console.log(`  0x${s.toString(16)} .. 0x${e.toString(16)}  (${e - s} B)`);
        k = j + 1;
    }
    const lo = diffs[0] & ~15, hi = (diffs[diffs.length - 1] + 1 + 15) & ~15;
    console.log('\n-- OURS --'); dump(a, lo, hi);
    console.log('\n-- YANU --'); dump(b, lo, hi);
}

main();
