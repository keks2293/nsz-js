// Shared NCA utilities extracted from duplicated code in nca-pack.js, update.js, bktr.js, bktr-merge.js

import { AesEcb } from '../crypto/aes128.js';
import { AesXts } from '../crypto/aes-ops.mjs';

export const NCA_HEADER_SIZE = 0xC00;

export function hexToBytes(hex) {
    const buf = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        buf[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return buf;
}

export function writeU64LE(buf, offset, value) {
    const n = typeof value === 'bigint' ? value : BigInt(value);
    const view = new DataView(buf.buffer, buf.byteOffset + offset, 8);
    view.setBigUint64(0, n, true);
}

export function writeU32LE(buf, offset, value) {
    const view = new DataView(buf.buffer, buf.byteOffset + offset, 4);
    view.setUint32(0, value, true);
}

// Normalize a key from the keys file: hex string, Uint8Array, or Array.
export function toKeyBytes(v) {
    if (v instanceof Uint8Array) return v;
    return typeof v === 'string' ? hexToBytes(v) : new Uint8Array(v);
}

// XTS-decrypt a raw NCA header (0xC00 bytes) with header_key.
export function decryptNcaHeaderBytes(raw, keys) {
    return new AesXts(toKeyBytes(keys.header_key)).decrypt(raw, 0);
}

// Derive titlekey from the NCA header key area (hactool nca.c: nca_decrypt_key_area,
// titlekey = decrypted entry [2]). Key area (4 x 16B) at 0x300-0x340 decrypted with
// AES-128-ECB using key_area_keys[master_key][kaek_ind]. Master key index per hactool
// (nca_process): crypto_type = max(crypto_type, crypto_type2), then -- if nonzero
// (i.e. 0,1 → master key 0).
export function deriveTitlekeyFromKeyArea(decHeader, keys) {
    if (!keys) return null;
    const cryptoType = decHeader[0x206];
    const cryptoType2 = decHeader[0x220];
    const kaekInd = decHeader[0x207];
    const maxCt = Math.max(cryptoType, cryptoType2);
    const mk = maxCt > 0 ? maxCt - 1 : 0;
    const kakHex = keys.keyAreaKeys && keys.keyAreaKeys[mk] && (keys.keyAreaKeys[mk][kaekInd] || keys.keyAreaKeys[mk][0]);
    if (!kakHex) return null;
    const keyArea = decHeader.subarray(0x300, 0x340);
    if (keyArea.length < 0x40) return null;
    const unwrapped = new AesEcb(toKeyBytes(kakHex)).decrypt(keyArea);
    return unwrapped.subarray(0x20, 0x30);
}

// Extract titlekey from a .tik file (hactool: titlekek ECB-decrypt of bytes
// [0x180, 0x190)). Scene/prod tickets carry the mk2 titlekey, so titlekek_02 is used.
// Optionally verifies rights_id at 0x2A0 against expectedRightsId (32-char hex).
export function extractTitlekeyFromTik(tikData, keys, expectedRightsId = null) {
    if (!tikData || tikData.length < (expectedRightsId ? 0x2B0 : 0x190)) return null;
    const titlekek = keys.titlekek_02;
    if (!titlekek) return null;
    if (expectedRightsId) {
        const rid = tikData.subarray(0x2A0, 0x2B0);
        const ridStr = Array.from(rid).map(b => b.toString(16).padStart(2, '0')).join('');
        if (ridStr.toLowerCase() !== expectedRightsId.toLowerCase()) return null;
    }
    return new AesEcb(toKeyBytes(titlekek)).decrypt(tikData.subarray(0x180, 0x190));
}

// Resolve titlekey for an NCA: tik first (if provided), then key-area fallback.
export function resolveTitlekey(tikData, decHeader, keys) {
    if (tikData) {
        const tk = extractTitlekeyFromTik(tikData, keys);
        if (tk) return tk;
    }
    return deriveTitlekeyFromKeyArea(decHeader, keys);
}

// Reversed section CTR: FsHeader[0x140:0x148] stores the counter little-endian,
// but AES-CTR expects the initial counter big-endian (hactool nca.c nca_update_ctr
// builds ctr[j] = section_ctr[8-j-1]).
export function reversedSectionCtr(fsHdr) {
    const raw = fsHdr.subarray(0x140, 0x148);
    const rev = new Uint8Array(8);
    for (let i = 0; i < 8; i++) rev[i] = raw[7 - i];
    return rev;
}

// Find the RomFS section (hash_type 3) among the 4 FsHeaders of a decrypted header.
// Returns { idx, fsHdr } or throws.
export function findRomfsFsHeader(decHeader, name) {
    for (let i = 0; i < 4; i++) {
        const fh = decHeader.subarray(0x400 + i * 0x200, 0x400 + i * 0x200 + 0x200);
        if (fh[0x03] === 3) return { idx: i, fsHdr: fh };
    }
    throw new Error(`${name}: RomFS section not found`);
}
