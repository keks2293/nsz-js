// Shared NCA utilities extracted from duplicated code in nca-pack.js, update.js, bktr.js, bktr-merge.js

import { AesEcb } from '../crypto/aes128.js';
import { AesXts } from '../crypto/aes-ops.mjs';

export const NCA_HEADER_SIZE = 0xC00;

// ── IVFC format constants (hacpack ivfc.h / nca.c) ─────────────────────────────
// ivfc_hdr_t: magic@0x00, id@0x04, master_hash_size@0x08, num_levels@0x0C,
// level_headers[IVFC_MAX_LEVEL]@0x10, _0xA0[0x20]@0xA0, master_hash@0xC0 (total 0xE0).
// Shared by the packer (nca-pack.js buildIvfcHeader) and the BKTR reader
// (bktr-merge.js), which parses the same layout from a stored superblock.
export const MAGIC_IVFC = 0x43465649;        // "IVFC"
export const IVFC_HEADER_SIZE = 0xE0;
export const IVFC_ID = 0x20000;
export const IVFC_MASTER_HASH_SIZE = 0x20;
export const IVFC_NUM_LEVELS = 0x07;         // 6 level slots; 7 is the canonical field value
export const IVFC_BLOCK_SIZE_LOG2 = 0x0E;    // block_size field = log2(0x4000)
export const IVFC_HASH_BLOCK_SIZE = 0x4000;  // hacpack ivfc.h IVFC_HASH_BLOCK_SIZE
export const IVFC_HASH_SIZE = 0x20;          // sha256 digest per block
export const IVFC_LEVELS_OFFSET = 0x10;
export const IVFC_MASTER_HASH_OFFSET = 0xC0;
export const IVFC_MAX_LEVEL = 6;             // hacpack ivfc.h; level [5] = DATA level
// ivfc_level_hdr_t: logical_offset(u64)@+0x00, hash_data_size(u64)@+0x08,
// block_size(u32)@+0x10, reserved(u32)@+0x14 → 0x18 bytes
export const IVFC_LEVEL_HDR = { SIZE: 0x18, LOGICAL_OFFSET: 0x00, HASH_DATA_SIZE: 0x08, BLOCK_SIZE: 0x10 };

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
