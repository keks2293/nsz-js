// NCA-specific utilities (header offsets, titlekey, FsSection, IVFC).
// Generic byte-level helpers (hex + LE read/write) live in ./bytes.js.

import { AesEcb } from '../crypto/aes128.js';
import { AesXts } from '../crypto/aes-ops.mjs';
import { hexToBytes, bytesToHex, readLeU32 } from './bytes.js';

export const NCA_HEADER_SIZE = 0xC00;

// NCA header field offsets (mirror of hacPack nca_header_t, #pragma pack(1); switchbrew NCA).
export const NCA_HDR = {
    SIGNATURE_FIXED: 0x000,   // RSA sig over header (fixed key)
    SIGNATURE_NPDM: 0x100,    // RSA sig over header (NPDM ACID key)
    MAGIC: 0x200,
    DISTRIBUTION: 0x204,
    CONTENT_TYPE: 0x205,
    CRYPTO_TYPE: 0x206,
    KAEK_IND: 0x207,
    SIZE: 0x208,
    TITLE_ID: 0x210,
    CONTENT_INDEX: 0x218,
    SDK_VERSION: 0x21C,
    CRYPTO_TYPE2: 0x220,
    RIGHTS_ID: 0x230,
    SECTIONS: 0x240,              // 4 × 0x10 section entries (media offset/end in 0x200 blocks)
    SECTION_ENTRY_SIZE: 0x10,
    SECTION_HASHES: 0x280,        // 4 × 0x20 sha256 of each FsHeader
    KEY_AREA: 0x300,              // 4 × 0x10 encrypted titlekey slots
    FS_HEADERS: 0x400,            // 4 × 0x200 FsSection headers
    FS_HEADER_SIZE: 0x200,
    MEDIA_BLOCK_SIZE: 0x200,
};

// FsSection header field offsets (switchbrew NCA FsHeader; hacPack nca_fs_header_t).
export const FS_HDR = {
    FS_TYPE: 0x02,
    HASH_TYPE: 0x03,
    CRYPTO_TYPE: 0x04,
    HASH_DATA: 0x08,        // start of the hash superblock (PFS0 superblock / IVFC)
    PFS0_OFFSET: 0x40,      // HierarchicalSha256Data (PFS0): LayerRegions[1] offset
    PFS0_SIZE: 0x48,        // LayerRegions[1] size
    ROMFS_DATA_SIZE: 0x98,  // IVFC (HierarchicalIntegrity): DATA level (5) hash_data_size
    PATCH_INFO: 0x100,        // PatchInfo Indirect slot (reloc BKTR): offset@+0, size@+8, BKTR header@+0x10
    PATCH_INFO_AESCTREX: 0x120, // PatchInfo AesCtrEx slot (sub BKTR): offset@+0, size@+8, BKTR header@+0x10
    SECTION_CTR: 0x140,
    SECURE_VALUE: 0x144,
};

// content_type field of the NCA header 0x205 (switchbrew NCA; hacPack nca.c:249,617).
export const NCA_CONTENT_TYPE = { PROGRAM: 0x00, META: 0x01, CONTROL: 0x02, MANUAL: 0x03, DATA: 0x04, PUBLIC_DATA: 0x05 };

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
    const cryptoType = decHeader[NCA_HDR.CRYPTO_TYPE];
    const cryptoType2 = decHeader[NCA_HDR.CRYPTO_TYPE2];
    const kaekInd = decHeader[NCA_HDR.KAEK_IND];
    const maxCt = Math.max(cryptoType, cryptoType2);
    const mk = maxCt > 0 ? maxCt - 1 : 0;
    const kakHex = keys.keyAreaKeys && keys.keyAreaKeys[mk] && (keys.keyAreaKeys[mk][kaekInd] || keys.keyAreaKeys[mk][0]);
    if (!kakHex) return null;
    const keyArea = decHeader.subarray(NCA_HDR.KEY_AREA, NCA_HDR.KEY_AREA + 0x40);
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
        const ridStr = bytesToHex(rid);
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
    const raw = fsHdr.subarray(FS_HDR.SECTION_CTR, FS_HDR.SECTION_CTR + 8);
    const rev = new Uint8Array(8);
    for (let i = 0; i < 8; i++) rev[i] = raw[7 - i];
    return rev;
}

// Return the FsSection header (0x200 B) for section idx (0-3) of a decrypted NCA header.
export function fsHeaderAt(decHeader, idx) {
    const start = NCA_HDR.FS_HEADERS + idx * NCA_HDR.FS_HEADER_SIZE;
    return decHeader.subarray(start, start + NCA_HDR.FS_HEADER_SIZE);
}

// Return the media offset/end (0x240 + idx*0x10 entry) for a section, in media units.
export function sectionMedia(decHeader, idx) {
    const e = NCA_HDR.SECTIONS + idx * NCA_HDR.SECTION_ENTRY_SIZE;
    return { mediaOffset: readLeU32(decHeader, e), mediaEnd: readLeU32(decHeader, e + 4) };
}

// Find the RomFS section (hash_type 3) among the 4 FsHeaders of a decrypted header.
// Returns { idx, fsHdr } or throws.
export function findRomfsFsHeader(decHeader, name) {
    for (let i = 0; i < 4; i++) {
        const fh = fsHeaderAt(decHeader, i);
        if (fh[0x03] === 3) return { idx: i, fsHdr: fh };
    }
    throw new Error(`${name}: RomFS section not found`);
}

// content_type field of the NCA header: 0=Program, 1=Meta (hacPack nca.c:249,617).
export function isMetaNca(header) {
    return !!header && header.contentType === NCA_CONTENT_TYPE.META;
}
