// BKTR (Bucket Tree) primitives for NCA RomFS patching
// Reference: SciresM/hactool (nca.c, bktr.h) + switchbrew.org/wiki/NCA

import { AesEcb } from '../crypto/aes128.js';
import { AesCtr } from '../crypto/aes-ops.mjs';

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

export function readLeU64(buf, o) {
    return Number(new DataView(buf.buffer, buf.byteOffset + o, 8).getBigUint64(0, true));
}

export function readLeU32(buf, o) {
    return new DataView(buf.buffer, buf.byteOffset + o, 4).getUint32(0, true);
}

const BKTR_HEADER_OFFSET = 0x100; // In FsHeader extension

export function parseBktrHeader(fsHdr, offset) {
    return {
        offset: readLeU64(fsHdr, offset),
        size: readLeU64(fsHdr, offset + 8),
        magic: readLeU32(fsHdr, offset + 0x10),
    };
}

// Decrypt BKTR table region using AES-ECB with custom counter (AesCtr.seek gives wrong counter for some reason)
export async function decryptBktrTable(ncaData, titlekey, nonce, absOffset, size) {
    const result = new Uint8Array(size);
    const aes = new AesEcb(titlekey);
    const counter = new Uint8Array(16);
    let pos = 0;

    while (pos < size) {
        const chunkEnd = Math.min(pos + 16, size);
        const fileOffsetForBlock = absOffset + pos;

        // Build counter exactly as hactool does
        counter.set(nonce, 0);
        const blockIndex = Math.floor(fileOffsetForBlock / 16);
        let tmp = blockIndex;
        for (let j = 15; j >= 8; j--) {
            counter[j] = tmp & 0xFF;
            tmp >>= 8;
        }

        const keystream = aes.encryptBlock(counter);
        const rawBlock = ncaData.subarray(fileOffsetForBlock, fileOffsetForBlock + chunkEnd - pos);
        for (let i = 0; i < chunkEnd - pos; i++) {
            result[pos + i] = rawBlock[i] ^ keystream[i];
        }

        pos += chunkEnd - pos;
    }

    return result;
}

// Parse relocation block per hactool bktr.h bktr_relocation_block_t
export function parseRelocationBlock(block) {
    const numBuckets = readLeU32(block, 4);
    const totalSize = readLeU64(block, 8);
    const entries = [];

    // Per hactool bktr.h: bucket_virtual_offsets[0x3FF0/sizeof(uint64_t)] = 1022 entries
    // Fixed size: 0x3FF0 bytes, so buckets start at 0x4000
    for (let b = 0; b < numBuckets; b++) {
        const bucketOff = 0x4000 + b * 0x4000;
        if (bucketOff + 0x10 > block.length) break;
        const nEntries = readLeU32(block, bucketOff + 4);
        let eStart = bucketOff + 0x10;
        for (let i = 0; i < nEntries; i++) {
            if (eStart + 0x14 > block.length) break;
            entries.push({
                virtOffset: readLeU64(block, eStart),
                physOffset: readLeU64(block, eStart + 8),
                isPatch: readLeU32(block, eStart + 0x10) !== 0,
            });
            eStart += 0x14;
        }
    }

    return { totalSize, entries };
}

// Parse subsection block per hactool bktr.h bktr_subsection_block_t
// bucket_physical_offsets[0x3FF0/sizeof(uint64_t)] = 1022 entries, fixed size 0x3FF0 bytes
// bktr_subsection_entry_t: offset(u64) + _0x8(u32) + ctr_val(u32) = 16 bytes with pragma pack(1)
export function parseSubsectionBlock(block) {
    const numBuckets = readLeU32(block, 4);
    const totalSize = readLeU64(block, 8);
    const entries = [];

    // Buckets start at 0x4000 (fixed, after bucket_physical_offsets array)
    for (let b = 0; b < numBuckets; b++) {
        const bucketOff = 0x4000 + b * 0x4000;
        if (bucketOff + 0x10 > block.length) break;
        const nEntries = readLeU32(block, bucketOff + 4);
        let eStart = bucketOff + 0x10;
        for (let i = 0; i < nEntries; i++) {
            if (eStart + 0x10 > block.length) break;
            entries.push({
                offset: readLeU64(block, eStart),
                ctrVal: readLeU32(block, eStart + 12),
            });
            eStart += 16;
        }
    }

    return { totalSize, entries };
}

export function findRelocEntry(entries, virtOffset) {
    let lo = 0, hi = entries.length - 1;
    while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (entries[mid].virtOffset > virtOffset) hi = mid - 1;
        else lo = mid + 1;
    }
    if (hi < 0) return null;
    const nextVirt = hi + 1 < entries.length ? entries[hi + 1].virtOffset : Infinity;
    if (virtOffset < nextVirt) return entries[hi];
    return null;
}

export function findSubsectionEntry(entries, physOffset) {
    const idx = subEntryIdx(entries, physOffset);
    if (idx < 0) return null;
    return entries[idx];
}

export function subEntryIdx(entries, physOffset) {
    let lo = 0, hi = entries.length - 1;
    while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (entries[mid].offset > physOffset) hi = mid - 1;
        else lo = mid + 1;
    }
    if (hi < 0) return -1;
    const nextOff = hi + 1 < entries.length ? entries[hi + 1].offset : Infinity;
    if (physOffset < nextOff) return hi;
    return -1;
}

// Build AesCtrEx counter block per hactool's nca_update_bktr_ctr
// counter[0:4] = section_ctr[0:4] (first 4 bytes as-is, NOT reversed)
// counter[4:8] = ctr_val LE
// counter[8:16] = block_index BE (ofs / 16, where ofs is absolute offset in NCA)
export function buildAesCtrExCounter(sectionCtr, ctrVal, fileOffset) {
    const ctr = new Uint8Array(16);
    // ctr[0:4] = section_ctr[0:4] as-is (matches hactool)
    ctr[0] = sectionCtr[0];
    ctr[1] = sectionCtr[1];
    ctr[2] = sectionCtr[2];
    ctr[3] = sectionCtr[3];
    // ctr[4:8] = ctr_val LE
    ctr[4] = ctrVal & 0xFF;
    ctr[5] = (ctrVal >> 8) & 0xFF;
    ctr[6] = (ctrVal >> 16) & 0xFF;
    ctr[7] = (ctrVal >> 24) & 0xFF;
    // ctr[8:16] = block_index BE
    const blockIndex = Math.floor(fileOffset / 16);
    let tmp = blockIndex;
    for (let j = 15; j >= 8; j--) {
        ctr[j] = tmp & 0xFF;
        tmp >>= 8;
    }
    return ctr;
}

// Decrypt a patch region using AesCtrEx
// Counter (Stratosphere AesCtrCounterExtendedStorage::Read + MakeIv):
//   ctr[0:4] = FsHeader.secure_value BE (FsHeader[0x144:0x148], u32 LE → BE)
//   ctr[4:8] = subEntry.ctrVal BE (generation from BKTR entry, u32 LE → BE)
//   ctr[8:16] = fileOffset/16 BE
export async function decryptPatchRegion(ncaData, titlekey, secureValue, subEntry, fileOffset, size) {
    const result = new Uint8Array(size);
    let pos = 0;
    const counter = new Uint8Array(16);
    const aes = new AesEcb(titlekey);

    // ctr[0:4] = secure_value BE (constant for all blocks)
    counter[0] = (secureValue >> 24) & 0xFF;
    counter[1] = (secureValue >> 16) & 0xFF;
    counter[2] = (secureValue >> 8) & 0xFF;
    counter[3] = secureValue & 0xFF;

    while (pos < size) {
        const chunkEnd = Math.min(pos + 16, size);
        const fileOffsetForBlock = fileOffset + pos;

        // ctr[4:8] = ctrVal BE (constant for this subsection)
        counter[4] = (subEntry.ctrVal >> 24) & 0xFF;
        counter[5] = (subEntry.ctrVal >> 16) & 0xFF;
        counter[6] = (subEntry.ctrVal >> 8) & 0xFF;
        counter[7] = subEntry.ctrVal & 0xFF;

        // ctr[8:16] = blockIndex BE
        const bi = Math.floor(fileOffsetForBlock / 16);
        let tmp = bi;
        for (let j = 15; j >= 8; j--) {
            counter[j] = tmp & 0xFF;
            tmp >>= 8;
        }

        const keystream = aes.encryptBlock(counter);
        const rawBlock = ncaData.subarray(fileOffsetForBlock, fileOffsetForBlock + chunkEnd - pos);
        for (let i = 0; i < chunkEnd - pos; i++) {
            result[pos + i] = rawBlock[i] ^ keystream[i];
        }

        pos += chunkEnd - pos;
    }

    return result;
}

// Load titlekeys from file (format: rights_id = titlekey)
// Returns Map<rights_id_string, Uint8Array>
export async function loadTitlekeysFile(path) {
    try {
        const { readFileSync } = await import('fs');
        const text = readFileSync(path, 'utf-8');
        const map = new Map();
        for (const line of text.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            const eqIdx = trimmed.indexOf('=');
            if (eqIdx === -1) continue;
            const rid = trimmed.substring(0, eqIdx).trim();
            const keyHex = trimmed.substring(eqIdx + 1).trim();
            if (rid.length === 32 && keyHex.length === 32) {
                const bytes = hexToBytes(keyHex);
                map.set(rid, bytes);
            }
        }
        return map;
    } catch {
        return null;
    }
}

// Lookup titlekey from titlekeys database by rights_id
export function lookupTitlekeyFromDatabase(rightsId, titlekeysMap) {
    if (!titlekeysMap || !rightsId) return null;
    // rightsId should be 32-char hex string
    const rid = rightsId.toLowerCase().replace(/\s/g, '');
    return titlekeysMap.get(rid) || null;
}

export function deriveTitlekeyFromKeyArea(decHeader, keys) {
    // Encrypted key area (4 x 16B) at NCA header offset 0x300-0x340.
    // hactool (nca.c:683-686, 532): kaek = key_area_keys[master_key][kaek_ind]
    // (header crypto_type 0,1 -> master key 0, 2 -> mk1, 3 -> mk2; kaek_ind
    // 0/1/2 = application/ocean/system), key area decrypted with AES-128-ECB,
    // titlekey = decrypted entry [2] (bytes 32-48) for CTR-encrypted sections.
    const keyArea = decHeader.subarray(0x300, 0x340);
    if (keyArea.length < 0x40) return null;
    const cryptoType = decHeader[0x206];
    const kaekInd = decHeader[0x207];
    const mk = cryptoType <= 1 ? 0 : cryptoType - 1;
    const kakHex = (keys.keyAreaKeys && keys.keyAreaKeys[mk] && (keys.keyAreaKeys[mk][kaekInd] || keys.keyAreaKeys[mk][0])) || null;
    if (!kakHex) return null;
    const kak = hexToBytes(kakHex);
    const unwrapped = new AesEcb(kak).decrypt(keyArea);
    return unwrapped.subarray(0x20, 0x30);
}

// Extract titlekey from a tik file.
//
// Matches yanu's TitleKey::try_new (sources/yanu crates, yanu_ticket.rs:32-72):
//   RIGHTS_ID_OFFSET = 0x2A0, TITLE_KEY_OFFSET = 0x180.
// Scene tickets are "dummy" (sigType 0x10004, all-0xFF signature, rightsId at 0x10 is
// garbage/all-F) but DO carry a valid rightsId at 0x2A0 (== the NCA header rightsId at
// 0x230) and a titlekek-encrypted titlekey at 0x180. yanu reads them with NO validation
// (it just seek()+read_exact()) and stores "rights_id=key" into title.keys for
// hac2l/hacPack. We therefore also read the rightsId at 0x2A0 for the expectedRightsId
// check and do NOT reject the dummy tickets — the key at 0x180 is real.
export function extractTitlekeyFromTik(tikData, keys, expectedRightsId = null) {
    if (!tikData || tikData.length < 0x2B0) return null;
    const titlekek = keys.titlekek_02 || keys.titlekek_source;
    if (!titlekek) return null;

    // If expectedRightsId provided, verify against tik rights_id at 0x2A0 (yanu offset).
    if (expectedRightsId) {
        const rid = tikData.subarray(0x2A0, 0x2B0);
        const ridStr = Array.from(rid).map(b => b.toString(16).padStart(2, '0')).join('');
        if (ridStr.toLowerCase() !== expectedRightsId.toLowerCase()) {
            return null; // Rights ID mismatch
        }
    }

    const kek = typeof titlekek === 'string' ? hexToBytes(titlekek) : titlekek;
    const ecb = new AesEcb(kek);
    return ecb.decrypt(tikData.subarray(0x180, 0x190));
}

// Decrypt base romfs section using AES-CTR with titlekey
export async function decryptBaseRomfs(baseNcaData, baseRomfsSecMeta, baseDecHeader, baseTitlekey) {
    const romfsSecFsHdrOffset = 0x400 + baseRomfsSecMeta.secIdx * 0x200;
    const baseFsHdr = baseDecHeader.subarray(romfsSecFsHdrOffset, romfsSecFsHdrOffset + 0x200);
    const baseSectionCtrRaw = baseFsHdr.subarray(0x140, 0x148);
    const baseNonce = new Uint8Array(8);
    for (let j = 0; j < 8; j++) baseNonce[j] = baseSectionCtrRaw[7 - j];

    const c = new AesCtr(baseTitlekey, baseNonce);
    c.seek(baseRomfsSecMeta.offset);
    return await c.decrypt(
        baseNcaData.subarray(baseRomfsSecMeta.offset, baseRomfsSecMeta.offset + baseRomfsSecMeta.size)
    );
}
