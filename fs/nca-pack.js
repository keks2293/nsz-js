import { AesXts, AesCtr } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';
import { sha256, SHA256, digest32 } from '../crypto/sha256.js';
import { PFS0, PFS0Writer } from './pfs0.js';
import { hexToBytes, writeU64LE, writeU32LE, NCA_HEADER_SIZE, toKeyBytes, decryptNcaHeaderBytes, resolveTitlekey, reversedSectionCtr, findRomfsFsHeader, MAGIC_IVFC, IVFC_HEADER_SIZE, IVFC_ID, IVFC_MASTER_HASH_SIZE, IVFC_NUM_LEVELS, IVFC_BLOCK_SIZE_LOG2, IVFC_HASH_BLOCK_SIZE, IVFC_HASH_SIZE, IVFC_LEVELS_OFFSET, IVFC_MASTER_HASH_OFFSET, IVFC_MAX_LEVEL, IVFC_LEVEL_HDR, CONTENT_TYPE } from './nca-utils.js';

// Yanu update pipeline uses only:
//   PROGRAM (--plaintext) → ExeFS + RomFS, CRYPT_NONE sections ✅
//   META → PFS0, CRYPT_CTR, XTS header ✅
//
// NOT needed for yanu update:
//   CONTROL/DATA/MANUAL/PUBLICDATA — copied from update container as-is
//   Encrypted sections — yanu uses --plaintext only
//   NCA header RSA signatures — left all-zero (hacpack NCA_SIG_TYPE_ZERO default)
//   NCA0 format — obsolete
//   Sparse storage — not used in modern NCAs
//   Compressed storage — not used in modern NCAs

// ── Helpers ──────────────────────────────────────────────────────────────────

// Pad to 0x200 boundary
function pad200(n) {
    return (n + 0x1FF) & ~0x1FF;
}

// Pad to 0x4000 boundary
function pad4000(n) {
    return (n + 0x3FFF) & ~0x3FFF;
}

// ── NCA section constants (hacpack nca.h) ─────────────────────────────────────
// fs_type / hash_type / crypt_type for the fs_headers[] entries.
const FS_TYPE = { ROMFS: 0x00, PFS0: 0x01 };
const HASH_TYPE = { PFS0: 0x02, ROMFS: 0x03 };
const CRYPT = { NONE: 0x01, CTR: 0x03 };

// ── PFS0 constants (hacpack pfs0.h) ───────────────────────────────────────────
const PFS0_EXEFS_HASH_BLOCK_SIZE = 0x10000;
const PFS0_META_HASH_BLOCK_SIZE = 0x1000;

// ── NCA keygen constants (hacpack settings) ───────────────────────────────────
const KEYAREAKEY = new Uint8Array(16).fill(0x04); // keyareakey — key-area slot 2 + CNMT CTR key
const SDK_VERSION = 0x000C1100;                    // hacpack main.c:116 default

// ── IVFC hash tree ───────────────────────────────────────────────────────────
// 5 hash levels + 1 data level (the romfs image).
// Each hash level hashes 16KB (0x4000) blocks from the level below.
// Each level file is padded to 0x4000 on disk.
//
// IVFC header level_headers[0..5]:
//   [0] = top hash level 0, [1]..[4] = hash levels 1..4, [5] = DATA level
// Each hash_data_size = padded file size for hash levels, = raw romfs size for data.
// Master hash = sha256(entire top hash level-0 file (all 0x4000 bytes)).

// Assemble the 0xE0 IVFC header from the 6 level sizes (write order H5..H1, then
// the data level) + master hash. Shared by the buffered buildIvfcHashTree() and
// the streaming StreamingIvfcHasher so the header bytes can never diverge.
function buildIvfcHeader(dataSizes, masterHash) {
    const ivfcHeader = new Uint8Array(IVFC_HEADER_SIZE);
    const v = new DataView(ivfcHeader.buffer);
    v.setUint32(0, MAGIC_IVFC, true);            // magic
    v.setUint32(4, IVFC_ID, true);               // id
    v.setUint32(8, IVFC_MASTER_HASH_SIZE, true); // master_hash_size
    v.setUint32(12, IVFC_NUM_LEVELS, true);      // num_levels

    let cumulativeOffset = 0;
    for (let lvl = 0; lvl < IVFC_MAX_LEVEL; lvl++) {
        const base = IVFC_LEVELS_OFFSET + lvl * IVFC_LEVEL_HDR.SIZE;
        v.setBigUint64(base + IVFC_LEVEL_HDR.LOGICAL_OFFSET, BigInt(cumulativeOffset), true);
        v.setBigUint64(base + IVFC_LEVEL_HDR.HASH_DATA_SIZE, BigInt(dataSizes[lvl]), true);
        v.setUint32(base + IVFC_LEVEL_HDR.BLOCK_SIZE, IVFC_BLOCK_SIZE_LOG2, true);
        cumulativeOffset += dataSizes[lvl];
    }
    ivfcHeader.set(masterHash, IVFC_MASTER_HASH_OFFSET);
    return ivfcHeader;
}

export function buildIvfcHashTree(romfsData) {
    const numHashLevels = 5;

    // Build hash levels from bottom up (data → hash4 → ... → hash0)
    let currentData = romfsData;
    const allFiles = [romfsData];
    const allSizes = [romfsData.length];

    for (let lvl = 0; lvl < numHashLevels; lvl++) {
        const numBlocks = Math.ceil(currentData.length / IVFC_HASH_BLOCK_SIZE);
        const hashFile = new Uint8Array(numBlocks * IVFC_HASH_SIZE);
        for (let b = 0; b < numBlocks; b++) {
            const blockStart = b * IVFC_HASH_BLOCK_SIZE;
            const blockEnd = Math.min(blockStart + IVFC_HASH_BLOCK_SIZE, currentData.length);
            // The last partial block is zero-padded to blockSize before hashing:
            // Nintendo hashes a full blockSize (blockEnd - blockStart bytes of
            // real data, then zeros up to 0x4000).
            //
            // Confirmed byte-identical against real data:
            //   - Nintendo update: stored lvl4[37011] = sha256(pad4000(final
            //     block)) = 40baee67..., while sha256(unpadded) = df07e695... does
            //     not match.
            //   - yanu/hacPack output for the same game: stored lvl4[37011] =
            //     sha256(pad4000(their final block)) = f04eec97... (also padded).
            //
            // NOTE: hacPack's ivfc_create_level (ivfc.c) itself feeds only the
            // read bytes to sha_update (no padding); the packer must therefore
            // zero-pad each level to a 0x4000 multiple before hashing. We do the
            // padding inline here.
            const block = new Uint8Array(IVFC_HASH_BLOCK_SIZE);
            block.set(currentData.subarray(blockStart, blockEnd));
            const hash = digest32(block);
            hashFile.set(hash, b * IVFC_HASH_SIZE);
        }
        const paddedSize = pad4000(hashFile.length);
        const paddedFile = new Uint8Array(paddedSize);
        paddedFile.set(hashFile);
        allFiles.push(paddedFile);
        allSizes.push(paddedSize);
        currentData = paddedFile;
    }

    // Reverse: [data, h1, h2, h3, h4, h5] -> [h5, h4, h3, h2, h1, data]
    const reversedFiles = allFiles.reverse();
    const reversedSizes = allSizes.reverse();

    // Master hash = sha256(top hash level H5, all 0x4000 bytes)
    const ivfcHeader = buildIvfcHeader(reversedSizes, digest32(reversedFiles[0]));

    // Physical layout: concatenate all level files
    const physicalSize = reversedFiles.reduce((a, f) => a + f.length, 0);

    return { ivfcHeader, levelFiles: reversedFiles, dataSizes: reversedSizes, physicalSize };
}


// ── PFS0 hash table ─────────────────────────────────────────────────────────
// Each block of hash_block_size gets sha256 hash (no zero-padding of last block).
// Hash table is then padded to 0x200 boundary.
// Master hash = sha256 of (hash_table[0..hash_table_size]) — raw hash bytes only.

// Pad the raw hash table to 0x200 and compute the master hash — sha256 of the
// RAW (unpadded) table bytes only. Shared by the buffered buildPfs0HashTable()
// and the streaming StreamingPfs0Hasher.finalize().
function finalizePfs0HashTable(rawHashTable) {
    const paddedSize = pad200(rawHashTable.length);
    const padded = new Uint8Array(paddedSize);
    padded.set(rawHashTable);
    const masterHash = digest32(rawHashTable);
    return { hashTable: padded, rawHashSize: rawHashTable.length, masterHash };
}

export function buildPfs0HashTable(pfs0Data, hashBlock) {
    const hashSize = 0x20;
    const numBlocks = Math.ceil(pfs0Data.length / hashBlock);
    const hashTable = new Uint8Array(numBlocks * hashSize);

    for (let b = 0; b < numBlocks; b++) {
        const blockStart = b * hashBlock;
        const blockEnd = Math.min(blockStart + hashBlock, pfs0Data.length);
        const block = pfs0Data.subarray(blockStart, blockEnd);
        const hash = digest32(block);
        hashTable.set(hash, b * hashSize);
    }

    return finalizePfs0HashTable(hashTable);
}

// ── Streaming IVFC hash tree ─────────────────────────────────────────────────
// Incremental equivalent of buildIvfcHashTree(): feed the romfs data in order via
// update(chunk); finalize() then yields the 5 hash levels (write order H5..H1),
// the IVFC header, the master hash and the physical size — WITHOUT ever holding
// the data. Only level-1 (H1, ~size/0x200000) + one 0x4000 block buffer is kept.
export class StreamingIvfcHasher {
    constructor(dataSize) {
        this.dataSize = dataSize;
        const numBlocks = Math.ceil(dataSize / IVFC_HASH_BLOCK_SIZE);
        this.h1 = new Uint8Array(numBlocks * IVFC_HASH_SIZE);
        this.buf = new Uint8Array(IVFC_HASH_BLOCK_SIZE);
        this.bufLen = 0;
        this.blockIdx = 0;
    }
    update(chunk) {
        let off = 0;
        while (off < chunk.length) {
            const space = IVFC_HASH_BLOCK_SIZE - this.bufLen;
            const n = Math.min(space, chunk.length - off);
            this.buf.set(chunk.subarray(off, off + n), this.bufLen);
            this.bufLen += n;
            off += n;
            if (this.bufLen === IVFC_HASH_BLOCK_SIZE) {
                this.h1.set(digest32(this.buf), this.blockIdx * IVFC_HASH_SIZE);
                this.blockIdx++;
                this.bufLen = 0;
            }
        }
    }
    finalize() {
        if (this.bufLen > 0) {
            const padded = new Uint8Array(IVFC_HASH_BLOCK_SIZE);
            padded.set(this.buf.subarray(0, this.bufLen));
            this.h1.set(digest32(padded), this.blockIdx * IVFC_HASH_SIZE);
            this.blockIdx++;
        }
        // Build H1..H5 (each level = sha256 of 0x4000 blocks of the previous, padded level).
        const levels = [];
        let current = this.h1;
        for (let i = 0; i < 5; i++) {
            const paddedSize = pad4000(current.length);
            const padded = new Uint8Array(paddedSize);
            padded.set(current);
            levels.push(padded);
            const numBlocks = Math.ceil(padded.length / IVFC_HASH_BLOCK_SIZE);
            const next = new Uint8Array(numBlocks * IVFC_HASH_SIZE);
            for (let b = 0; b < numBlocks; b++) {
                next.set(digest32(padded.subarray(b * IVFC_HASH_BLOCK_SIZE, (b + 1) * IVFC_HASH_BLOCK_SIZE)), b * IVFC_HASH_SIZE);
            }
            current = next;
        }
        // levels = [H1, H2, H3, H4, H5]; write order = [H5, H4, H3, H2, H1]
        const hashLevels = [levels[4], levels[3], levels[2], levels[1], levels[0]];
        const dataSizes = [levels[4].length, levels[3].length, levels[2].length, levels[1].length, levels[0].length, this.dataSize];
        const masterHash = digest32(levels[4]);
        const ivfcHeader = buildIvfcHeader(dataSizes, masterHash);
        const physicalSize = dataSizes.reduce((a, b) => a + b, 0);
        return { hashLevels, dataSizes, masterHash, ivfcHeader, physicalSize };
    }
}

// ── Streaming PFS0 hash table ────────────────────────────────────────────────
// Incremental equivalent of buildPfs0HashTable(): feed the PFS0 data in order via
// update(chunk); finalize() yields the (padded) hash table + master hash. The last
// partial block is hashed as-is (NO zero-padding), matching buildPfs0HashTable.
export class StreamingPfs0Hasher {
    constructor(hashBlock = PFS0_EXEFS_HASH_BLOCK_SIZE) {
        this.hashBlock = hashBlock;
        this.hashSize = 0x20;
        this.buf = new Uint8Array(hashBlock);
        this.bufLen = 0;
        this._hashBuf = new Uint8Array(4096);
        this._hashCount = 0;
    }
    update(chunk) {
        let off = 0;
        while (off < chunk.length) {
            const space = this.hashBlock - this.bufLen;
            const n = Math.min(space, chunk.length - off);
            this.buf.set(chunk.subarray(off, off + n), this.bufLen);
            this.bufLen += n;
            off += n;
            if (this.bufLen === this.hashBlock) {
                this._writeHash(digest32(this.buf));
                this.bufLen = 0;
            }
        }
    }
    _writeHash(h) {
        const need = (this._hashCount + 1) * this.hashSize;
        if (need > this._hashBuf.length) {
            const grown = new Uint8Array(this._hashBuf.length * 2);
            grown.set(this._hashBuf.subarray(0, this._hashCount * this.hashSize));
            this._hashBuf = grown;
        }
        this._hashBuf.set(h, this._hashCount * this.hashSize);
        this._hashCount++;
    }
    finalize() {
        if (this.bufLen > 0) {
            this._writeHash(digest32(this.buf.subarray(0, this.bufLen)));
        }
        const hashTable = this._hashBuf.subarray(0, this._hashCount * this.hashSize);
        return finalizePfs0HashTable(hashTable);
    }
}

// ── FsHeader builders ────────────────────────────────────────────────────────
// nca_fs_header_t layout (from nca.h):
//   version(u16) @0x00, fs_type(u8) @0x02, hash_type(u8) @0x03,
//   crypt_type(u8) @0x04, _0x5[3] @0x05,
//   superblock(union) @0x08 (0x138 bytes),
//   section_ctr[8] @0x140, _0x148[0xB8] @0x148  → total 0x200

// Common part of both FsHeader variants: version=2, fs_type, hash_type,
// crypt_type. The buffer is fresh (already zero), so _0x5, the unused
// superblock tail and section_ctr need no explicit fills.
function buildFsHeader(fsType, hashType, cryptType) {
    const fh = new Uint8Array(0x200);
    const v = new DataView(fh.buffer);
    v.setUint16(0, 2, true);   // version
    fh[0x02] = fsType;
    fh[0x03] = hashType;
    fh[0x04] = cryptType;
    return fh;
}

function buildPfs0FsHeader(cryptType) { return buildFsHeader(FS_TYPE.PFS0, HASH_TYPE.PFS0, cryptType); }
function buildRomfsFsHeader(cryptType) { return buildFsHeader(FS_TYPE.ROMFS, HASH_TYPE.ROMFS, cryptType); }

// ── Shared NCA header helpers ────────────────────────────────────────────────

// Fill PFS0 superblock fields in an ExeFS/RomFS FsHeader.
// Offsets: 0x08=master_hash, 0x28=block_size, 0x2C=always_2,
// 0x38=hash_table_size, 0x40=pfs0_offset, 0x48=pfs0_size.
function fillPfs0Superblock(fh, masterHash, { blockSize, hashTableSize, pfs0Offset, pfs0Size }) {
    const ev = new DataView(fh.buffer);
    fh.set(masterHash, 0x08);
    ev.setUint32(0x28, blockSize, true);
    ev.setUint32(0x2C, 2, true);
    ev.setBigUint64(0x38, BigInt(hashTableSize), true);
    ev.setBigUint64(0x40, BigInt(pfs0Offset), true);
    ev.setBigUint64(0x48, BigInt(pfs0Size), true);
}

// Compute section hashes (sha256 of each 0x200-byte FsHeader) and place in NCA header.
function fillSectionHashes(header) {
    header.set(digest32(header.subarray(0x400, 0x600)), 0x280);
    header.set(digest32(header.subarray(0x600, 0x800)), 0x2A0);
}

// XTS-encrypt the NCA header with header_key.
function encryptNcaHeader(header, keys) {
    return new AesXts(toKeyBytes(keys.header_key)).encrypt(header);
}

// ── NCA header builder ───────────────────────────────────────────────────────
// nca_header_t layout (from nca.h):
//   fixed_key_sig[0x100] @0x00 — RSA sig 1 (fixed key)
//   npdm_key_sig[0x100] @0x100 — RSA sig 2 (NPDM ACID key)
//   magic(NCA3) @0x200
//   distribution(u8, 0) @0x204
//   content_type(u8) @0x205
//   crypto_type(u8, 0=kg1) @0x206
//   kaek_ind(u8) @0x207
//   nca_size(u64) @0x208
//   title_id(u64) @0x210
//   _0x218[4] padding @0x218
//   sdk_version(u32) @0x21C
//   crypto_type2(u8) @0x220
//   _0x221[0xF] padding
//   rights_id[0x10] @0x230 (all zeros — no titlekey)
//   section_entries[4] @0x240
//   section_hashes[4][0x20] @0x280
//   encrypted_keys[4][0x10] @0x300
//   _0x340[0xC0] padding
//   fs_headers[4] @0x400
//
// Signature policy: repacked NCAs always ship with BOTH sig regions zeroed
// (hacpack NCA_SIG_TYPE_ZERO, yanu parity) — that is the only sig mode here.
// NCAs copied verbatim (merge/convert/update's other members) keep their
// original headers and never go through this function.
// NOT to confuse with the ACID key pair INSIDE main.npdm (ExeFS content) — a
// different region, zeroed by processNpdmAcid()/createExefsAcidFilter().
//
// Keygen policy: repacked NCAs are always keygen 1 — crypto_type(0x206),
// kaek_ind(0x207) and crypto_type2(0x220) all stay zero. These fields do not
// mean "no encryption"; they are the tag selecting which fixed prod.keys key
// decrypts this NCA, so the tag must match the header_key we XTS-encrypt with
// (encryptNcaHeader()/decryptNcaHeaderBytes() — the only header key in this
// toolchain). The update path packs sections CRYPT_NONE (hacpack --plaintext),
// so no titlekey is involved, and the key area is the hacpack --plaintext
// standard: slot 2 = keyareakey (0x04*16), ECB key_area_key_application_00
// (nca.c:399-401, 774-779). keygen 2+ (hacpack nca_set_keygen, nca.c:893)
// would require header_key_2 — out of scope here.
//
// The buffer is fresh (zero by spec); the explicit sig fill below stays as the
// visible statement of the zero-sig decision. Other zero regions (padding,
// rights_id, unused section hashes) rely on the fresh allocation.

function buildNcaHeader(titleId, sections, keys, contentType = CONTENT_TYPE.PROGRAM) {
    const header = new Uint8Array(NCA_HEADER_SIZE);

    // fixed_key_sig + npdm_key_sig = all zeros (The-4n/hacPack default)
    header.fill(0, 0, 0x200);

    // Magic: "NCA3"
    header[0x200] = 0x4E; header[0x201] = 0x43; header[0x202] = 0x41; header[0x203] = 0x33;
    // distribution = 0 (not gamecard)
    header[0x204] = 0x00;
    // content_type (CONTENT_TYPE)
    header[0x205] = contentType;
    // crypto_type(0x206)/kaek_ind(0x207)/crypto_type2(0x220) stay zero — keygen 1
    // (keygen policy above; fresh buffer)
    // title_id (big-endian u64)
    const tidBytes = hexToBytes(titleId.toLowerCase());
    const tidRev = new Uint8Array(8);
    for (let i = 0; i < 8; i++) tidRev[i] = tidBytes[7 - i];
    header.set(tidRev, 0x210);
    // sdk_version (hacpack main.c:116 default)
    const hv = new DataView(header.buffer, header.byteOffset);
    hv.setUint32(0x21C, SDK_VERSION, true);
    // rights_id [0x230..0x240) stays zero (fresh buffer, no titlekey)

    // Section entries
    const validSecs = sections.filter(s => s.size > 0);
    for (let i = 0; i < validSecs.length; i++) {
        const base = 0x240 + i * 0x10;
        const sec = validSecs[i];
        writeU32LE(header, base, Math.floor(sec.offset / 0x200));
        writeU32LE(header, base + 4, Math.floor(sec.endOffset / 0x200));
        header[base + 8] = 0x01; // _0x8[0] = 1 (hacPack always sets this)
    }

    // Section hashes [0x280..0x300): stay zero here — fillSectionHashes()
    // writes slots 0/1 later; slots 2/3 remain zero (fresh buffer).

    // Key area: encrypted_keys[4][0x10]
    // Default: [0, 0, KEYAREAKEY, 0]
    const keyBlock = new Uint8Array(0x40);
    keyBlock.set(KEYAREAKEY, 0x20); // slot 2 = keyareakey

    // ECB-encrypt entire key block with key_area_key_application_00
    const ecb = new AesEcb(toKeyBytes(keys.key_area_key_application_00));
    const encKeyBlock = new Uint8Array(0x40);
    for (let blk = 0; blk < 4; blk++) {
        const chunk = keyBlock.subarray(blk * 0x10, (blk + 1) * 0x10);
        encKeyBlock.set(ecb.encrypt(chunk), blk * 0x10);
    }
    header.set(encKeyBlock, 0x300);

    // _0x340[0xC0] padding = all zeros (already zeroed)

    // FsHeaders — filled by caller

    return header;
}

// Build + XTS-encrypt a (plaintext) Program NCA header: ExeFS (PFS0) FsHeader 0
// + RomFS (IVFC) FsHeader 1 + section hashes + NCA size. Shared by all Program
// NCA packers (buffered, prepared, streaming, two-pass) so the header layout
// cannot drift between them. Section 0 (ExeFS) always starts at the header end
// (NCA_HEADER_SIZE); section sizes fully determine the layout.
function buildEncryptedProgramNcaHeader({ titleId, keys, exeHash, exePfs0Offset, exefsSize, romIvfc, exeSectionSize, romSectionSize }) {
    const sec0Start = NCA_HEADER_SIZE;
    const sec0End = sec0Start + exeSectionSize;
    const sec1Start = sec0End;
    const sec1End = sec1Start + romSectionSize;
    const ncaSize = sec1End;
    const header = buildNcaHeader(titleId, [
        { offset: sec0Start, endOffset: sec0End, size: exeSectionSize },
        { offset: sec1Start, endOffset: sec1End, size: romSectionSize },
    ], keys);
    const exeFsHeader = buildPfs0FsHeader(CRYPT.NONE);
    fillPfs0Superblock(exeFsHeader, exeHash.masterHash, {
        blockSize: PFS0_EXEFS_HASH_BLOCK_SIZE, hashTableSize: exeHash.rawHashSize,
        pfs0Offset: exePfs0Offset, pfs0Size: exefsSize,
    });
    header.set(exeFsHeader, 0x400);
    const romFsHeader = buildRomfsFsHeader(CRYPT.NONE);
    romFsHeader.set(romIvfc.ivfcHeader, 0x08);
    header.set(romFsHeader, 0x600);
    fillSectionHashes(header);
    writeU64LE(header, 0x208, ncaSize);
    return encryptNcaHeader(header, keys);
}

// ── Main: packPlaintextProgramNca ────────────────────────────────────────────
// Layout (matching hacPack --plaintext):
//   Header (0xC00, XTS-encrypted)
//   Section 0: ExeFS = PFS0(hash_table + PFS0 data)
//   Section 1: RomFS = IVFC(5 hash levels + romfs data)
// Each section padded to 0x200.

export async function packPlaintextProgramNca(exefsData, romfsData, controlData, titleId, keys, log) {
    const _log = typeof log === 'function' ? log : () => {};
    _log('info', '----> Creating Program NCA:');

    // Reuse the shared hash/layout/header computation (identical bytes to
    // preparePlaintextProgramNca), then assemble the full NCA buffer.
    const prepared = await preparePlaintextProgramNca(exefsData, romfsData, controlData, titleId, keys, log);
    const { encHeader, exeHtablePadded, exePfs0Offset, exefsData: exefs, romIvfc,
            sec0Start, exePaddingSize } = prepared.data;
    const ncaSize = prepared.size;

    // ── Assemble NCA: header + sections ────────────────────────────────────
    _log('info', '  Assembling NCA: header + sections...');
    const nca = new Uint8Array(ncaSize);
    nca.set(encHeader, 0);

    // Section 0: ExeFS = hash_table + PFS0 data (+ padding zeros)
    nca.set(exeHtablePadded, sec0Start);
    nca.set(exefs, sec0Start + exePfs0Offset);

    // Section 1: RomFS = level files concatenated (starts at end of ExeFS section)
    let romPos = sec0Start + exeHtablePadded.length + exefs.length + exePaddingSize;
    for (let lvl = 0; lvl < romIvfc.levelFiles.length; lvl++) {
        nca.set(romIvfc.levelFiles[lvl], romPos);
        romPos += romIvfc.levelFiles[lvl].length;
    }

    _log('info', '  ----> Created Program NCA: ' + ncaSize + ' bytes sha256=' + prepared.hashHex);
    return nca;
}

// ── packMetaNca (hacpack create_meta mode) ──────────────────────────────────
// Builds a CNMT NCA: content_type=1 (Meta), PFS0 section, CRYPT_CTR encrypted
// with keyareakey (0x04*16), XTS-encrypted header.
// Matches The-4n/hacPack: nca_create_meta(), plaintext=0.

export async function packMetaNca(cnmtData, pfs0FileName, titleId, keys, log) {
    const _log = typeof log === 'function' ? log : () => {};
    _log('info', '  Building Meta (CNMT) NCA...');

    // ── PFS0 with single CNMT file ─────────────────────────────────────────
    const pw = new PFS0Writer(true);
    pw.add(pfs0FileName, cnmtData.length);
    const pfs0Header = pw.buildHeader();
    const newPfs0 = new Uint8Array(pfs0Header.headerSize + cnmtData.length);
    newPfs0.set(pfs0Header.buffer, 0);
    newPfs0.set(cnmtData, pfs0Header.headerSize);

    // ── PFS0 hash table (PFS0_META_HASH_BLOCK_SIZE) ─────────────────────────
    const pfs0Hash = buildPfs0HashTable(newPfs0, PFS0_META_HASH_BLOCK_SIZE);
    const htablePadded = pfs0Hash.hashTable;
    const pfs0Offset = htablePadded.length; // = 0x200
    const pfs0Size = newPfs0.length;
    const masterHash = pfs0Hash.masterHash;

    // ── Section layout ─────────────────────────────────────────────────────
    const sectionDataSize = pad200(pfs0Offset + pfs0Size);
    const sectionStart = 0xC00;
    const sectionEnd = sectionStart + sectionDataSize;
    const ncaSize = sectionEnd; // header(0xC00) + section

    _log('info', `  CNMT section: htable=${htablePadded.length} B, PFS0=${pfs0Size} B, total=${sectionDataSize} B, NCA=${ncaSize} B`);

    // ── FsHeader (PFS0, CRYPT_CTR) ─────────────────────────────────────────
    const fsHeader = buildPfs0FsHeader(CRYPT.CTR);
    fillPfs0Superblock(fsHeader, masterHash, {
        blockSize: PFS0_META_HASH_BLOCK_SIZE, hashTableSize: pfs0Hash.rawHashSize,
        pfs0Offset, pfs0Size,
    });

    // ── NCA header (content_type = Meta) ────────────────────────────────────
    const header = buildNcaHeader(titleId, [
        { offset: sectionStart, endOffset: sectionEnd, size: sectionDataSize },
    ], keys, CONTENT_TYPE.META);
    writeU64LE(header, 0x208, ncaSize);
    header.set(digest32(fsHeader), 0x280);
    header.set(fsHeader, 0x400);

    // ── Section data (CTR-encrypted) ───────────────────────────────────────
    const secDec = new Uint8Array(sectionDataSize);
    secDec.set(htablePadded, 0);
    secDec.set(newPfs0, pfs0Offset);
    const zerosNonce = new Uint8Array(8);
    const ctrEnc = new AesCtr(KEYAREAKEY, zerosNonce);
    ctrEnc.seek(sectionStart);
    const secEnc = await ctrEnc.encrypt(secDec);

    // ── Assemble + XTS header encryption ───────────────────────────────────
    const nca = new Uint8Array(ncaSize);
    nca.set(header, 0);
    nca.set(secEnc, sectionStart);
    nca.set(encryptNcaHeader(nca.subarray(0, NCA_HEADER_SIZE), keys), 0);

    const finalHash = sha256(nca);
    _log('info', `  CNMT NCA: ${ncaSize} bytes sha256=${finalHash}`);
    return { nca, name: `${finalHash.slice(0, 32)}.cnmt.nca` };
}

// ── Unused features (documented stubs) ────────────────────────────────────────
// These are NOT needed for yanu's update pipeline and are not implemented:
//
// 1. Encrypted NCAs (non-plaintext):
//    hacpack: --plaintext flag skipped → sections encrypted with AES-CTR(titlekey)
//    yanu: always uses --plaintext → sections plaintext, FsHeader.cryptType=CRYPT_NONE
//    Our code: only packPlaintextProgramNca implemented
//
// 2. NCA header signatures (fixed_key_sig @0x00, npdm_key_sig @0x100):
//    hacpack: can RSA-sign (sig 1 / sig 2); default NCA_SIG_TYPE_ZERO leaves both
//    all-zero. yanu keeps that default → we do the same; see the signature-policy
//    block above buildNcaHeader (the only sig mode we implement).
//
// 3. NCA0/NCA0_BETA format:
//    hacpack: not supported (NCA3 only)
//    yanu: not used (modern NCAs are NCA3)
//    Our code: only NCA3 (magic=0x4E434133)
//
// 4. Sparse storage (FsHeader.sparse_info):
//    Stratosphere: SparseStorage wraps data storage with bucket tree
//    yanu: not used in modern NCAs
//    Our code: not implemented
//
// 5. Compressed storage (FsHeader.compression_info):
//    Stratosphere: CompressedStorage for lz4-compressed sections
//    yanu: not used in modern NCAs
//    Our code: not implemented

// Accept either a full NCA buffer (Uint8Array) or an NcaInput
// { headerRaw: Uint8Array(0xC00), source: RangeSource }.
function ncaHeaderRaw(nca) {
    if (nca && nca.source) return nca.headerRaw;
    return nca.subarray(0, NCA_HEADER_SIZE);
}
async function ncaRead(nca, offset, length) {
    if (nca && nca.source) return await nca.source.read(offset, length);
    return nca.subarray(offset, offset + length);
}

// ── Section metadata + streaming helpers ────────────────────────────────────

function parseExefsSectionMeta(ncaData, keys, tikData) {
    const decHeader = decryptNcaHeaderBytes(ncaHeaderRaw(ncaData), keys);
    const titlekey = resolveTitlekey(tikData, decHeader, keys);

    const exeFsFsHdr = decHeader.subarray(0x400, 0x600);
    const sectionCtrRev = reversedSectionCtr(exeFsFsHdr);

    const sectionStart = Number(new DataView(exeFsFsHdr.buffer, exeFsFsHdr.byteOffset + 0x40, 8).getBigUint64(0, true));
    const sectionSize = Number(new DataView(exeFsFsHdr.buffer, exeFsFsHdr.byteOffset + 0x48, 8).getBigUint64(0, true));

    const mediaOffset = Number(new DataView(decHeader.buffer, decHeader.byteOffset + 0x240, 4).getUint32(0, true));
    const sectionOffset = mediaOffset * 0x200;

    return { titlekey, sectionCtrRev, sectionOffset, sectionStart, sectionSize };
}

function parseRomfsSectionMeta(ncaData, keys, tikData) {
    const decHeader = decryptNcaHeaderBytes(ncaHeaderRaw(ncaData), keys);
    const titlekey = resolveTitlekey(tikData, decHeader, keys);

    const { idx: romfsIdx, fsHdr: romfsFsHdr } = findRomfsFsHeader(decHeader, 'extractRomfs');
    const sectionCtrRev = reversedSectionCtr(romfsFsHdr);

    const mediaOffset = new DataView(decHeader.buffer, decHeader.byteOffset + 0x240 + romfsIdx * 0x10, 4).getUint32(0, true);
    const mediaEnd = new DataView(decHeader.buffer, decHeader.byteOffset + 0x240 + romfsIdx * 0x10 + 4, 4).getUint32(0, true);
    const sectionOffset = mediaOffset * 0x200;
    const mediaSize = mediaEnd * 0x200 - sectionOffset;

    return { titlekey, sectionCtrRev, sectionOffset, mediaSize };
}

async function streamNcaSection(ncaData, offset, size, titlekey, ctrRev, onChunk) {
    if (!titlekey || size === 0) {
        let done = 0;
        while (done < size) {
            const n = Math.min(0x100000, size - done);
            const raw = await ncaRead(ncaData, offset + done, n);
            await onChunk(raw, done);
            done += n;
        }
        return size;
    }

    const c = new AesCtr(titlekey, ctrRev);
    c.seek(offset);
    let done = 0;
    while (done < size) {
        const n = Math.min(0x100000, size - done);
        const cipher = await ncaRead(ncaData, offset + done, n);
        const dec = await c.decrypt(cipher);
        await onChunk(dec, done);
        done += n;
    }
    return size;
}

// ── extractExefs / extractRomfs ─────────────────────────────────────────────

export async function extractExefs(ncaData, keys, tikData = null) {
    const { titlekey, sectionCtrRev, sectionOffset, sectionStart, sectionSize } = parseExefsSectionMeta(ncaData, keys, tikData);

    const raw = await ncaRead(ncaData, sectionOffset, sectionStart + sectionSize);

    if (!titlekey || sectionSize === 0) {
        return raw.subarray(sectionStart, sectionStart + sectionSize);
    }

    const c = new AesCtr(titlekey, sectionCtrRev);
    c.seek(sectionOffset);
    const decrypted = await c.decrypt(raw);
    return decrypted.subarray(sectionStart, sectionStart + sectionSize);
}

// Streaming variant: feeds the ExeFS PFS0 data to onChunk(chunk, offInData)
// instead of returning one big buffer.
export async function extractExefsStream(ncaData, keys, tikData, onChunk) {
    const { titlekey, sectionCtrRev, sectionOffset, sectionStart, sectionSize } = parseExefsSectionMeta(ncaData, keys, tikData);
    return streamNcaSection(ncaData, sectionOffset + sectionStart, sectionSize, titlekey, sectionCtrRev, onChunk);
}

export async function extractRomfs(ncaData, keys, tikData = null) {
    const { titlekey, sectionCtrRev, sectionOffset, mediaSize } = parseRomfsSectionMeta(ncaData, keys, tikData);

    const raw = await ncaRead(ncaData, sectionOffset, mediaSize);
    if (!titlekey || mediaSize === 0) return raw;

    const c = new AesCtr(titlekey, sectionCtrRev);
    c.seek(sectionOffset);
    const decrypted = await c.decrypt(raw);
    return decrypted;
}

export async function extractRomfsStream(ncaData, keys, tikData, onChunk) {
    const { titlekey, sectionCtrRev, sectionOffset, mediaSize } = parseRomfsSectionMeta(ncaData, keys, tikData);
    return streamNcaSection(ncaData, sectionOffset, mediaSize, titlekey, sectionCtrRev, onChunk);
}

// ── NPDM ACID zeroing (hacpack parity) ───────────────────────────────────────
// NOTE: this is the ACID key pair INSIDE main.npdm (ExeFS content) — NOT the
// npdm_key_sig field of the NCA header (a different region; see buildNcaHeader).
// When packing a Program NCA, hacpack (The-4n, v1.36) zeros the ACID
// signature + key in main.npdm by default: signature[0x100] + modulus[0x100]
// starting at acid_offset (NPDM header field at +0x78). Its opt-out flags
// --nozeronpdmsig / --nozeroacidkey keep them. We mirror that: zero both by
// default, keep either via opts.keepSig / opts.keepKey.
// The ACID is not enforced for plaintext/dev NCAs (integrity comes from the
// IVFC hash trees), so zeroing is harmless and matches the reference output.
export function processNpdmAcid(exefsData, opts = {}, log = () => {}) {
    const _log = typeof log === 'function' ? log : () => {};
    const { keepSig = false, keepKey = false } = opts;
    if (keepSig && keepKey) return exefsData;

    const pfs0 = new PFS0(exefsData);
    const npdm = pfs0.getFiles().find(f => f.name === 'main.npdm');
    if (!npdm) {
        _log('warn', 'processNpdmAcid: main.npdm not found in ExeFS — skipping');
        return exefsData;
    }

    const view = new DataView(exefsData.buffer, exefsData.byteOffset);
    const acidOffset = view.getUint32(npdm.offset + 0x78, true);
    const sigStart = npdm.offset + acidOffset;
    if (!keepSig) {
        exefsData.fill(0, sigStart, sigStart + 0x100);
        _log('info', `  Zeroed ACID signature in main.npdm (0x${acidOffset.toString(16)}..0x${(acidOffset + 0x100).toString(16)})`);
    }
    if (!keepKey) {
        exefsData.fill(0, sigStart + 0x100, sigStart + 0x200);
        _log('info', `  Zeroed ACID key in main.npdm (0x${(acidOffset + 0x100).toString(16)}..0x${(acidOffset + 0x200).toString(16)})`);
    }
    return exefsData;
}

// Streaming equivalent of processNpdmAcid(): returns an async filter(chunk, off)
// to run over the ExeFS PFS0 data stream. It locates main.npdm from the PFS0 header
// (first chunk), reads acid_offset from the npdm header (+0x78), and zeroes the
// ACID region [sigStart, sigStart+0x200) in place as it streams by — so the ExeFS
// is never buffered. Respects keepSig/keepKey exactly like processNpdmAcid.
export function createExefsAcidFilter(opts = {}, log = () => {}) {
    const _log = typeof log === 'function' ? log : () => {};
    const keepSig = opts.keepSig === true;
    const keepKey = opts.keepKey === true;
    if (keepSig && keepKey) return async () => {};
    let npdmOffset = -1;   // -1 unknown, -2 = no main.npdm
    let sigStart = -1;
    let pfs0Parsed = false;
    return async function filter(chunk, off) {
        if (!pfs0Parsed) {
            if (off !== 0) return;
            pfs0Parsed = true;
            const pfs0 = new PFS0(chunk);
            const npdm = pfs0.getFiles().find(f => f.name === 'main.npdm');
            if (!npdm) {
                _log('warn', 'processNpdmAcid: main.npdm not found in ExeFS — skipping');
                npdmOffset = -2;
                return;
            }
            npdmOffset = npdm.offset;
            if (npdmOffset + 0x7C <= chunk.length) {
                const v = new DataView(chunk.buffer, chunk.byteOffset + npdmOffset + 0x78, 4);
                sigStart = npdmOffset + v.getUint32(0, true);
                _log('info', `  ACID (stream): main.npdm @0x${npdmOffset.toString(16)}, region @0x${sigStart.toString(16)}..0x${(sigStart + 0x200).toString(16)}`);
            }
        } else if (npdmOffset !== -2 && sigStart < 0) {
            // npdm header not in the first chunk — read acid_offset when it arrives.
            const hdrEnd = npdmOffset + 0x7C;
            if (off <= npdmOffset && off + chunk.length >= hdrEnd) {
                const local = npdmOffset + 0x78 - off;
                const v = new DataView(chunk.buffer, chunk.byteOffset + local, 4);
                sigStart = npdmOffset + v.getUint32(0, true);
                _log('info', `  ACID (stream): region @0x${sigStart.toString(16)}..0x${(sigStart + 0x200).toString(16)}`);
            }
        }
        if (npdmOffset === -2 || sigStart < 0) return;
        // Zero the ACID region [sigStart, sigStart+0x200) in place as it streams by.
        const regionEnd = sigStart + 0x200;
        const a = Math.max(off, sigStart);
        const b = Math.min(off + chunk.length, regionEnd);
        if (b <= a) return;
        const sigEnd = sigStart + 0x100;
        if (!keepSig) {
            const s0 = Math.max(a, sigStart), s1 = Math.min(b, sigEnd);
            if (s1 > s0) chunk.fill(0, s0 - off, s1 - off);
        }
        if (!keepKey) {
            const k0 = Math.max(a, sigEnd), k1 = Math.min(b, regionEnd);
            if (k1 > k0) chunk.fill(0, k0 - off, k1 - off);
        }
    };
}

// ── Streaming NCA pack ───────────────────────────────────────────────────────
// Writes NCA to output adapter instead of buffering in memory.
// Output adapter: { write(offset, data), size }
// Returns: { hashHex, size } — hash of the full NCA (computed during write)
//
// Two-pass approach:
//   Pass 1: compute IVFC hash tree + PFS0 hash table (RomFS/ExeFS already in memory)
//   Pass 2: write NCA header (with zeros for hashes) + sections via adapter.write()
//   Pass 3: compute section hashes → patch header via adapter.seek/write (disk) or
//           adapter.write at offset 0 (memory)
//
// For disk/CLI: adapter must support write(offset, data) for seek-back header patch.
// For SW/memory: adapter handles offset-based writes (Blob assembly, etc).

// Prepares a plaintext Program NCA and returns its full NCA hash WITHOUT writing
// anything. The hash is deterministic (depends only on exefsData, romfsData,
// titleId and keys) — this lets callers learn the real `<contentId>.nca` name
// before building the PFS0 header, so no seek-back is needed.
//
// Returns: { data, hashHex, size } where `data` holds everything needed by
// `writePlaintextProgramNca()`.
export async function preparePlaintextProgramNca(exefsData, romfsData, controlData, titleId, keys, log) {
    const _log = typeof log === 'function' ? log : () => {};
    _log('info', '----> Preparing Program NCA:');

    // ── Pass 1: Compute hashes (same as buffer version) ────────────────────
    _log('info', '  Computing ExeFS PFS0 hash table...');
    const exeHash = buildPfs0HashTable(exefsData, PFS0_EXEFS_HASH_BLOCK_SIZE);
    const exeHtablePadded = exeHash.hashTable;
    const exePfs0Offset = exeHtablePadded.length;
    const exeSectionSize = pad200(exePfs0Offset + exefsData.length);

    _log('info', '  Computing IVFC hash tree (5 levels + data)...');
    const romIvfc = buildIvfcHashTree(romfsData);
    // Pad RomFS data level to 0x4000 (IVFC_HASH_BLOCK_SIZE) to match Nintendo's canonical
    // layout (base NCA data level is 0x4000-aligned) and hacpack (romfs_build pads to
    // IVFC_HASH_BLOCK_SIZE). pad200 left it 0x200-aligned.
    const romSectionSize = pad4000(romIvfc.physicalSize);

    // ── Section layout ─────────────────────────────────────────────────────
    const sec0Start = NCA_HEADER_SIZE;
    const sec0End = sec0Start + exeSectionSize;
    const sec1Start = sec0End;
    const sec1End = sec1Start + romSectionSize;
    const ncaSize = sec1End;

    _log('info', `  NCA layout: header=0x${NCA_HEADER_SIZE.toString(16)}, ExeFS=0x${exeSectionSize.toString(16)}, RomFS=0x${romSectionSize.toString(16)}, total=0x${ncaSize.toString(16)} (${ncaSize} bytes)`);

    // ── Build NCA header (shared helper, XTS-encrypted) ───────────────────
    _log('info', '  Building NCA header...');
    const encHeader = buildEncryptedProgramNcaHeader({
        titleId, keys, exeHash, exePfs0Offset, exefsSize: exefsData.length, romIvfc,
        exeSectionSize, romSectionSize,
    });

    // ── Compute full NCA hash (sha256 over header + all section bytes) ─────
    const ncaHasher = new SHA256();
    ncaHasher.update(encHeader);
    ncaHasher.update(exeHtablePadded);
    ncaHasher.update(exefsData);

    // Hash ExeFS section padding (zeros between ExeFS data end and RomFS start)
    const exePaddingSize = exeSectionSize - (exePfs0Offset + exefsData.length);
    if (exePaddingSize > 0) {
        ncaHasher.update(new Uint8Array(exePaddingSize));
    }

    // Hash RomFS section: IVFC levels concatenated
    for (const levelData of romIvfc.levelFiles) {
        ncaHasher.update(levelData);
    }

    // Hash RomFS section trailing padding (zeros after RomFS data to align to 0x200)
    const romPaddingSize = romSectionSize - romIvfc.physicalSize;
    if (romPaddingSize > 0) {
        ncaHasher.update(new Uint8Array(romPaddingSize));
    }

    _log('info', '  Calculating NCA hash...');
    const hashHex = ncaHasher.hex();
    _log('info', '  ----> Prepared Program NCA: ' + ncaSize + ' bytes sha256=' + hashHex);

    return {
        data: {
            encHeader, exeHtablePadded, exePfs0Offset, exefsData, romIvfc,
            sec0Start, exePaddingSize, romPaddingSize,
        },
        hashHex, size: ncaSize,
    };
}

// Writes a previously prepared plaintext Program NCA to the output adapter.
// The bytes written are byte-identical to what `preparePlaintextProgramNca`
// hashed, so `prepared.hashHex` remains valid.
export async function writePlaintextProgramNca(prepared, outputAdapter, log, baseOffset = 0) {
    const _log = typeof log === 'function' ? log : () => {};
    const { encHeader, exeHtablePadded, exePfs0Offset, exefsData, romIvfc,
            sec0Start, exePaddingSize, romPaddingSize } = prepared.data;
    _log('info', '  Writing NCA to output adapter (streaming)...');

    // Snapshot all lengths BEFORE any writes — postMessage transfer can
    // detach buffers, making .length return 0 for full-buffer Uint8Arrays.
    const htableLen = exeHtablePadded.length;
    const exefsLen = exefsData.length;

    // Write header (at baseOffset)
    await outputAdapter.write(baseOffset, encHeader);

    // Write ExeFS section: hash_table + PFS0 data + section padding
    await outputAdapter.write(baseOffset + sec0Start, exeHtablePadded);
    await outputAdapter.write(baseOffset + sec0Start + exePfs0Offset, exefsData);
    if (exePaddingSize > 0) {
        await outputAdapter.write(baseOffset + sec0Start + exePfs0Offset + exefsLen,
            new Uint8Array(exePaddingSize));
    }

    // Write RomFS section: IVFC levels concatenated
    // Snapshot level lengths BEFORE writing — postMessage transfer detaches buffers,
    // making .length return 0 for full-buffer Uint8Arrays.
    const levelLengths = romIvfc.levelFiles.map(l => l.length);
    let romPos = sec0Start + htableLen + exefsLen + exePaddingSize;
    for (let lvl = 0; lvl < romIvfc.levelFiles.length; lvl++) {
        const levelData = romIvfc.levelFiles[lvl];
        await outputAdapter.write(baseOffset + romPos, levelData);
        romPos += levelLengths[lvl];
    }
    if (romPaddingSize > 0) {
        await outputAdapter.write(baseOffset + romPos, new Uint8Array(romPaddingSize));
    }
}

export async function packPlaintextProgramNcaStreaming(exefsData, romfsData, controlData, titleId, keys, outputAdapter, log, baseOffset = 0) {
    const _log = typeof log === 'function' ? log : () => {};
    _log('info', '----> Creating Program NCA (streaming):');
    const prepared = await preparePlaintextProgramNca(exefsData, romfsData, controlData, titleId, keys, log);
    await writePlaintextProgramNca(prepared, outputAdapter, log, baseOffset);
    _log('info', '  ----> Created Program NCA: ' + prepared.size + ' bytes sha256=' + prepared.hashHex);
    return { hashHex: prepared.hashHex, size: prepared.size };
}

// ── Fully streaming Program NCA pack (seekable output, no data buffer) ─────────
// Avoids holding the NCA (or the romfs/exefs data) as a single ArrayBuffer — the
// payload is written straight to the output adapter via streamExefs/streamRomfs,
// feeding StreamingPfs0Hasher / StreamingIvfcHasher. The hash metadata (PFS0 htable,
// IVFC levels) and the NCA header precede the data in each section, so they are
// written with seek-back. Finally the written NCA is re-read from the output and
// hashed to obtain the contentId — byte-identical to preparePlaintextProgramNca.
//
// streamExefs(stream)  : calls stream(chunk, offInExefsData) over the ExeFS PFS0 data
// streamRomfs(stream)  : calls stream(chunk, offInRomfsData) over the merged RomFS data
// Returns { hashHex, size }.
export async function packProgramNcaStream({ adapter, ncaOffset, exefsSize, romfsDataSize, titleId, keys, streamExefs, streamRomfs, log, progress }) {
    const _log = typeof log === 'function' ? log : () => {};

    // ── Layout (from sizes only) ───────────────────────────────────────────
    const { exeHtableSize, exeSectionSize, sec0Start, sec1Start, sec0DataOff, sec1DataOff,
            hashLevelsSize, romSectionSize, ncaSize, exePaddingSize, romPaddingSize }
        = computeProgramNcaLayout(exefsSize, romfsDataSize);
    _log('info', `  Streaming NCA layout: ExeFS=0x${exeSectionSize.toString(16)} (htable 0x${exeHtableSize.toString(16)}), RomFS=0x${romSectionSize.toString(16)} (levels 0x${hashLevelsSize.toString(16)}), total=0x${ncaSize.toString(16)}`);

    const pfs0 = new StreamingPfs0Hasher(PFS0_EXEFS_HASH_BLOCK_SIZE);
    const ivfc = new StreamingIvfcHasher(romfsDataSize);

    // ── Stream ExeFS data → output + PFS0 hasher ───────────────────────────
    _log('info', '  Streaming ExeFS (PFS0 data) → output...');
    await streamExefs(async (chunk, off) => {
        await adapter.write(ncaOffset + sec0DataOff + off, chunk);
        pfs0.update(chunk);
    });
    const exeHash = pfs0.finalize();

    // ── Stream RomFS data → output + IVFC hasher ───────────────────────────
    _log('info', '  Streaming RomFS (BKTR data) → output...');
    const _prog = typeof progress === 'function' ? progress : () => {};
    const romTotal = romfsDataSize || 1;
    let romDone = 0;
    await streamRomfs(async (chunk, off) => {
        await adapter.write(ncaOffset + sec1DataOff + off, chunk);
        ivfc.update(chunk);
        romDone += chunk.length;
        _prog(romDone / romTotal);
    });
    const romIvfc = ivfc.finalize();

    // ── Section paddings (zeros) ───────────────────────────────────────────
    if (exePaddingSize > 0) await adapter.write(ncaOffset + sec0DataOff + exefsSize, new Uint8Array(exePaddingSize));
    if (romPaddingSize > 0) await adapter.write(ncaOffset + sec1DataOff + romfsDataSize, new Uint8Array(romPaddingSize));

    // ── Build NCA header (shared helper, XTS-encrypted) ───────────────────
    const encHeader = buildEncryptedProgramNcaHeader({
        titleId, keys, exeHash, exePfs0Offset: exeHtableSize, exefsSize, romIvfc,
        exeSectionSize, romSectionSize,
    });

    // ── Seek-back: header + PFS0 htable + IVFC levels ──────────────────────
    _log('info', '  Writing header + hash tables (seek-back)...');
    await adapter.write(ncaOffset, encHeader);
    await adapter.write(ncaOffset + sec0Start, exeHash.hashTable);
    let lvOff = 0;
    for (const lvl of romIvfc.hashLevels) {
        const lvlLen = lvl.length;
        await adapter.write(ncaOffset + sec1Start + lvOff, lvl);
        lvOff += lvlLen;
    }

    // ── Re-read NCA from output → contentId (sha256) ───────────────────────
    _log('info', '  Re-reading NCA from output → contentId...');
    const h = new SHA256();
    let roff = 0;
    while (roff < ncaSize) {
        const n = Math.min(0x1000000, ncaSize - roff);
        const part = await adapter.read(ncaOffset + roff, n);
        h.update(part);
        roff += n;
    }
    const hashHex = h.hex();
    _log('info', `  ----> Program NCA (streaming): ${ncaSize} bytes sha256=${hashHex}`);
    return { hashHex, size: ncaSize };
}

// ── Two-pass Program NCA pack (sequential output, no seek-back, no re-read) ─
// For outputs that cannot read back (SW download, FSA without read()).
//
// Phase 1 — computeProgramNcaContentId:
//   seekable output:  exefs 2× + romfs 1× → meta + sha256Mid (contentId in Pass 2)
//   append-only SW:   exefs 2× + romfs 2× → meta + contentId (PFS0 header must
//                     precede the NCA, so it must be final after Pass 1)
// Phase 2 — writeProgramNcaTwoPass: write NCA sequentially (exefs 1× + romfs 1×).
//
// Memory: ~200 KB (hash levels + header only).
// streamExefs / streamRomfs must be re-callable (up to 3× each for SW).

export function computeProgramNcaLayout(exefsSize, romfsDataSize) {
    const exeHtableSize = pad200(Math.ceil(exefsSize / PFS0_EXEFS_HASH_BLOCK_SIZE) * 0x20);
    const exeSectionSize = pad200(exeHtableSize + exefsSize);
    const sec0Start = NCA_HEADER_SIZE;
    const sec1Start = sec0Start + exeSectionSize;
    const sec0DataOff = sec0Start + exeHtableSize;
    const h1 = pad4000(Math.ceil(romfsDataSize / 0x4000) * 0x20);
    const h2 = pad4000(Math.ceil(h1 / 0x4000) * 0x20);
    const h3 = pad4000(Math.ceil(h2 / 0x4000) * 0x20);
    const h4 = pad4000(Math.ceil(h3 / 0x4000) * 0x20);
    const h5 = pad4000(Math.ceil(h4 / 0x4000) * 0x20);
    const hashLevelsSize = h1 + h2 + h3 + h4 + h5;
    const sec1DataOff = sec1Start + hashLevelsSize;
    const romSectionSize = pad4000(hashLevelsSize + romfsDataSize);
    const ncaSize = sec1Start + romSectionSize;
    const exePaddingSize = exeSectionSize - (exeHtableSize + exefsSize);
    const romPaddingSize = romSectionSize - (hashLevelsSize + romfsDataSize);
    return { exeHtableSize, exeSectionSize, sec0Start, sec1Start, sec0DataOff, sec1DataOff,
             hashLevelsSize, romSectionSize, ncaSize, exePaddingSize, romPaddingSize,
             exefsSize, romfsDataSize };
}

// Phase 1: compute metadata + SHA256 mid-state (no romfs re-stream). Returns meta for Phase 2.
// contentIdInPass1: when true (append-only outputs — the PFS0 header must be
// written BEFORE the NCA, so the contentId must be final after Pass 1), re-stream
// RomFS into the contentId hash here instead of deferring it to Pass 2.
export async function computeProgramNcaContentId({ exefsSize, romfsDataSize, titleId, keys, streamExefs, streamRomfs, log, progress, contentIdInPass1 = false }) {
    const _log = typeof log === 'function' ? log : () => {};
    const L = computeProgramNcaLayout(exefsSize, romfsDataSize);
    _log('info', `  Two-pass NCA layout: ExeFS=0x${L.exeSectionSize.toString(16)} (htable 0x${L.exeHtableSize.toString(16)}), RomFS=0x${L.romSectionSize.toString(16)} (levels 0x${L.hashLevelsSize.toString(16)}), total=0x${L.ncaSize.toString(16)}`);

    _log('info', '  Pass 1: Computing hash metadata (1 romfs pass)...');
    const pfs0 = new StreamingPfs0Hasher(PFS0_EXEFS_HASH_BLOCK_SIZE);
    await streamExefs(async (chunk, off) => { pfs0.update(chunk); });
    const exeHash = pfs0.finalize();

    const ivfc = new StreamingIvfcHasher(romfsDataSize);
    const _prog = typeof progress === 'function' ? progress : () => {};
    const romTotal = romfsDataSize || 1;
    let romDone = 0;
    await streamRomfs(async (chunk, off) => { ivfc.update(chunk); romDone += chunk.length; _prog(romDone / romTotal); });
    const romIvfc = ivfc.finalize();

    const encHeader = buildEncryptedProgramNcaHeader({
        titleId, keys, exeHash, exePfs0Offset: L.exeHtableSize, exefsSize, romIvfc,
        exeSectionSize: L.exeSectionSize, romSectionSize: L.romSectionSize,
    });

    // Hash NCA up to hashLevels, then clone state. The remaining bytes
    // (romChunks + romPadding) will be hashed in Pass 2 alongside the write,
    // saving one full romfs NCZ decompression — but that defers the contentId
    // to Pass 2, which is only possible when the PFS0 header can be written
    // after the NCA (seekable output). For append-only outputs the header must
    // precede the NCA, so contentId must be final here (re-stream RomFS).
    const sha = new SHA256();
    sha.update(encHeader);
    sha.update(exeHash.hashTable);
    await streamExefs(async (chunk) => { sha.update(chunk); });
    if (L.exePaddingSize > 0) sha.update(new Uint8Array(L.exePaddingSize));
    for (const lvl of romIvfc.hashLevels) sha.update(lvl);

    let contentId = null;
    let sha256Mid = null;
    if (contentIdInPass1) {
        _log('info', '  Pass 1: Computing contentId (re-stream)...');
        await streamRomfs(async (chunk) => { sha.update(chunk); });
        if (L.romPaddingSize > 0) sha.update(new Uint8Array(L.romPaddingSize));
        contentId = sha.hex();
        _log('info', `  ----> Program NCA (two-pass): ${L.ncaSize} bytes sha256=${contentId}`);
    } else {
        sha256Mid = sha.clone();
        _log('info', `  ----> Program NCA (two-pass): ${L.ncaSize} bytes (contentId computed in Pass 2)`);
    }

    return { size: L.ncaSize, contentId, meta: { encHeader, exeHash, romIvfc, L, sha256Mid } };
}

// Phase 2: write NCA sequentially (no seek-back). Uses meta from Phase 1.
// Returns contentId — either the one passed in (precomputed in Pass 1, append-only
// outputs) or the SHA256 finalized here from the sha256Mid state (seekable outputs,
// where hashing piggybacks on the write and saves a romfs stream).
export async function writeProgramNcaTwoPass({ meta, adapter, ncaOffset, streamExefs, streamRomfs, log, progress, contentId = null }) {
    const _log = typeof log === 'function' ? log : () => {};
    const _prog = typeof progress === 'function' ? progress : () => {};
    const { encHeader, exeHash, romIvfc, L, sha256Mid } = meta;
    _log('info', '  Pass 2: Writing NCA to output...');

    // The two-pass path is for sequential outputs: every write must land exactly
    // where the previous one ended. A mismatch means the output would be corrupt
    // (SW adapter fills the gap with zeros), so fail loudly instead.
    let expected = ncaOffset;
    const w = async (pos, data) => {
        if (pos !== expected) {
            throw new Error(`writeProgramNcaTwoPass: non-sequential write at 0x${pos.toString(16)} (expected 0x${expected.toString(16)}, gap=${pos - expected}) — output would be corrupt`);
        }
        expected += data.byteLength;
        return await adapter.write(pos, data);
    };

    // Progress + activity logs (a pass-2 merge can take a while with no other
    // output — the UI would otherwise look frozen). track() takes a SIZE (number):
    // the SW adapter transfers full-buffer chunks (detaches them), so lengths
    // must be captured before the write, never read off the chunk afterwards.
    let ncaDone = 0;
    const track = (n) => {
        ncaDone += n;
        if ((ncaDone & 0x3FFFFFF) === 0) {
            _log('info', `  Program NCA: ${(ncaDone / 1048576).toFixed(0)} / ${(L.ncaSize / 1048576).toFixed(0)} MB`);
            _prog(Math.min(1, ncaDone / L.ncaSize));
        }
    };

    const hdrLen = encHeader.byteLength;
    await w(ncaOffset, encHeader);
    track(hdrLen);
    const htabLen = exeHash.hashTable.byteLength;
    await w(ncaOffset + L.sec0Start, exeHash.hashTable);
    track(htabLen);
    await streamExefs(async (chunk, off) => {
        const n = chunk.byteLength;
        await w(ncaOffset + L.sec0DataOff + off, chunk);
        track(n);
    });
    if (L.exePaddingSize > 0) {
        await w(ncaOffset + L.sec0DataOff + L.exefsSize, new Uint8Array(L.exePaddingSize));
        track(L.exePaddingSize);
    }
    let lvOff = 0;
    for (let i = 0; i < romIvfc.hashLevels.length; i++) {
        const lvl = romIvfc.hashLevels[i];
        // Capture the length BEFORE the write: the SW adapter transfers the
        // buffer (detaches it), which zeroes .length on the caller's view —
        // `lvOff += lvl.length` after the write would add 0.
        const lvlLen = lvl.length;
        await w(ncaOffset + L.sec1Start + lvOff, lvl);
        lvOff += lvlLen;
        track(lvlLen);
    }
    _log('info', `  RomFS streaming: ${(L.romfsDataSize / 1048576).toFixed(0)} MB to merge/write...`);
    // Seekable output: restore the SHA256 mid-state (has header + exefs +
    // hashLevels) and let romChunks + romPadding be hashed alongside the
    // write → contentId for free. Append-only output: contentId was
    // precomputed in Pass 1 — write only.
    const sha = contentId === null ? sha256Mid.clone() : null;
    await streamRomfs(async (chunk, off) => {
        if (sha) sha.update(chunk);
        await w(ncaOffset + L.sec1DataOff + off, chunk);
        track(chunk.byteLength);
    });
    if (L.romPaddingSize > 0) {
        const pad = new Uint8Array(L.romPaddingSize);
        if (sha) sha.update(pad);
        await w(ncaOffset + L.sec1DataOff + L.romfsDataSize, pad);
    }
    if (sha) contentId = sha.hex();
    _prog(1);
    return contentId;
}

export async function extractControl(updateNcaData, keys) {
    const { decryptNcaHeader } = await import('./nca.js');

    const header = decryptNcaHeader(updateNcaData.subarray(0, NCA_HEADER_SIZE), keys);
    if (!header) throw new Error('Failed to decrypt update NCA header');

    const controlSec = header.sections[2];
    if (!controlSec || controlSec.size === 0) return null;

    const raw = updateNcaData.subarray(controlSec.offset, controlSec.offset + controlSec.size);

    if (controlSec.cryptoType === 1) {
        return raw;
    }

    const { decryptNcaSection } = await import('./nca.js');
    return await decryptNcaSection(raw, controlSec);
}
