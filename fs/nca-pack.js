import { AesXts, AesCtr } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';
import { sha256 } from '../crypto/sha256.js';
import { PFS0Writer } from './pfs0.js';
import { hexToBytes, writeU64LE, writeU32LE, NCA_HEADER_SIZE } from './nca-utils.js';

// Yanu update pipeline uses only:
//   PROGRAM (--plaintext) → ExeFS + RomFS, CRYPT_NONE sections ✅
//   META → PFS0, CRYPT_CTR, XTS header ✅
//
// NOT needed for yanu update:
//   CONTROL/DATA/MANUAL/PUBLICDATA — copied from update container as-is
//   Encrypted sections — yanu uses --plaintext only
//   ACID signature (npdm_key_sig) — Atmosphere ignores it
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

// ── IVFC hash tree ───────────────────────────────────────────────────────────
// 5 hash levels + 1 data level (the romfs image).
// Each hash level hashes 16KB (0x4000) blocks from the level below.
// Each level file is padded to 0x4000 on disk.
//
// IVFC header level_headers[0..5]:
//   [0] = top hash level 0, [1]..[4] = hash levels 1..4, [5] = DATA level
// Each hash_data_size = padded file size for hash levels, = raw romfs size for data.
// Master hash = sha256(entire top hash level-0 file (all 0x4000 bytes)).

export function buildIvfcHashTree(romfsData) {
    const blockSize = 0x4000;
    const hashSize = 0x20;
    const numHashLevels = 5;

    // Build hash levels from bottom up (data → hash4 → ... → hash0)
    let currentData = romfsData;
    const allFiles = [romfsData];
    const allSizes = [romfsData.length];

    for (let lvl = 0; lvl < numHashLevels; lvl++) {
        const numBlocks = Math.ceil(currentData.length / blockSize);
        const hashFile = new Uint8Array(numBlocks * hashSize);
        for (let b = 0; b < numBlocks; b++) {
            const blockStart = b * blockSize;
            const blockEnd = Math.min(blockStart + blockSize, currentData.length);
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
            const block = new Uint8Array(blockSize);
            block.set(currentData.subarray(blockStart, blockEnd));
            const hash = hexToBytes(sha256(block));
            hashFile.set(hash, b * hashSize);
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

    // Build IVFC header (0xE0 bytes)
    const ivfcHeader = new Uint8Array(0xE0);
    const ivfcView = new DataView(ivfcHeader.buffer);
    ivfcView.setUint32(0, 0x43465649, true);       // magic "IVFC"
    ivfcView.setUint32(4, 0x20000, true);          // id
    ivfcView.setUint32(8, 0x20, true);             // master_hash_size
    ivfcView.setUint32(12, 7, true);               // num_levels

    const LOGICAL_OFFSET = 0x00;
    const HASH_DATA_SIZE = 0x08;
    const BLOCK_SIZE = 0x10;
    const HEADER_PER_LEVEL = 0x18;
    const numLevels = 6;

    let cumulativeOffset = 0;
    for (let lvl = 0; lvl < numLevels; lvl++) {
        const base = 0x10 + lvl * HEADER_PER_LEVEL;
        // Each level header (ivfc.h): logical_offset(u64)@+0x00, hash_data_size(u64@+0x08, block_size(u32@+0x10, reserved(u32)@+0x14 = 0x18 bytes
        ivfcView.setBigUint64(base + LOGICAL_OFFSET, BigInt(cumulativeOffset), true);
        ivfcView.setBigUint64(base + HASH_DATA_SIZE, BigInt(reversedSizes[lvl]), true);
        ivfcView.setUint32(base + 0x10, 0x0E, true);
        cumulativeOffset += reversedSizes[lvl];
    }

    // Master hash = sha256(top hash level 0 (all 0x4000 bytes))
    ivfcHeader.set(hexToBytes(sha256(reversedFiles[0])), 0xC0);

    // Physical layout: concatenate all level files
    let physicalSize = 0;
    for (let lvl = 0; lvl < numLevels; lvl++) {
        physicalSize += reversedFiles[lvl].length;
    }

    return { ivfcHeader, levelFiles: reversedFiles, dataSizes: reversedSizes, physicalSize };
}


// ── PFS0 hash table ─────────────────────────────────────────────────────────
// Each block of hash_block_size gets sha256 hash (no zero-padding of last block).
// Hash table is then padded to 0x200 boundary.
// Master hash = sha256 of (hash_table[0..hash_table_size]) — raw hash bytes only.

function buildPfs0HashTable(pfs0Data, hashBlock) {
    const hashSize = 0x20;
    const numBlocks = Math.ceil(pfs0Data.length / hashBlock);
    const hashTable = new Uint8Array(numBlocks * hashSize);

    for (let b = 0; b < numBlocks; b++) {
        const blockStart = b * hashBlock;
        const blockEnd = Math.min(blockStart + hashBlock, pfs0Data.length);
        const block = pfs0Data.subarray(blockStart, blockEnd);
        const hash = hexToBytes(sha256(block));
        hashTable.set(hash, b * hashSize);
    }

    const paddedSize = pad200(hashTable.length);
    const padded = new Uint8Array(paddedSize);
    padded.set(hashTable);

    const masterHash = hexToBytes(sha256(hashTable.subarray(0, hashTable.length)));

    return {
        hashTable: padded,
        rawHashSize: hashTable.length,
        masterHash,
    };
}

// ── FsHeader builders ────────────────────────────────────────────────────────
// nca_fs_header_t layout (from nca.h):
//   version(u16) @0x00, fs_type(u8) @0x02, hash_type(u8=2/3) @0x03,
//   crypt_type(u8) @0x04, _0x5[3] @0x05,
//   superblock(union) @0x08 (0x138 bytes),
//   section_ctr[8] @0x140, _0x148[0xB8] @0x148  → total 0x200

function buildPfs0FsHeader(cryptType) {
    const fh = new Uint8Array(0x200);
    const v = new DataView(fh.buffer);

    // version = 2 (u16 LE)
    v.setUint16(0, 2, true);
    // fs_type = 1 (PFS0)
    fh[0x02] = 1;
    // hash_type = 2 (PFS0)
    fh[0x03] = 2;
    // crypt_type
    fh[0x04] = cryptType;
    // _0x5[3] = 0
    fh.fill(0, 0x05, 0x08);
    // section_ctr = 0
    fh.fill(0, 0x140, 0x148);
    // _0x148[0xB8] = 0 (already zeroed)

    return fh;
}

function buildRomfsFsHeader(cryptType) {
    const fh = new Uint8Array(0x200);
    const v = new DataView(fh.buffer);

    // version = 2 (u16 LE)
    v.setUint16(0, 2, true);
    // fs_type = 0 (ROMFS)
    fh[0x02] = 0;
    // hash_type = 3 (ROMFS/IVFC)
    fh[0x03] = 3;
    // crypt_type
    fh[0x04] = cryptType;
    // _0x5[3] = 0
    fh.fill(0, 0x05, 0x08);
    // section_ctr = 0
    fh.fill(0, 0x140, 0x148);

    return fh;
}

// ── NCA header builder ───────────────────────────────────────────────────────
// nca_header_t layout (from nca.h):
//   fixed_key_sig[0x100] @0x00 = all zeros (The-4n/hacPack default: NCA_SIG_TYPE_ZERO)
//   npdm_key_sig[0x100] @0x100 = all zeros
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
//   rights_id[0x10] @0x230 (all zeros for no-titlekey)
//   section_entries[4] @0x240
//   section_hashes[4][0x20] @0x280
//   encrypted_keys[4][0x10] @0x300
//   _0x340[0xC0] padding
//   fs_headers[4] @0x400

function buildNcaHeader(titleId, sections, keys) {
    const header = new Uint8Array(NCA_HEADER_SIZE);

    // fixed_key_sig = all zeros (The-4n/hacPack default)
    header.fill(0, 0, 0x100);
    // npdm_key_sig = all zeros
    header.fill(0, 0x100, 0x200);

    // Magic: "NCA3"
    header[0x200] = 0x4E; header[0x201] = 0x43; header[0x202] = 0x41; header[0x203] = 0x33;
    // distribution = 0 (not gamecard)
    header[0x204] = 0x00;
    // content_type = 0 (Program)
    header[0x205] = 0x00;
    // crypto_type = 0 (keygen 1)
    header[0x206] = 0x00;
    // kaek_ind = 0
    header[0x207] = 0x00;
    // title_id (big-endian u64)
    const tidBytes = hexToBytes(titleId.toLowerCase());
    const tidRev = new Uint8Array(8);
    for (let i = 0; i < 8; i++) tidRev[i] = tidBytes[7 - i];
    header.set(tidRev, 0x210);
    // sdk_version = 0x000C1100 (hacPack default)
    const hv = new DataView(header.buffer, header.byteOffset);
    hv.setUint32(0x21C, 0x000C1100, true);
    // crypto_type2 = 0
    header[0x220] = 0x00;
    // rights_id = all zeros
    header.fill(0, 0x230, 0x240);

    // Section entries
    const validSecs = sections.filter(s => s.size > 0);
    for (let i = 0; i < validSecs.length; i++) {
        const base = 0x240 + i * 0x10;
        const sec = validSecs[i];
        writeU32LE(header, base, Math.floor(sec.offset / 0x200));
        writeU32LE(header, base + 4, Math.floor(sec.endOffset / 0x200));
        header[base + 8] = 0x01; // _0x8[0] = 1 (hacPack always sets this)
    }

    // reserved (0x280..0x2FF) = all zeros — section hashes filled later
    header.fill(0, 0x280, 0x300);

    // Key area: encrypted_keys[4][0x10]
    // Default: [0, 0, keyareakey(0x04*16), 0]
    const keyareakey = new Uint8Array(16).fill(0x04);
    const keyBlock = new Uint8Array(0x40);
    keyBlock.set(keyareakey, 0x20); // slot 2 = keyareakey

    // ECB-encrypt entire key block with key_area_key_application_00
    const kak00 = typeof keys.key_area_key_application_00 === 'string'
        ? hexToBytes(keys.key_area_key_application_00)
        : (keys.key_area_key_application_00 instanceof Uint8Array
            ? keys.key_area_key_application_00
            : new Uint8Array(keys.key_area_key_application_00));
    const ecb = new AesEcb(kak00);
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

// ── Main: packPlaintextProgramNca ────────────────────────────────────────────
// Layout (matching hacPack --plaintext):
//   Header (0xC00, XTS-encrypted)
//   Section 0: ExeFS = PFS0(hash_table + PFS0 data)
//   Section 1: RomFS = IVFC(5 hash levels + romfs data)
// Each section padded to 0x200.

export async function packPlaintextProgramNca(exefsData, romfsData, controlData, titleId, keys, log) {
    const _log = typeof log === 'function' ? log : () => {};
    _log('info', '----> Creating Program NCA:');

    // ── Section 0: ExeFS (PFS0) ────────────────────────────────────────────
    _log('info', '  Building ExeFS PFS0 hash table...');
    const exeHash = buildPfs0HashTable(exefsData, 0x10000);
    const exeHtablePadded = exeHash.hashTable; // padded to 0x200
    const exePfs0Offset = exeHtablePadded.length;
    const exeSectionSize = pad200(exePfs0Offset + exefsData.length);

    _log('info', '  ExeFS: htable=' + exeHtablePadded.length + ' B, PFS0=' + exefsData.length + ' B, section=' + exeSectionSize + ' B');

    // ── Section 1: RomFS (IVFC) ────────────────────────────────────────────
    _log('info', '  Building IVFC hash tree (5 levels + data)...');
    const romIvfc = buildIvfcHashTree(romfsData);
    const romSectionSize = pad200(romIvfc.physicalSize);

    _log('info', '  RomFS: levels=' + romIvfc.levelFiles.length + ', total=' + romIvfc.physicalSize + ' B, section=' + romSectionSize + ' B');

    // ── Section layout ─────────────────────────────────────────────────────
    const ncaHeader = new Uint8Array(NCA_HEADER_SIZE);
    const sec0Start = NCA_HEADER_SIZE;
    const sec0End = sec0Start + exeSectionSize;
    const sec1Start = sec0End;
    const sec1End = sec1Start + romSectionSize;
    const ncaSize = sec1End;

    // ── Build NCA header ───────────────────────────────────────────────────
    _log('info', '  Building NCA header...');
    const header = buildNcaHeader(titleId, [
        { offset: sec0Start, endOffset: sec0End, size: exeSectionSize },
        { offset: sec1Start, endOffset: sec1End, size: romSectionSize },
    ], keys);

    // ── FsHeader 0: ExeFS (PFS0, CRYPT_NONE) ───────────────────────────────
    const exeFsHeader = buildPfs0FsHeader(0x01); // CRYPT_NONE
    const ev = new DataView(exeFsHeader.buffer);

    // PFS0 superblock at FsHeader + 0x08 (pfs0_superblock_t from hacPack/pfs0.h):
    //   0x00-0x1F: master_hash[0x20]
    //   0x20: block_size (u32 LE)
    //   0x24: always_2 (u32 LE)
    //   0x28: hash_table_offset (u64 LE, normally 0)
    //   0x30: hash_table_size (u64 LE)
    //   0x38: pfs0_offset (u64 LE)
    //   0x40: pfs0_size (u64 LE)
    //   0x48-0x137: padding
    exeFsHeader.set(exeHash.masterHash, 0x08);
    ev.setUint32(0x28, 0x10000, true); // block_size = 0x10000 (64KB)
    ev.setUint32(0x2C, 2, true);       // always_2 = 2
    // hash_table_offset = 0 (u64 LE, already 0)
    ev.setBigUint64(0x38, BigInt(exeHash.rawHashSize), true); // hash_table_size
    ev.setBigUint64(0x40, BigInt(exePfs0Offset), true);       // pfs0_offset
    ev.setBigUint64(0x48, BigInt(exefsData.length), true);    // pfs0_size

    header.set(exeFsHeader, 0x400);

    // ── FsHeader 1: RomFS (IVFC, CRYPT_NONE) ───────────────────────────────
    const romFsHeader = buildRomfsFsHeader(0x01); // CRYPT_NONE

    // IVFC superblock at FsHeader + 0x08
    romFsHeader.set(romIvfc.ivfcHeader, 0x08);

    // IVFC level headers use dataSizes from buildIvfcHashTree
    // (already set in ivfcHeader by buildIvfcHashTree)

    header.set(romFsHeader, 0x600);

    // ── Section hashes (sha256 of each plaintext fs_header[0x200]) ──────────
    const sec0Hash = sha256(header.subarray(0x400, 0x600));
    const sec1Hash = sha256(header.subarray(0x600, 0x800));
    header.set(hexToBytes(sec0Hash), 0x280);
    header.set(hexToBytes(sec1Hash), 0x2A0);

    // ── Update NCA size ────────────────────────────────────────────────────
    writeU64LE(header, 0x208, ncaSize);

    // ── Assemble NCA: header + sections ────────────────────────────────────
    _log('info', '  Assembling NCA: header + sections...');
    const nca = new Uint8Array(ncaSize);
    nca.set(header, 0);

    // Section 0: ExeFS = hash_table + PFS0 data
    nca.set(exeHtablePadded, sec0Start);
    nca.set(exefsData, sec0Start + exePfs0Offset);

    // Section 1: RomFS = level files concatenated
    let romPos = sec1Start;
    for (let lvl = 0; lvl < romIvfc.levelFiles.length; lvl++) {
        nca.set(romIvfc.levelFiles[lvl], romPos);
        romPos += romIvfc.levelFiles[lvl].length;
    }

    // ── Encrypt header with XTS ────────────────────────────────────────────
    _log('info', '  Encrypting header with XTS...');
    const hdrKey = typeof keys.header_key === 'string'
        ? hexToBytes(keys.header_key)
        : (keys.header_key instanceof Uint8Array
            ? keys.header_key
            : new Uint8Array(keys.header_key));
    const xts = new AesXts(hdrKey);
    const encHeader = xts.encrypt(nca.subarray(0, NCA_HEADER_SIZE));
    nca.set(encHeader, 0);

    // ── Final hash ─────────────────────────────────────────────────────────
    _log('info', '  Calculating NCA hash...');
    const finalHash = sha256(nca);
    _log('info', '  ----> Created Program NCA: ' + ncaSize + ' bytes sha256=' + finalHash);
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

    // ── PFS0 hash table (block_size=0x1000, PFS0_META_HASH_BLOCK_SIZE) ──────
    const hashBlock = 0x1000;
    const hashSize = 0x20;
    const numBlocks = Math.ceil(newPfs0.length / hashBlock);
    const htableRaw = new Uint8Array(numBlocks * hashSize);
    for (let b = 0; b < numBlocks; b++) {
        const blockStart = b * hashBlock;
        const blockEnd = Math.min(blockStart + hashBlock, newPfs0.length);
        const block = newPfs0.subarray(blockStart, blockEnd);
        const hash = hexToBytes(sha256(block));
        htableRaw.set(hash, b * hashSize);
    }
    const htablePadded = new Uint8Array(pad200(htableRaw.length));
    htablePadded.set(htableRaw);
    const pfs0Offset = htablePadded.length; // = 0x200
    const pfs0Size = newPfs0.length;
    const masterHash = hexToBytes(sha256(htableRaw));

    // ── Section layout ─────────────────────────────────────────────────────
    const sectionDataSize = pad200(pfs0Offset + pfs0Size);
    const sectionStart = 0xC00;
    const sectionEnd = sectionStart + sectionDataSize;
    const ncaSize = sectionEnd; // header(0xC00) + section

    _log('info', `  CNMT section: htable=${htablePadded.length} B, PFS0=${pfs0Size} B, total=${sectionDataSize} B, NCA=${ncaSize} B`);

    // ── FsHeader (PFS0, CRYPT_CTR) ─────────────────────────────────────────
    const fsHeader = new Uint8Array(0x200);
    const fv = new DataView(fsHeader.buffer);
    fv.setUint16(0, 2, true); // version = 2
    fsHeader[0x02] = 1; // fs_type = PFS0
    fsHeader[0x03] = 2; // hash_type = PFS0
    fsHeader[0x04] = 3; // crypt_type = CRYPT_CTR (3)
    fsHeader.set(masterHash, 0x08); // PFS0 superblock
    fv.setUint32(0x28, 0x1000, true); // block_size = 0x1000
    fv.setUint32(0x2C, 2, true); // always_2 = 2
    fv.setBigUint64(0x38, BigInt(htableRaw.length), true); // hash_table_size
    fv.setBigUint64(0x40, BigInt(pfs0Offset), true); // pfs0_offset
    fv.setBigUint64(0x48, BigInt(pfs0Size), true); // pfs0_size

    // ── NCA header ─────────────────────────────────────────────────────────
    const header = new Uint8Array(NCA_HEADER_SIZE);
    header.fill(0, 0, 0x200); // fixed_key_sig + npdm_key_sig = zeros
    header[0x200] = 0x4E; header[0x201] = 0x43; header[0x202] = 0x41; header[0x203] = 0x33; // NCA3
    header[0x204] = 0x00; // distribution = 0
    header[0x205] = 0x01; // content_type = Meta
    header[0x206] = 0x00; // crypto_type = 0 (kg1)
    header[0x207] = 0x00; // kaek_ind = 0
    writeU64LE(header, 0x208, ncaSize); // nca_size

    const tidBytes = hexToBytes(titleId.toLowerCase());
    const tidRev = new Uint8Array(8);
    for (let i = 0; i < 8; i++) tidRev[i] = tidBytes[7 - i];
    header.set(tidRev, 0x210);
    const hv = new DataView(header.buffer, header.byteOffset);
    hv.setUint32(0x21C, 0x000C1100, true); // sdk_version
    header[0x220] = 0x00; // crypto_type2 = 0
    header.fill(0, 0x230, 0x240); // rights_id = 0

    writeU32LE(header, 0x240, Math.floor(sectionStart / 0x200));
    writeU32LE(header, 0x244, Math.floor(sectionEnd / 0x200));
    header[0x248] = 0x01; // _0x8[0] = 1

    const secHash = sha256(fsHeader);
    header.set(hexToBytes(secHash), 0x280);

    // Key area
    const keyareakey = new Uint8Array(16).fill(0x04);
    const keyBlock = new Uint8Array(0x40);
    keyBlock.set(keyareakey, 0x20);
    const kak00 = typeof keys.key_area_key_application_00 === 'string'
        ? hexToBytes(keys.key_area_key_application_00)
        : (keys.key_area_key_application_00 instanceof Uint8Array
            ? keys.key_area_key_application_00
            : new Uint8Array(keys.key_area_key_application_00));
    const ecb = new AesEcb(kak00);
    const encKeyBlock = new Uint8Array(0x40);
    for (let blk = 0; blk < 4; blk++) {
        const chunk = keyBlock.subarray(blk * 0x10, (blk + 1) * 0x10);
        encKeyBlock.set(ecb.encrypt(chunk), blk * 0x10);
    }
    header.set(encKeyBlock, 0x300);
    header.set(fsHeader, 0x400);

    // ── Section data (CTR-encrypted) ───────────────────────────────────────
    const secDec = new Uint8Array(sectionDataSize);
    secDec.set(htablePadded, 0);
    secDec.set(newPfs0, pfs0Offset);
    const ctrKey = new Uint8Array(16).fill(0x04);
    const zerosNonce = new Uint8Array(8);
    const ctrEnc = new AesCtr(ctrKey, zerosNonce);
    ctrEnc.seek(sectionStart);
    const secEnc = await ctrEnc.encrypt(secDec);

    // ── Assemble + XTS header encryption ───────────────────────────────────
    const nca = new Uint8Array(ncaSize);
    nca.set(header, 0);
    nca.set(secEnc, sectionStart);
    const hdrKey = typeof keys.header_key === 'string'
        ? hexToBytes(keys.header_key)
        : (keys.header_key instanceof Uint8Array
            ? keys.header_key
            : new Uint8Array(keys.header_key));
    const xts = new AesXts(hdrKey);
    nca.set(xts.encrypt(nca.subarray(0, NCA_HEADER_SIZE)), 0);

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
// 2. ACID signature (npdm_key_sig @0x100):
//    hacpack: RSA-2048-PSS-SHA256(header[0:0x200]) with ACID private key
//    yanu: keeps hacpack's default (zeros) → Atmosphere ignores
//    Our code: header[0x100:0x200] = all zeros (correct for yanu)
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

function deriveTitlekey(decHeader, keys) {
    if (!keys || !keys.titlekek_02) return null;
    const titlekek = typeof keys.titlekek_02 === 'string' ? hexToBytes(keys.titlekek_02) : keys.titlekek_02;
    const keyArea = decHeader.subarray(0x100, 0x300);
    return new AesEcb(titlekek).decrypt(keyArea.subarray(0x20, 0x30));
}

export async function extractExefs(ncaData, keys, tikData = null) {
    const hdrKey = typeof keys.header_key === 'string'
        ? hexToBytes(keys.header_key)
        : new Uint8Array(keys.header_key);
    const xts = new AesXts(hdrKey);
    const decHeader = xts.decrypt(ncaData.subarray(0, NCA_HEADER_SIZE), 0);

    let titlekey = null;
    if (tikData && tikData.length >= 0x190) {
        const titlekek = typeof keys.titlekek_02 === 'string' ? hexToBytes(keys.titlekek_02) : keys.titlekek_02;
        titlekey = new AesEcb(titlekek).decrypt(tikData.subarray(0x180, 0x190));
    }
    if (!titlekey) {
        titlekey = deriveTitlekey(decHeader, keys);
    }

    const exeFsFsHdr = decHeader.subarray(0x400, 0x600);
    const sectionCtrRaw = exeFsFsHdr.subarray(0x140, 0x148);
    const sectionCtrRev = new Uint8Array(8);
    for (let i = 0; i < 8; i++) sectionCtrRev[i] = sectionCtrRaw[7 - i];

    const sectionStart = Number(new DataView(exeFsFsHdr.buffer, exeFsFsHdr.byteOffset + 0x40, 8).getBigUint64(0, true));
    const sectionSize = Number(new DataView(exeFsFsHdr.buffer, exeFsFsHdr.byteOffset + 0x48, 8).getBigUint64(0, true));

    const mediaOffset = Number(new DataView(decHeader.buffer, decHeader.byteOffset + 0x240, 4).getUint32(0, true));
    const sectionOffset = mediaOffset * 0x200;

    const raw = ncaData.subarray(sectionOffset, sectionOffset + sectionStart + sectionSize);

    if (!titlekey || sectionSize === 0) {
        return raw.subarray(sectionStart, sectionStart + sectionSize);
    }

    const c = new AesCtr(titlekey, sectionCtrRev);
    c.seek(sectionOffset);
    const decrypted = await c.decrypt(raw);
    return decrypted.subarray(sectionStart, sectionStart + sectionSize);
}

export async function extractRomfs(ncaData, keys, tikData = null) {
    const hdrKey = typeof keys.header_key === 'string'
        ? hexToBytes(keys.header_key)
        : new Uint8Array(keys.header_key);
    const xts = new AesXts(hdrKey);
    const decHeader = xts.decrypt(ncaData.subarray(0, NCA_HEADER_SIZE), 0);

    let titlekey = null;
    if (tikData && tikData.length >= 0x190) {
        const titlekek = typeof keys.titlekek_02 === 'string' ? hexToBytes(keys.titlekek_02) : keys.titlekek_02;
        titlekey = new AesEcb(titlekek).decrypt(tikData.subarray(0x180, 0x190));
    }
    if (!titlekey) {
        titlekey = deriveTitlekey(decHeader, keys);
    }

    let romfsIdx = -1;
    let romfsFsHdr = null;
    for (let i = 0; i < 4; i++) {
        const fh = decHeader.subarray(0x400 + i * 0x200, 0x400 + i * 0x200 + 0x200);
        if (fh[0x03] === 3) { romfsIdx = i; romfsFsHdr = fh; break; }
    }
    if (romfsIdx < 0) throw new Error('extractRomfs: RomFS section not found');

    const sectionCtrRaw = romfsFsHdr.subarray(0x140, 0x148);
    const sectionCtrRev = new Uint8Array(8);
    for (let i = 0; i < 8; i++) sectionCtrRev[i] = sectionCtrRaw[7 - i];

    const mediaOffset = new DataView(decHeader.buffer, decHeader.byteOffset + 0x240 + romfsIdx * 0x10, 4).getUint32(0, true);
    const mediaEnd = new DataView(decHeader.buffer, decHeader.byteOffset + 0x240 + romfsIdx * 0x10 + 4, 4).getUint32(0, true);
    const sectionOffset = mediaOffset * 0x200;
    const mediaSize = mediaEnd * 0x200 - sectionOffset;

    const raw = ncaData.subarray(sectionOffset, sectionOffset + mediaSize);
    if (!titlekey || mediaSize === 0) return raw;

    const c = new AesCtr(titlekey, sectionCtrRev);
    c.seek(sectionOffset);
    const decrypted = await c.decrypt(raw);
    return decrypted;
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
