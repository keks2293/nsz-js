import { AesXts } from '../crypto/aes-ops.mjs';
import { decryptNcaHeader } from './nca.js';
import {
    parseBktrHeader,
    decryptBktrTable,
    parseRelocationBlock,
    parseSubsectionBlock,
    findSubsectionEntry,
    subEntryIdx,
    decryptPatchRegion,
    decryptBaseRomfs,
    extractTitlekeyFromTik,
    deriveTitlekeyFromKeyArea,
    lookupTitlekeyFromDatabase,
} from './bktr.js';

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

const BKTR_HEADER_OFFSET = 0x100; // In FsHeader extension

export async function mergeRomFS(baseNcaData, updateNcaData, options = {}) {
    const { keys, baseTitlekey: providedBaseTitlekey, updateTitlekey: providedUpdateTitlekey, baseTik, updateTik, titlekeysFile } = options;

    if (!keys) throw new Error('BKTR: keys required');

    const baseHeader = decryptNcaHeader(baseNcaData.subarray(0, 0xc00), keys);
    const updateHeader = decryptNcaHeader(updateNcaData.subarray(0, 0xc00), keys);
    if (!baseHeader || !updateHeader) throw new Error('BKTR: failed to decrypt NCA headers');

    const baseRomfsSec = baseHeader.sections.find(s => s.fsType === 3);
    const updateRomfsSec = updateHeader.sections.find(s => s.fsType === 3 && s.cryptoType === 4);
    if (!baseRomfsSec) throw new Error('BKTR: base romfs section not found');
    if (!updateRomfsSec) throw new Error('BKTR: update BKTR romfs section not found');

    const baseRomfsSecMeta = {
        offset: baseRomfsSec.offset,
        size: baseRomfsSec.size,
        secIdx: baseHeader.sections.indexOf(baseRomfsSec),
    };
    const updateRomfsSecIdx = updateHeader.sections.indexOf(updateRomfsSec);

    // Decrypt NCA headers
    const hdrKey = typeof keys.header_key === 'string' ? hexToBytes(keys.header_key) : keys.header_key;
    const xts = new AesXts(hdrKey);
    const updateDecHeader = xts.decrypt(updateNcaData.subarray(0, 0xc00), 0);
    const baseDecHeader = xts.decrypt(baseNcaData.subarray(0, 0xc00), 0);

    // Update FsHeader
    const updateFsHdr = updateDecHeader.subarray(0x400 + updateRomfsSecIdx * 0x200, 0x400 + updateRomfsSecIdx * 0x200 + 0x200);

    // Parse IVFC header from the BKTR superblock (bktr_superblock_t = ivfc_header @ superblock+0x0, see nca.h).
    // The BKTR superblock starts at FsHeader+0x8; ivfc_hdr_t (ivfc.h) is:
    //   magic(4)@+0, id(4)@+4, master_hash_size(4)@+8, num_levels(4)@+0xC,
    //   level_headers[6]@+0x10 (each 0x18: logical_offset u64, hash_data_size u64, block_size u32, reserved u32),
    //   master_hash(0x20)@+0xC0.
    // Level 5 is the DATA level: the actual RomFS image. hactool uses it as the RomFS base
    // (nca.c:1240 "ctx->bktr_ctx.romfs_offset = ctx->bktr_ctx.ivfc_levels[IVFC_MAX_LEVEL-1].data_offset").
    const ivfcBase = updateFsHdr.byteOffset + 0x8;
    const readLevelU64 = (levelIdx, fieldOff) =>
        Number(new DataView(updateFsHdr.buffer, ivfcBase + 0x10 + levelIdx * 0x18 + fieldOff, 8).getBigUint64(0, true));
    const dataLevelOffset = readLevelU64(5, 0x00); // logical_offset of level 5 = where RomFS data starts
    const dataLevelSize = readLevelU64(5, 0x08);   // hash_data_size of level 5 = size of RomFS data

    // Parse BKTR headers
    const relocHeader = parseBktrHeader(updateFsHdr, BKTR_HEADER_OFFSET);
    const subHeader = parseBktrHeader(updateFsHdr, BKTR_HEADER_OFFSET + 0x20);
    if (relocHeader.magic !== 0x52544B42) throw new Error(`BKTR: reloc magic 0x${relocHeader.magic.toString(16).padStart(8, '0')}`);
    if (subHeader.magic !== 0x52544B42) throw new Error(`BKTR: sub magic 0x${subHeader.magic.toString(16).padStart(8, '0')}`);

    // AesCtrUpperIv: FsHeader[0x140:0x148] = {generation(u32 LE), secure_value(u32 LE)}
    // Stratosphere uses secure_value as ctr[0:4] BE in AesCtrEx counter
    const secureValue = new DataView(updateFsHdr.buffer, updateFsHdr.byteOffset + 0x144, 4).getUint32(0, true);
    // section_ctr for BKTR table decryption (regular AES-CTR, reversed)
    const sectionCtrRaw = updateFsHdr.subarray(0x140, 0x148);
    const updateNonce = new Uint8Array(8);
    for (let j = 0; j < 8; j++) updateNonce[j] = sectionCtrRaw[7 - j];

    // Load titlekeys database if provided
    let titlekeysMap = null;
    if (titlekeysFile) {
        const { loadTitlekeysFile } = await import('./bktr.js');
        titlekeysMap = await loadTitlekeysFile(titlekeysFile);
    }

    // Get titlekeys (prefer provided, then titlekeys database, then tik, then key_area)
    let updateTitlekey = providedUpdateTitlekey
        || (titlekeysMap ? lookupTitlekeyFromDatabase(updateHeader.rightsId, titlekeysMap) : null)
        || (updateTik ? extractTitlekeyFromTik(updateTik, keys, updateHeader.rightsId) : null)
        || deriveTitlekeyFromKeyArea(updateDecHeader, keys);
    if (!updateTitlekey) throw new Error('BKTR: cannot get update titlekey (provide titlekeysFile or valid updateTik)');

    let baseTitlekey = providedBaseTitlekey
        || (titlekeysMap ? lookupTitlekeyFromDatabase(baseHeader.rightsId, titlekeysMap) : null)
        || (baseTik ? extractTitlekeyFromTik(baseTik, keys, baseHeader.rightsId) : null)
        || deriveTitlekeyFromKeyArea(baseDecHeader, keys);
    if (!baseTitlekey) throw new Error('BKTR: cannot get base titlekey (provide titlekeysFile or valid baseTik)');

    // Decrypt BKTR tables
    const relocTableBuf = await decryptBktrTable(
        updateNcaData, updateTitlekey, updateNonce,
        updateRomfsSec.offset + relocHeader.offset, relocHeader.size
    );
    const subTableBuf = await decryptBktrTable(
        updateNcaData, updateTitlekey, updateNonce,
        updateRomfsSec.offset + subHeader.offset, subHeader.size
    );

    const relocBlock = parseRelocationBlock(relocTableBuf);
    const subBlock = parseSubsectionBlock(subTableBuf);
    if (relocBlock.entries.length === 0) throw new Error('BKTR: no relocation entries');
    if (subBlock.entries.length === 0) throw new Error('BKTR: no subsection entries');

    // Decrypt base romfs
    const baseRomfsDecrypted = await decryptBaseRomfs(
        baseNcaData, baseRomfsSecMeta, baseDecHeader, baseTitlekey
    );

    // Build merged RomFS.
    //
    // The relocation table maps the WHOLE virtual section (IVFC header + hash levels 0..4 +
    // level-5 data) and extends to relocBlock.totalSize (a bit past the end of level-5 data:
    // level 4 hashes the data in 0x4000 blocks, and the last block covers that trailing part
    // of the virtual image). So `merged` must be built at full virtual size (totalSize).
    // The actual RomFS image that gets re-packed is ONLY the level-5 DATA region:
    // yanu extracts it via hac2l ("--basenca base update --romfsdir ..." → NcaReader/BKTR
    // reader returns the merged romfs starting at ivfc level-5 offset) and repacks with
    // hacPack (romfs_build()), which expects just the data blob — see hactool nca.c:1240
    // ("romfs_offset = ivfc_levels[IVFC_MAX_LEVEL-1].data_offset").
    // So mergedData = merged.subarray(dataLevelOffset, dataLevelOffset + dataLevelSize).
    const merged = new Uint8Array(relocBlock.totalSize);
    let pos = 0;
    let entryIdx = 0;

    while (pos < merged.length && entryIdx < relocBlock.entries.length) {
        const entry = relocBlock.entries[entryIdx];
        const nextVirt = entryIdx + 1 < relocBlock.entries.length
            ? relocBlock.entries[entryIdx + 1].virtOffset
            : merged.length;
        const chunkEnd = Math.min(nextVirt, merged.length);
        const readSize = chunkEnd - pos;

        if (entry.isPatch) {
            // Decrypt patch from update NCA using AesCtrEx
            // Must handle subsection entry boundaries within the patch range
            let writePos = pos;
            let currentPhys = entry.physOffset + (pos - entry.virtOffset);

            while (writePos < chunkEnd) {
                // Find subsection entry covering current physOffset
                const subEntry = findSubsectionEntry(subBlock.entries, currentPhys);
                if (!subEntry) {
                    throw new Error(`BKTR: no subsection entry for physOffset 0x${currentPhys.toString(16)}`);
                }

                // Calculate how much we can read with this subsection entry
                const nextSubOff = subEntryIdx(subBlock.entries, currentPhys) + 1 < subBlock.entries.length
                    ? subBlock.entries[subEntryIdx(subBlock.entries, currentPhys) + 1].offset
                    : Infinity;
                const remainingInSub = nextSubOff - currentPhys;
                const remainingToWrite = chunkEnd - writePos;
                const readLen = Math.min(remainingInSub, remainingToWrite);

                const fileOffset = updateRomfsSec.offset + currentPhys;
                const chunk = await decryptPatchRegion(
                    updateNcaData, updateTitlekey, secureValue, subEntry, fileOffset, readLen
                );
                merged.set(chunk, writePos);

                writePos += readLen;
                currentPhys += readLen;
            }
        } else {
            // Copy from base romfs
            const baseOffset = entry.physOffset + (pos - entry.virtOffset);
            if (baseOffset + readSize > baseRomfsDecrypted.length) {
                throw new Error(`BKTR: base read OOB at 0x${baseOffset.toString(16)}`);
            }
            merged.set(baseRomfsDecrypted.subarray(baseOffset, baseOffset + readSize), pos);
        }

        pos = chunkEnd;
        entryIdx++;
    }

    return {
        merged: merged,                      // full virtual image (IVFC header + hash levels + data) — for verification scripts
        mergedData: merged.subarray(dataLevelOffset, dataLevelOffset + dataLevelSize), // level-5 data only — the RomFS image to repack
        dataOffset: dataLevelOffset,
        relocEntries: relocBlock.entries.length,
        subsectionEntries: subBlock.entries.length,
    };
}
