import { AesCtr } from '../crypto/aes-ops.mjs';
import { decryptNcaHeader } from './nca.js';
import { BufferRangeSource } from './range-source.js';
import { markMerge } from './debug-trace.js';
import { decryptNcaHeaderBytes, reversedSectionCtr, extractTitlekeyFromTik, deriveTitlekeyFromKeyArea } from './nca-utils.js';
import {
    parseBktrHeader,
    decryptBktrTableData,
    parseRelocationBlock,
    parseSubsectionBlock,
    findSubsectionEntry,
    subEntryIdx,
    decryptPatchRegionData,
    lookupTitlekeyFromDatabase,
} from './bktr.js';

// Accept either a full NCA buffer (Uint8Array) or an NcaInput:
// { headerRaw: Uint8Array(0xC00), source: RangeSource } where
// source.read(offset, length) serves NCA ciphertext by absolute offset.
function toNcaInput(nca) {
    if (nca && typeof nca.subarray === 'function' && !nca.source) {
        return { headerRaw: nca.subarray(0, 0xC00), source: new BufferRangeSource(nca) };
    }
    return nca;
}

const BKTR_HEADER_OFFSET = 0x100;

export async function mergeRomFS(baseNcaData, updateNcaData, options = {}) {
    const { keys, onChunk, baseTitlekey: providedBaseTitlekey, updateTitlekey: providedUpdateTitlekey, baseTik, updateTik, titlekeysFile, state } = options;
    // Optional mutable { desc } — the caller's watchdog prints it to show which
    // await the merge is currently blocked on (diagnostics, no behavior change).
    // Also mirrored into the global trace so the write-side watchdog sees it too.
    const _mark = (d) => { markMerge(d); if (state) state.desc = d; };

    if (!keys) throw new Error('BKTR: keys required');

    baseNcaData = toNcaInput(baseNcaData);
    updateNcaData = toNcaInput(updateNcaData);

    const baseHeader = decryptNcaHeader(baseNcaData.headerRaw, keys);
    const updateHeader = decryptNcaHeader(updateNcaData.headerRaw, keys);
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

    // Decrypt NCA headers (raw bytes)
    const updateDecHeader = decryptNcaHeaderBytes(updateNcaData.headerRaw, keys);
    const baseDecHeader = decryptNcaHeaderBytes(baseNcaData.headerRaw, keys);

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
    const updateNonce = reversedSectionCtr(updateFsHdr);

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

    // Decrypt BKTR tables (read only the table ranges from the update source)
    _mark('decrypting BKTR tables');
    const relocAbsOffset = updateRomfsSec.offset + relocHeader.offset;
    const subAbsOffset = updateRomfsSec.offset + subHeader.offset;
    const relocTableBuf = await decryptBktrTableData(
        await updateNcaData.source.read(relocAbsOffset, relocHeader.size),
        updateTitlekey, updateNonce, relocAbsOffset
    );
    const subTableBuf = await decryptBktrTableData(
        await updateNcaData.source.read(subAbsOffset, subHeader.size),
        updateTitlekey, updateNonce, subAbsOffset
    );

    const relocBlock = parseRelocationBlock(relocTableBuf);
    const subBlock = parseSubsectionBlock(subTableBuf);
    if (relocBlock.entries.length === 0) throw new Error('BKTR: no relocation entries');
    if (subBlock.entries.length === 0) throw new Error('BKTR: no subsection entries');

    // Pre-register the base romfs ranges (in strictly increasing order) so an
    // NCZ stream source can serve them in ONE sequential decompression pass
    // without buffering the whole base romfs section. File/buffer sources
    // ignore registration.
    for (let i = 0; i < relocBlock.entries.length; i++) {
        const e = relocBlock.entries[i];
        if (e.isPatch) continue;
        const nextVirt = i + 1 < relocBlock.entries.length
            ? relocBlock.entries[i + 1].virtOffset : relocBlock.totalSize;
        baseNcaData.source.registerRange(baseRomfsSecMeta.offset + e.physOffset, nextVirt - e.virtOffset);
    }

    // Base romfs is decrypted IN PLACE, per relocation entry, directly into
    // `merged` (chunked, transient 16 MB) from the source's ciphertext — no
    // full-image buffer (the old approach decrypted the whole ~850 MB section
    // up front and it lived alongside `merged` for the entire merge).
    // Counter base = section offset (AesCtr counter = absolute section byte / 16).
    const baseFsHdr = baseDecHeader.subarray(0x400 + baseRomfsSecMeta.secIdx * 0x200, 0x400 + baseRomfsSecMeta.secIdx * 0x200 + 0x200);
    const baseNonce = reversedSectionCtr(baseFsHdr);
    const baseCtr = new AesCtr(baseTitlekey, baseNonce);
    const BASE_DECRYPT_CHUNK = 0x1000000; // 16 MB

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
    // Streaming mode: when an onChunk(chunk, romfsDataOffset) callback is given, only the
    // level-5 DATA region [dataLevelOffset, dataLevelOffset+dataLevelSize) is emitted through
    // the callback and the full virtual-image buffer is NOT allocated. Buffered mode (no
    // onChunk) builds `merged` as before (used by verification scripts).
    const streaming = typeof onChunk === 'function';
    const totalSize = relocBlock.totalSize;
    const merged = streaming ? null : new Uint8Array(totalSize);
    const dataStart = dataLevelOffset;
    const dataEnd = dataLevelOffset + dataLevelSize;
    let pos = 0;
    let entryIdx = 0;

    while (pos < totalSize && entryIdx < relocBlock.entries.length) {
        const entry = relocBlock.entries[entryIdx];
        const nextVirt = entryIdx + 1 < relocBlock.entries.length
            ? relocBlock.entries[entryIdx + 1].virtOffset
            : totalSize;
        const chunkEnd = Math.min(nextVirt, totalSize);
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
                // Cap at 16 MB so the decrypted `chunk` buffer stays small even for
                // large patch entries (the counter is absolute, so chunking is safe).
                const readLen = Math.min(remainingInSub, remainingToWrite, BASE_DECRYPT_CHUNK);

                const fileOffset = updateRomfsSec.offset + currentPhys;
                _mark('patch read @0x' + fileOffset.toString(16));
                const patchRaw = await updateNcaData.source.read(fileOffset, readLen);
                _mark('patch decrypt @0x' + fileOffset.toString(16));
                const chunk = await decryptPatchRegionData(
                    patchRaw, updateTitlekey, secureValue, subEntry, fileOffset
                );
                if (streaming) {
                    const a = Math.max(writePos, dataStart);
                    const b = Math.min(writePos + readLen, dataEnd);
                    if (b > a) {
                        _mark('emit @romfs 0x' + (a - dataStart).toString(16));
                        await onChunk(chunk.subarray(a - writePos, b - writePos), a - dataStart);
                    }
                } else {
                    merged.set(chunk, writePos);
                }

                writePos += readLen;
                currentPhys += readLen;
            }
        } else {
            // Copy from base romfs: read the ciphertext range from the source
            // and decrypt it straight into merged (no full-image buffer).
            const baseOffset = entry.physOffset + (pos - entry.virtOffset);
            if (baseOffset + readSize > baseRomfsSecMeta.size) {
                throw new Error(`BKTR: base read OOB at 0x${baseOffset.toString(16)}`);
            }
            // Read the base ciphertext in 16 MB chunks (not the whole entry) so the
            // transient `cipher` buffer stays small even for large unpatched entries.
            // FileRangeSource reads from the container; NczStreamSource serves a view
            // of its (already-buffered) registered range.
            let done = 0;
            while (done < readSize) {
                const n = Math.min(BASE_DECRYPT_CHUNK, readSize - done);
                _mark('base read @0x' + (baseRomfsSecMeta.offset + baseOffset + done).toString(16));
                const cipher = await baseNcaData.source.read(baseRomfsSecMeta.offset + baseOffset + done, n);
                baseCtr.seek(baseRomfsSecMeta.offset + baseOffset + done);
                const dec = await baseCtr.decrypt(cipher);
                if (streaming) {
                    const a = Math.max(pos + done, dataStart);
                    const b = Math.min(pos + done + n, dataEnd);
                    if (b > a) {
                        _mark('emit @romfs 0x' + (a - dataStart).toString(16));
                        await onChunk(dec.subarray(a - (pos + done), b - (pos + done)), a - dataStart);
                    }
                } else {
                    merged.set(dec, pos + done);
                }
                done += n;
            }
        }

        pos = chunkEnd;
        entryIdx++;
    }

    return {
        mergedData: streaming ? null : merged.subarray(dataLevelOffset, dataLevelOffset + dataLevelSize),
        dataOffset: dataLevelOffset,
        dataLevelSize,
        relocEntries: relocBlock.entries.length,
        subsectionEntries: subBlock.entries.length,
    };
}
