import { PFS0, PFS0Writer } from './pfs0.js';
import { buildAdapter, buildRead, collectBlob, copyRange } from './adapter.js';
import { openContainer } from './container.js';
import { NCZDecompressor, AdapterNCZReader, parseNczSections } from './ncz.js';
import { decryptNcaHeader, decryptNcaSection, parseCnmtFromDecryptedSection } from './nca.js';
import { Cnmt } from './cnmt.js';
import { sha256 } from '../crypto/sha256.js';
import { mergeRomFS } from './bktr-merge.js';
import { FileRangeSource, NczStreamSource, ViewRangeSource, SparseNcaView } from './range-source.js';
import { preparePlaintextProgramNca, writePlaintextProgramNca, packProgramNcaStream, computeProgramNcaContentId, writeProgramNcaTwoPass, extractExefsStream, extractRomfsStream, createExefsAcidFilter, packMetaNca, extractExefs, extractRomfs, processNpdmAcid, twoPassLayout } from './nca-pack.js';
import { hexToBytes, writeU64LE, writeU32LE, NCA_HEADER_SIZE, decryptNcaHeaderBytes, findRomfsFsHeader } from './nca-utils.js';
import { writeFromReader } from './convert-common.js';
import { trace } from './debug-trace.js';

function u32le(v) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v >>> 0, true);
    return b;
}

function u16le(v) {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, v, true);
    return b;
}

// Total plaintext Program NCA size from ExeFS and RomFS data sizes.
function programNcaSize(exefsSize, romfsDataSize) {
    return twoPassLayout(exefsSize, romfsDataSize).ncaSize;
}

// Extract romfsDataSize / exefsSize from the decrypted update NCA header.
// Used by the BKTR streaming paths (identical logic).
function parseUpdateSectionSizes(updateHeaderDec, updateHeaderRaw, updateRomfsSec, updateExefsSec, keys) {
    const decBytes = decryptNcaHeaderBytes(updateHeaderRaw, keys);
    const romfsIdx = updateHeaderDec.sections.indexOf(updateRomfsSec);
    const romfsFsHdr = decBytes.subarray(0x400 + romfsIdx * 0x200, 0x400 + (romfsIdx + 1) * 0x200);
    const romfsDataSize = Number(new DataView(romfsFsHdr.buffer, romfsFsHdr.byteOffset + 0x98, 8).getBigUint64(0, true));
    const exefsIdx = updateHeaderDec.sections.indexOf(updateExefsSec);
    const exefsFsHdr = decBytes.subarray(0x400 + exefsIdx * 0x200, 0x400 + (exefsIdx + 1) * 0x200);
    const exefsSize = Number(new DataView(exefsFsHdr.buffer, exefsFsHdr.byteOffset + 0x48, 8).getBigUint64(0, true));
    return { romfsDataSize, exefsSize, programSize: programNcaSize(exefsSize, romfsDataSize) };
}

// Build a ContentMeta: 0x20 header + extended header + 0x38 content infos (+ digest).
function buildCnmt(tidHex, version, type, extHdr, entries, withDigest) {
    const cnmt = new Uint8Array(0x20 + extHdr.length + entries.length * 0x38 + (withDigest ? 0x20 : 0));
    const tid = hexToBytes(tidHex).reverse();
    let o = 0;
    cnmt.set(tid, o); o += 8;
    cnmt.set(u32le(version), o); o += 4;
    cnmt[o++] = type;
    cnmt[o++] = 0x00;
    cnmt.set(u16le(extHdr.length), o); o += 2;
    cnmt.set(u16le(entries.length), o); o += 2;
    cnmt.set(u16le(0), o); o += 2;
    cnmt[o++] = 0x00;
    o += 3;
    o += 4;
    o += 4;
    cnmt.set(extHdr, o); o += extHdr.length;
    for (const ci of entries) { cnmt.set(ci, o); o += 0x38; }
    if (withDigest) {
        const digest = sha256(cnmt.subarray(0, o));
        cnmt.set(hexToBytes(digest), o);
    }
    return cnmt;
}

function contentInfo(hashHex, type, size) {
    const ci = new Uint8Array(0x38);
    ci.set(hexToBytes(hashHex), 0);
    ci.set(hexToBytes(hashHex.slice(0, 32)), 0x20);
    const sz = new Uint8Array(8);
    new DataView(sz.buffer).setBigUint64(0, BigInt(size), true);
    ci.set(sz.subarray(0, 5), 0x30);
    ci[0x36] = type;
    return ci;
}

async function readCnmtNca(reader, entry, keys) {
    const raw = await reader.read(entry.offset, entry.size);
    const header = decryptNcaHeader(raw.subarray(0, Math.min(entry.size, 0xC00)), keys);
    if (!header || header.contentType !== 1) return null;
    const section = header.sections[0];
    if (!section) return null;
    const data = await reader.read(entry.offset + section.offset, section.size);
    const fsData = await decryptNcaSection(data, section);
    const cnmt = parseCnmtFromDecryptedSection(fsData, section);
    if (!cnmt) return null;
    const pfs0Raw = fsData.subarray(section.sectionStart);
    const files = new PFS0(pfs0Raw).getFiles();
    let cnmtRaw = null;
    let pfs0FileName = null;
    if (files.length > 0) {
        const f = files[0];
        pfs0FileName = f.name;
        cnmtRaw = pfs0Raw.subarray(f.offset, f.offset + f.size);
    }
    return { header, section, cnmt, cnmtRaw, pfs0FileName, fsData };
}

// Rebuild the base .cnmt.nca so its CNMT references the update's content NCAs
// (program/manual/publicdata) as full replacements under the base titleId.
// Matches The-4n/hacPack create_meta: CRYPT_CTR section, XTS header, zero sig.
async function rebuildCnmtNca(baseMeta, updateMeta, keys, log, mergedProgram = null) {
    const baseCnmt = baseMeta.cnmt;
    const updateCnmt = updateMeta.cnmt;

    const entries = [];
    for (const e of updateCnmt.contentEntries) {
        if (e.type === 6) continue;
        if (e.type === 1 && mergedProgram) {
            entries.push(contentInfo(mergedProgram.hashHex, 1, mergedProgram.size));
            continue;
        }
        // yanu uses type=4 for PublicData (BaseData), not type=5
        const entryType = e.type === 5 ? 4 : e.type;
        entries.push(contentInfo(e.hash, entryType, e.size));
    }
    log('info', `CNMT: base ${baseCnmt.titleId} v${baseCnmt.version} -> v${updateCnmt.version}, ${entries.length} contents` +
        (mergedProgram ? ` (program: merged NCA ${mergedProgram.hashHex.slice(0, 16)}...)` : ''));

    // Copy the base Application CNMT's extended header verbatim (keeps PatchId /
    // RequiredSystemVersion semantics intact for the same titleType).
    const extHdr = baseCnmt.tableOffset > 0
        ? baseMeta.cnmtRaw.slice(0x20, 0x20 + baseCnmt.tableOffset)
        : new Uint8Array(0x10);
    const cnmt = buildCnmt(baseCnmt.titleId, updateCnmt.version, 0x80, extHdr, entries, true);
    const parsed = Cnmt.parse(cnmt);
    if (parsed.contentEntryCount !== entries.length || parsed.version !== updateCnmt.version) {
        throw new Error('update: internal CNMT rebuild validation failed');
    }

    // Build the CNMT NCA using packMetaNca (hacpack create_meta mode).
    // packMetaNca handles: PFS0 → hash table → FsHeader → NCA header → CTR section → XTS header.
    const result = await packMetaNca(
        cnmt, baseMeta.pfs0FileName, baseCnmt.titleId, keys, log
    );
    return result;
}


// Extract a specific section from a potentially-NCZ-compressed NCA.
// For NCZ: streams through decompression but only buffers the requested section range.
// For plain NCA: direct read.
// Returns Uint8Array of the section data (NCA section bytes, decrypted).
async function extractNcaSection(reader, ncaOffset, ncaSize, isNcz, keys, log) {
    if (!isNcz) {
        return await reader.read(ncaOffset, ncaSize);
    }

    // NCZ: stream decompression, buffer only [ncaOffset, ncaOffset + ncaSize]
    const parsed = await parseNczSections(reader);
    if (ncaOffset + ncaSize > parsed.ncaSize) {
        throw new Error(`extractNcaSection: section range [${ncaOffset}, ${ncaOffset + ncaSize}) exceeds NCA size ${parsed.ncaSize}`);
    }

    const sectionBuffer = new Uint8Array(ncaSize);
    let sectionFilled = 0;
    let done = false;
    const sectionEnd = ncaOffset + ncaSize;

    const decomp = new NCZDecompressor(reader);
    try {
        await decomp.decompress(
            () => {},
            (chunk, offset) => {
                // Early stop: once past our section end, no more data needed
                // (NCZ is sequential: all blocks after our section can be skipped)
                if (offset >= sectionEnd) {
                    done = true;
                    throw new Error('SECTION_COMPLETE');
                }

                // Check if chunk overlaps with our target section
                const chunkEnd = offset + chunk.length;
                if (chunkEnd <= ncaOffset) return; // before our section

                const startInChunk = Math.max(0, ncaOffset - offset);
                const endInChunk = Math.min(chunk.length, sectionEnd - offset);
                const data = chunk.subarray(startInChunk, endInChunk);
                const targetOffset = Math.max(0, offset - ncaOffset);

                sectionBuffer.set(data, targetOffset);
                sectionFilled += data.length;
            },
            parsed,
        );
    } catch (e) {
        if (e.message !== 'SECTION_COMPLETE') throw e;
    }

    if (sectionFilled !== ncaSize) {
        throw new Error(`extractNcaSection: incomplete section data (${sectionFilled}/${ncaSize})`);
    }

    log('info', `Extracted NCA section [0x${ncaOffset.toString(16)}, 0x${(ncaOffset + ncaSize).toString(16)}) = ${ncaSize} bytes (streaming NCZ)`);
    return sectionBuffer;
}

// (SparseNcaView moved to ./range-source.js)

// ── Shared helpers for BKTR streaming paths ──────────────────────────────────

function collectOtherNcas(update) {
    const otherNcas = [];
    for (const e of update.cnmt.contentEntries) {
        if (e.type === 6 || e.type === 1) continue;
        const src = update.entries.find(x =>
            x.name.toLowerCase().startsWith(e.ncaId) && !x.name.toLowerCase().endsWith('.cnmt.nca'));
        if (src) otherNcas.push({
            name: src.name.replace(/\.ncz$/i, '.nca'),
            size: e.size,
            reader: update.reader,
            offset: src.offset,
            isNcz: src.name.toLowerCase().endsWith('.ncz'),
        });
    }
    otherNcas.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    return otherNcas;
}

async function writeOtherNcas(adapter, update, pfs0Header, pw, otherNcas, written, totalData, progress, log) {
    for (let i = 0; i < otherNcas.length; i++) {
        const m = otherNcas[i];
        const member = pw.files[i + 1];
        const pos = pfs0Header.headerSize + member.offset;
        await writeFromReader(adapter, pos, m,
            (p) => progress((written + member.size * p) / totalData, `Decompressing ${m.name}...`));
        log('info', `[WRITTEN] ${m.name} (${m.size} bytes)`);
        written += member.size;
    }
    return written;
}

async function writeCnmt(adapter, pfs0Header, pw, rebuilt, log) {
    const cnmtPfs0Offset = pfs0Header.headerSize + pw.files[pw.files.length - 1].offset;
    // Capture the size BEFORE the write: the SW adapter transfers the buffer
    // (detaches it), so rebuilt.nca.length would read 0 afterwards.
    const cnmtSize = rebuilt.nca.length;
    await adapter.write(cnmtPfs0Offset, rebuilt.nca);
    log('info', `[WRITTEN] ${rebuilt.name} (${cnmtSize} bytes)`);
}

function finishOutput(adapter, pfs0Header, totalData, pw, output, log) {
    const totalSize = pfs0Header.headerSize + totalData;
    log('info', `Updated NSP: ${pw.files.length} members, ${totalSize} bytes`);
    if (output.memory) {
        return { size: totalSize, blob: collectBlob(adapter, totalSize), memberCount: pw.files.length };
    }
    return { size: totalSize, memberCount: pw.files.length };
}

// Build the final output PFS0 layout: program NCA first, then other NCAs,
// then the rebuilt CNMT (yanu member order). Returns the writer, header,
// total data size, and the Program NCA's offset within the output.
function buildFinalPfs0(programName, programSize, otherNcas, rebuilt) {
    const pw = new PFS0Writer(true, null, 0x10);
    pw.add(programName, programSize);
    for (const m of otherNcas) pw.add(m.name, m.size);
    pw.add(rebuilt.name, rebuilt.nca.length);
    const pfs0Header = pw.buildHeader();
    const totalData = pw.files.reduce((s, f) => s + f.size, 0);
    const programNcaPfs0Offset = pfs0Header.headerSize + pw.files[0].offset;
    return { pw, pfs0Header, totalData, programNcaPfs0Offset };
}

// Write the tail of the output NSP: the non-Program NCAs, then the CNMT,
// then finish. pfs0Header is the header used to compute member offsets
// (normally the one just built; the seekback path passes its layout header,
// which is size-identical to the real one).
async function finalizeOutputNsP(adapter, { pfs0Header, pw, otherNcas, programSize, totalData, rebuilt, update, output, log, progress }) {
    await writeOtherNcas(adapter, update, pfs0Header, pw, otherNcas, programSize, totalData, progress, log);
    await writeCnmt(adapter, pfs0Header, pw, rebuilt, log);
    return finishOutput(adapter, pfs0Header, totalData, pw, output, log);
}

// Two-pass tail (shared by BKTR and non-BKTR two-pass paths): write the Program
// NCA in pass 2 (streaming), rebuild the CNMT, then the other NCAs + CNMT.
// Sources must already be nulled by the caller.
//
// No placeholder PFS0 header in either mode — only the write ORDER differs:
//   appendOnly (SW download): the stream can only grow, so the PFS0 header
//     (which contains the contentId filename) must be written BEFORE the NCA.
//     contentId is therefore precomputed in Pass 1 (contentIdInPass1) and Pass 2
//     skips the hash. 3× romfs reads.
//   seekable (FSA / memory): the NCA is written first (the adapter zero-fills
//     [0..programNcaPfs0Offset)), then the real header overwrites offset 0.
//     contentId piggybacks on the Pass 2 write. 2× romfs reads.
async function writeTwoPassProgramAndFinish({ adapter, base, update, keys, log, progress, output, programSize, meta, makeStreamExefs, makeStreamRomfs, contentId, appendOnly }) {
    const otherNcas = collectOtherNcas(update);
    const progProgress = (headerSize, total) => (p) => progress((headerSize + p * programSize) / total, 'Writing Program NCA...');

    if (appendOnly) {
        // contentId is final after Pass 1 → real PFS0 header first, then the NCA.
        const rebuilt = await rebuildCnmtNca(base, update, keys, log, { hashHex: contentId, size: programSize });
        const { pw, pfs0Header, totalData, programNcaPfs0Offset } = buildFinalPfs0(`${contentId.slice(0, 32)}.nca`, programSize, otherNcas, rebuilt);
        await adapter.write(0, pfs0Header.buffer);
        log('info', `PFS0 header ${pfs0Header.headerSize} bytes, ${pw.files.length} members`);
        await writeProgramNcaTwoPass({
            meta, adapter, ncaOffset: programNcaPfs0Offset, contentId,
            streamExefs: makeStreamExefs(), streamRomfs: makeStreamRomfs(), log,
            progress: progProgress(pfs0Header.headerSize, totalData),
        });
        return finalizeOutputNsP(adapter, { pfs0Header, pw, otherNcas, programSize, totalData, rebuilt, update, output, log, progress });
    }

    // Seekable: compute the layout in memory only (temp names are the same
    // LENGTH as the real ones — 36/41 chars — so headerSize and offsets are
    // identical to the final header), write the NCA, then the real header at 0.
    const TEMP_PROG = '0'.repeat(36);
    const TEMP_CNMT = '0'.repeat(41); // matches `${id}.cnmt.nca` length
    const { pfs0Header: layoutHdr, totalData: layoutTotal, programNcaPfs0Offset } = buildFinalPfs0(TEMP_PROG, programSize, otherNcas, { name: TEMP_CNMT, nca: new Uint8Array(0) });
    const id = await writeProgramNcaTwoPass({
        meta, adapter, ncaOffset: programNcaPfs0Offset,
        streamExefs: makeStreamExefs(), streamRomfs: makeStreamRomfs(), log,
        progress: progProgress(layoutHdr.headerSize, layoutTotal),
    });
    log('info', `ContentId: ${id} (${programSize} bytes)`);
    const rebuilt = await rebuildCnmtNca(base, update, keys, log, { hashHex: id, size: programSize });
    const { pw, pfs0Header, totalData } = buildFinalPfs0(`${id.slice(0, 32)}.nca`, programSize, otherNcas, rebuilt);
    await adapter.write(0, pfs0Header.buffer);
    log('info', `PFS0 header ${pfs0Header.headerSize} bytes, ${pw.files.length} members`);
    return finalizeOutputNsP(adapter, { pfs0Header, pw, otherNcas, programSize, totalData, rebuilt, update, output, log, progress });
}

// Factory for a streaming ExeFS extractor with NPDM ACID filtering applied.
// Each call returns a fresh stream (new acidFilter) so pass-1 and pass-2
// streaming both get clean state.
function makeExefsStream(updateInput, keys, updateTikData, options, log) {
    return async (emit) => {
        const acidFilter = createExefsAcidFilter({
            keepSig: options.keepNpdmAcidSig === true,
            keepKey: options.keepNpdmAcidKey === true,
        }, log);
        await extractExefsStream(updateInput, keys, updateTikData, async (chunk, off) => {
            await acidFilter(chunk, off);
            await emit(chunk, off);
        });
    };
}

export async function update(readers, output, options = {}) {
    const { log = () => {}, progress = () => {}, keys = null, updateMode = 'auto' } = options;

    if (!Array.isArray(readers) || readers.length !== 2) {
        throw new Error('update: exactly two inputs required (base + update)');
    }
    if (!keys) {
        throw new Error('update: requires keys (--keys / keys file) to decrypt CNMT metadata');
    }

    // Phase 1: read both containers and their CNMTs
    const metas = [];
    for (let i = 0; i < readers.length; i++) {
        const r = readers[i];
        const { kind, entries } = await openContainer(r);
        log('info', `Reading ${r.name}: ${entries.length} entries (${kind})`);
        const cnmtEntry = entries.find(e => e.name.toLowerCase().endsWith('.cnmt.nca'));
        if (!cnmtEntry) throw new Error(`update: no .cnmt.nca found in ${r.name}`);
        const m = await readCnmtNca(r.reader, cnmtEntry, keys);
        if (!m) throw new Error(`update: cannot decrypt/parse CNMT in ${r.name}`);
        m.raw = await r.reader.read(cnmtEntry.offset, cnmtEntry.size);
        m.cnmtNcaName = cnmtEntry.name;
        m.reader = r.reader;
        m.entries = entries;
        metas.push(m);
    }

    // base = the input whose CNMT is the Application (titleType 0x80); update = the patch
    const [m0, m1] = metas;
    let base, update;
    if (m0.cnmt.titleType === 0x80 && m1.cnmt.titleType !== 0x80) {
        base = m0; update = m1;
    } else if (m1.cnmt.titleType === 0x80 && m0.cnmt.titleType !== 0x80) {
        base = m1; update = m0;
    } else {
        throw new Error('update: cannot determine base/update pair (exactly one Application CNMT required)');
    }

    log('info', `Base:   ${base.cnmt.titleId} v${base.cnmt.version} (${base.cnmtNcaName})`);
    log('info', `Update: ${update.cnmt.titleId} v${update.cnmt.version} (${update.cnmtNcaName})`);
    if (base.cnmt.version >= update.cnmt.version) {
        log('warn', `Update: update version ${update.cnmt.version} is not newer than base ${base.cnmt.version}`);
    }

    // Check if update Program NCA has BKTR section (cryptoType=4) for yanu-style merge
    const bktrMerge = options.bktrMerge !== false; // Enabled by default if BKTR section found
    let baseProgramEntry = null;
    let updateProgramEntry = null;

    // Find base and update Program NCA entries (Program content type = 1)
    for (const e of base.cnmt.contentEntries) {
        if (e.type === 1) { // Program NCA
            const src = base.entries.find(x =>
                x.name.toLowerCase().startsWith(e.ncaId) && !x.name.toLowerCase().endsWith('.cnmt.nca'));
            if (src) {
                log('info', `Base Program NCA: ${src.name} (${src.size} bytes)`);
                baseProgramEntry = { entry: e, src };
            }
        }
    }
    for (const e of update.cnmt.contentEntries) {
        if (e.type === 1) { // Program NCA
            const src = update.entries.find(x =>
                x.name.toLowerCase().startsWith(e.ncaId) && !x.name.toLowerCase().endsWith('.cnmt.nca'));
            if (src) {
                log('info', `Update Program NCA: ${src.name} (${src.size} bytes)`);
                updateProgramEntry = { entry: e, src };
                break;
            }
        }
    }

    // Check for BKTR RomFS in update Program NCA
    let hasBktrRomfs = false;
    let updateHasRomfs = false;
    let updateHasExefs = false;
    if (updateProgramEntry && bktrMerge) {
        let rawHeader;
        if (updateProgramEntry.src.name.toLowerCase().endsWith('.ncz')) {
            // NCZ: decompress first to get the real NCA header
            log('info', 'Decompressing update Program NCA header for BKTR check...');
            const nczReader = new AdapterNCZReader(update.reader, updateProgramEntry.src.offset, updateProgramEntry.src.size);
            const parsed = await parseNczSections(nczReader);
            const decomp = new NCZDecompressor(nczReader);
            const headerSize = 0xC00;
            rawHeader = new Uint8Array(headerSize);
            await decomp.decompress(
                () => {},
                (chunk, offset) => {
                    if (offset >= headerSize) return;
                    const end = Math.min(offset + chunk.length, headerSize);
                    rawHeader.set(chunk.subarray(0, end - offset), offset);
                },
                parsed,
            );
        } else {
            rawHeader = await update.reader.read(
                updateProgramEntry.src.offset,
                Math.min(updateProgramEntry.src.size, 0xC00)
            );
        }
        const uHeader = decryptNcaHeader(rawHeader, keys);
        if (uHeader) {
            hasBktrRomfs = !!uHeader.sections.find(s => s.fsType === 3 && s.cryptoType === 4);
            updateHasRomfs = !!uHeader.sections.find(s => s.fsType === 3 && s.size > 0);
            updateHasExefs = !!uHeader.sections.find(s => s.fsType === 2 && s.size > 0);
            log('info', `Update Program NCA: BKTR RomFS=${hasBktrRomfs}, RomFS section=${updateHasRomfs}, ExeFS=${updateHasExefs}`);
        }
    }

    // Pre-read the base/update .tik titlekey data — the BKTR merge needs the titlekeys
    // before the ticket members are assembled below.
    let baseTikData = null;
    let updateTikData = null;
    for (const c of [base, update]) {
        for (const e of c.entries) {
            const lower = e.name.toLowerCase();
            if (lower.endsWith('.tik')) {
                const tikData = await c.reader.read(e.offset, e.size);
                if (c === base) baseTikData = tikData;
                if (c === update) updateTikData = tikData;
            }
        }
    }

    // Yanu-style merge: build the merged Program NCA BEFORE the CNMT, so the
    // rebuilt CNMT's program content entry can reference the merged NCA's own
    // sha256/id/size (hacpack does the same). Otherwise the CNMT would point at the
    // update Program NCA which is no longer shipped — installers would report
    // missing/corrupt program content.
    //
    // The merge runs for two kinds of update Program NCAs:
    //   - BKTR patch (fsType=3, cryptoType=4): merged RomFS = base + BKTR delta.
    //   - ExeFS-only (no RomFS section at all): the update ships only new code;
    //     the game data still lives in the base RomFS, so the merged Program NCA
    //     is update ExeFS + base RomFS (+ base Control). Shipping the ExeFS-only
    //     update NCA alone would produce an NSP without any game data.
    // An update Program NCA that carries its own full RomFS (fsType=3, non-BKTR)
    // is self-contained and goes through the standard path unchanged.
    let mergedProgram = null;
    const needsMerge = baseProgramEntry && updateProgramEntry && (hasBktrRomfs || (!updateHasRomfs && updateHasExefs));
    if (needsMerge) {
        const baseIsNcz = baseProgramEntry.src.name.toLowerCase().endsWith('.ncz');
        const updateIsNcz = updateProgramEntry.src.name.toLowerCase().endsWith('.ncz');
        const baseReader = new AdapterNCZReader(base.reader, baseProgramEntry.src.offset, baseProgramEntry.src.size);
        const updateReader = new AdapterNCZReader(update.reader, updateProgramEntry.src.offset, updateProgramEntry.src.size);

        // ── Extract base Program NCA header ──────────────────────────────────
        log('info', `Reading base Program NCA header (${baseIsNcz ? 'from NCZ' : 'direct'})...`);
        let baseHeaderRaw;
        let baseParsed = null;
        if (baseIsNcz) {
            baseParsed = await parseNczSections(baseReader);
            baseHeaderRaw = new Uint8Array(NCA_HEADER_SIZE);
            const decomp = new NCZDecompressor(baseReader);
            await decomp.decompress(() => {}, (chunk, offset) => {
                if (offset >= NCA_HEADER_SIZE) return;
                const end = Math.min(offset + chunk.length, NCA_HEADER_SIZE);
                baseHeaderRaw.set(chunk.subarray(0, end - offset), offset);
            }, baseParsed);
        } else {
            baseHeaderRaw = await base.reader.read(baseProgramEntry.src.offset, NCA_HEADER_SIZE);
        }
        const baseHeaderDec = decryptNcaHeader(baseHeaderRaw, keys);
        if (!baseHeaderDec) throw new Error('update: cannot decrypt base Program NCA header');

        // ── Extract update Program NCA header ────────────────────────────────
        log('info', `Reading update Program NCA header (${updateIsNcz ? 'from NCZ' : 'direct'})...`);
        let updateHeaderRaw;
        if (updateIsNcz) {
            const parsed = await parseNczSections(updateReader);
            updateHeaderRaw = new Uint8Array(NCA_HEADER_SIZE);
            const decomp = new NCZDecompressor(updateReader);
            await decomp.decompress(() => {}, (chunk, offset) => {
                if (offset >= NCA_HEADER_SIZE) return;
                const end = Math.min(offset + chunk.length, NCA_HEADER_SIZE);
                updateHeaderRaw.set(chunk.subarray(0, end - offset), offset);
            }, parsed);
        } else {
            updateHeaderRaw = await update.reader.read(updateProgramEntry.src.offset, NCA_HEADER_SIZE);
        }
        const updateHeaderDec = decryptNcaHeader(updateHeaderRaw, keys);
        if (!updateHeaderDec) throw new Error('update: cannot decrypt update Program NCA header');

        // ── Build NCA range sources (the NSZ→NSP converter's streaming discipline) ──
        // Base: the whole NCA is served from the container — .nsp is random access,
        // .nsz is ONE sequential NCZ decompression pass (base offsets are monotonic
        // in merge order, so every needed range is served in-stream; nothing is
        // buffered beyond transient 16 MB decrypt chunks).
        // Update: patch physical offsets are NOT monotonic, so a .nsz update cannot
        // stream — its BKTR + ExeFS sections are decompressed once and served from a
        // zero-copy sparse view. A .nsp update is read on demand from the container.
        const baseRomfsSec = baseHeaderDec.sections.find(s => s.fsType === 3);
        const updateRomfsSec = updateHeaderDec.sections.find(s => s.fsType === 3 && s.cryptoType === 4);
        const updateExefsSec = updateHeaderDec.sections.find(s => s.fsType === 2);

        if (!baseRomfsSec) throw new Error('update: base Program NCA has no RomFS section');
        if (!updateExefsSec) throw new Error('update: update Program NCA has no ExeFS section');

        let baseSource;
        if (baseIsNcz) {
            log('info', `Base .nsz: RomFS section (0x${baseRomfsSec.offset.toString(16)}..0x${(baseRomfsSec.endOffset).toString(16)}) streamed from NCZ, nothing buffered...`);
            baseSource = new NczStreamSource(baseReader, baseParsed, log);
        } else {
            log('info', `Base .nsp: RomFS section (0x${baseRomfsSec.offset.toString(16)}..0x${(baseRomfsSec.endOffset).toString(16)}) read on demand from container...`);
            baseSource = new FileRangeSource(base.reader, baseProgramEntry.src.offset, baseProgramEntry.src.size);
        }

        let updateSource;
        if (updateIsNcz) {
            let updateBktrData = null;
            if (hasBktrRomfs && updateRomfsSec) {
                log('info', `Extracting update BKTR section (0x${updateRomfsSec.offset.toString(16)}..0x${(updateRomfsSec.endOffset).toString(16)})...`);
                await new Promise(r => setTimeout(r, 0));
                updateBktrData = await extractNcaSection(
                    updateReader, updateRomfsSec.offset, updateRomfsSec.endOffset - updateRomfsSec.offset,
                    updateIsNcz, keys, log
                );
            }
            log('info', `Extracting update ExeFS section (0x${updateExefsSec.offset.toString(16)}..0x${(updateExefsSec.endOffset).toString(16)})...`);
            await new Promise(r => setTimeout(r, 0));
            const updateExefsData = await extractNcaSection(
                updateReader, updateExefsSec.offset, updateExefsSec.endOffset - updateExefsSec.offset,
                updateIsNcz, keys, log
            );
            const updateSections = [];
            if (updateBktrData) updateSections.push({ offset: updateRomfsSec.offset, data: updateBktrData });
            updateSections.push({ offset: updateExefsSec.offset, data: updateExefsData });
            const updateView = new SparseNcaView(updateHeaderRaw, updateSections);
            updateSource = new ViewRangeSource(updateView);
            log('info', `Update .nsz: ${updateSections.length} section(s) served from zero-copy sparse view (${updateView.length} bytes) — patch access is non-monotonic, so these stay buffered`);
        } else {
            log('info', 'Update .nsp: BKTR/ExeFS sections read on demand from container...');
            updateSource = new FileRangeSource(update.reader, updateProgramEntry.src.offset, updateProgramEntry.src.size);
        }

        const baseInput = { headerRaw: baseHeaderRaw, source: baseSource };
        const updateInput = { headerRaw: updateHeaderRaw, source: updateSource };

        // ── Streaming path (seekable output + BKTR): no RomFS buffer ──────────
        // ExeFS is buffered (small; needed for ACID zeroing); the large RomFS is
        // streamed through the BKTR merge straight to the output. The NCA header,
        // PFS0 htable, IVFC levels and the PFS0 Program/CNMT names are written with
        // seek-back; the contentId comes from re-reading the written NCA.
        const outRead = await buildRead(output);
        // Append-only output (SW download): the PFS0 header must be written
        // before the NCA (no seek-back), so the contentId must be final after
        // Pass 1. Seekable outputs (FSA / memory) can write the header last.
        const appendOnly = !!(output.writable && typeof output.writable.seek !== 'function');
        if (hasBktrRomfs && outRead !== null && updateMode !== 'buffered') {
            log('info', 'Streaming update (seekable output): ExeFS + RomFS streamed via BKTR merge (no data buffer)...');
            await new Promise(r => setTimeout(r, 0));

            // Precompute section data sizes from the update header (no buffering).
            const { romfsDataSize, exefsSize, programSize } = parseUpdateSectionSizes(updateHeaderDec, updateHeaderRaw, updateRomfsSec, updateExefsSec, keys);
            log('info', `Program NCA (streaming): exefs=${exefsSize} romfs=${romfsDataSize} total=${programSize}`);

            const adapter = await buildAdapter(output, outRead, { log, progress });

            const otherNcas = collectOtherNcas(update);

            // Compute PFS0 headerSize without writing: both names are fixed-length
            // (program 36 chars, CNMT 42 chars), so the layout matches the final header.
            const layoutPw = new PFS0Writer(true, null, 0x10);
            layoutPw.add(`${'0'.repeat(32)}.nca`, programSize);
            for (const m of otherNcas) layoutPw.add(m.name, m.size);
            layoutPw.add(`${'0'.repeat(32)}.cnmt.nca`, 0);
            const pfs0Header = layoutPw.buildHeader();
            const programNcaPfs0Offset = pfs0Header.headerSize + layoutPw.files[0].offset;
            log('info', `PFS0 layout: ${pfs0Header.headerSize} bytes header, ${layoutPw.files.length} members, Program NCA at 0x${programNcaPfs0Offset.toString(16)}`);

            const acidFilter = createExefsAcidFilter({
                keepSig: options.keepNpdmAcidSig === true,
                keepKey: options.keepNpdmAcidKey === true,
            }, log);
            const { hashHex: contentId } = await packProgramNcaStream({
                adapter, ncaOffset: programNcaPfs0Offset,
                exefsSize, romfsDataSize,
                titleId: base.cnmt.titleId, keys,
                streamExefs: async (emit) => {
                    await extractExefsStream(updateInput, keys, updateTikData, async (chunk, off) => {
                        await acidFilter(chunk, off);
                        await emit(chunk, off);
                    });
                },
                streamRomfs: async (emit) => {
                    await mergeRomFS(baseInput, updateInput, {
                        keys, baseTik: baseTikData, updateTik: updateTikData,
                        onChunk: async (chunk, off) => { await emit(chunk, off); },
                    });
                },
                log, progress,
            });

            baseSource = null;
            updateSource = null;
            baseParsed = null;

            const rebuilt = await rebuildCnmtNca(base, update, keys, log, { hashHex: contentId, size: programSize });
            const { pw: realPw, pfs0Header: realPfs0, totalData } = buildFinalPfs0(`${contentId.slice(0, 32)}.nca`, programSize, otherNcas, rebuilt);
            await adapter.write(0, realPfs0.buffer);
            log('info', `PFS0 header ${realPfs0.headerSize} bytes, ${realPw.files.length} members`);

            // Tail uses the layout header (pfs0Header), size-identical to realPfs0.
            return finalizeOutputNsP(adapter, { pfs0Header, pw: realPw, otherNcas, programSize, totalData, rebuilt, update, output, log, progress });
        }

        // ── Two-pass path (sequential output): no data buffer ───────────────
        // Pass 1: stream RomFS+ExeFS → compute hash metadata (+ contentId on
        //   append-only output, where the PFS0 header must precede the NCA).
        // Pass 2: stream again → write NCA sequentially to output.
        // Memory: ~200 KB + streaming buffers (vs ~700 MB for buffered path).
        // Seekable: 2× romfs reads (contentId piggybacks on the write).
        // Append-only (SW): 3× romfs reads (contentId must be final in Pass 1).
        //
        // One flow for both update kinds; hasBktrRomfs branches only in two
        // spots — the RomFS size source and the RomFS stream factory:
        //   BKTR: RomFS is a BKTR patch in the update → merged = base + delta
        //         (size from the update romfs section).
        //   non-BKTR (ExeFS-only update): no RomFS in the update → RomFS = base
        //         as-is (size from the base romfs fs-header).
        if (!hasBktrRomfs || (outRead === null && updateMode !== 'buffered')) {
            log('info', `Two-pass update (sequential output): ${hasBktrRomfs ? 'BKTR merge' : 'base RomFS + update ExeFS'}, ${appendOnly ? 3 : 2}× romfs reads, ~200 KB memory...`);
            await new Promise(r => setTimeout(r, 0));

            let romfsDataSize, exefsSize, programSize;
            if (hasBktrRomfs) {
                ({ romfsDataSize, exefsSize, programSize } = parseUpdateSectionSizes(updateHeaderDec, updateHeaderRaw, updateRomfsSec, updateExefsSec, keys));
            } else {
                const baseDecBytes = decryptNcaHeaderBytes(baseHeaderRaw, keys);
                const updateDecBytes = decryptNcaHeaderBytes(updateHeaderRaw, keys);
                const { idx: romfsIdx } = findRomfsFsHeader(baseDecBytes, 'base');
                const baseRomfsFsHdr = baseDecBytes.subarray(0x400 + romfsIdx * 0x200, 0x400 + (romfsIdx + 1) * 0x200);
                romfsDataSize = Number(new DataView(baseRomfsFsHdr.buffer, baseRomfsFsHdr.byteOffset + 0x98, 8).getBigUint64(0, true));
                const updateExefsFsHdr = updateDecBytes.subarray(0x400, 0x600);
                exefsSize = Number(new DataView(updateExefsFsHdr.buffer, updateExefsFsHdr.byteOffset + 0x48, 8).getBigUint64(0, true));
                programSize = programNcaSize(exefsSize, romfsDataSize);
            }
            log('info', `Program NCA (two-pass): exefs=${exefsSize} romfs=${romfsDataSize} total=${programSize}`);

            const adapter = await buildAdapter(output, null, { log, progress });

            const makeStreamExefs = () => makeExefsStream(updateInput, keys, updateTikData, options, log);
            // Capture base refs before they're nulled below — Pass 2 re-invokes
            // makeStreamRomfs() after baseParsed is set to null.
            const _baseReaderRef = baseReader;
            const _baseParsedRef = baseParsed;
            const makeStreamRomfs = hasBktrRomfs
                ? () => async (emit) => {
                    log('info', '[makeStreamRomfs] creating fresh base source...');
                    const freshBase = baseIsNcz
                        ? { headerRaw: baseHeaderRaw, source: new NczStreamSource(_baseReaderRef, _baseParsedRef, log) }
                        : baseInput;
                    log('info', '[makeStreamRomfs] mergeRomFS starting...');
                    let _mergeBytes = 0;
                    let _lastBytes = 0;
                    let _stallTicks = 0;
                    const _mergeState = { desc: 'init' };
                    const _wd = setInterval(() => {
                        _stallTicks = _mergeBytes === _lastBytes ? _stallTicks + 1 : 0;
                        _lastBytes = _mergeBytes;
                        const line = `[makeStreamRomfs] watchdog: merge emitted ${(_mergeBytes / 1048576).toFixed(0)} MB, state=${_mergeState.desc} | merge=${trace.merge} | pump=${trace.pump}`;
                        // An FSA op that never resolves can't be cancelled from JS, so
                        // after 5 zero-progress ticks (75 s) escalate: the run is hung.
                        if (_stallTicks >= 5) log('error', line + ` — STALLED ${_stallTicks * 15}s, no progress (blocked on "${_mergeState.desc}") — run is hung, retry`);
                        else log('info', line);
                    }, 15_000);
                    try {
                        await mergeRomFS(freshBase, updateInput, {
                            keys, baseTik: baseTikData, updateTik: updateTikData, state: _mergeState,
                            // Await emit: a fire-and-forget onChunk lets the merge
                            // run ahead of the output, queueing hundreds of MB of
                            // pending writes in a slow (FSA) stream and making
                            // "mergeRomFS done" fire before the writes land.
                            onChunk: async (chunk, off) => { _mergeBytes += chunk.length; await emit(chunk, off); },
                        });
                    } finally {
                        clearInterval(_wd);
                        log('info', `[makeStreamRomfs] mergeRomFS done (${(_mergeBytes / 1048576).toFixed(0)} MB emitted)`);
                    }
                }
                : () => async (emit) => {
                    let _mergeBytes = 0;
                    let _lastBytes = 0;
                    let _stallTicks = 0;
                    const _mergeState = { desc: 'extract base romfs' };
                    const _wd = setInterval(() => {
                        _stallTicks = _mergeBytes === _lastBytes ? _stallTicks + 1 : 0;
                        _lastBytes = _mergeBytes;
                        const line = `[makeStreamRomfs] watchdog: base romfs emitted ${(_mergeBytes / 1048576).toFixed(0)} MB, state=${_mergeState.desc} | merge=${trace.merge} | pump=${trace.pump}`;
                        if (_stallTicks >= 5) log('error', line + ` — STALLED ${_stallTicks * 15}s, no progress (blocked on "${_mergeState.desc}") — run is hung, retry`);
                        else log('info', line);
                    }, 15_000);
                    try {
                        await extractRomfsStream(baseInput, keys, baseTikData, async (chunk, off) => {
                            _mergeBytes += chunk.length;
                            _mergeState.desc = 'emit @romfs 0x' + off.toString(16);
                            await emit(chunk, off);
                        });
                    } finally {
                        clearInterval(_wd);
                        log('info', `[makeStreamRomfs] base romfs done (${(_mergeBytes / 1048576).toFixed(0)} MB emitted)`);
                    }
                };

            const { size: computedSize, contentId, meta } = await computeProgramNcaContentId({
                exefsSize, romfsDataSize, titleId: base.cnmt.titleId, keys,
                streamExefs: makeStreamExefs(), streamRomfs: makeStreamRomfs(), log,
                progress: (p) => progress(p * 0.5),
                contentIdInPass1: appendOnly,
            });
            log('info', contentId
                ? `ContentId: ${contentId} (${computedSize} bytes)`
                : `Program NCA: ${computedSize} bytes (contentId computed in Pass 2)`);

            baseSource = null;
            updateSource = null;
            baseParsed = null;

            return await writeTwoPassProgramAndFinish({
                adapter, base, update, keys, log, progress, output,
                programSize, meta, makeStreamExefs, makeStreamRomfs,
                contentId, appendOnly,
            });
        }

        // ── BKTR buffered path (forced buffered mode) ────────────────────────
        // Merge RomFS into memory, extract ExeFS, pack NCA from buffers.
        // Only reached when updateMode === 'buffered' (skip streaming paths above).
        log('info', `Merging RomFS (buffered, base streamed from ${baseIsNcz ? 'NCZ' : 'container'})...`);
        await new Promise(r => setTimeout(r, 0));
        const mergeResult = await mergeRomFS(baseInput, updateInput, {
            keys,
            baseTik: baseTikData,
            updateTik: updateTikData,
        });
        const mergedRomfs = mergeResult.mergedData;
        log('info', `Merged RomFS: ${mergedRomfs.length} bytes, ${mergeResult.relocEntries} reloc entries, ${mergeResult.subsectionEntries} subsection entries`);

        log('info', 'Extracting ExeFS from update Program NCA...');
        await new Promise(r => setTimeout(r, 0));
        const exefsData = await extractExefs(updateInput, keys, updateTikData);
        log('info', `ExeFS: ${exefsData.length} bytes`);

        processNpdmAcid(exefsData, {
            keepSig: options.keepNpdmAcidSig === true,
            keepKey: options.keepNpdmAcidKey === true,
        }, log);

        baseSource = null;
        updateSource = null;
        baseParsed = null;

        log('info', 'Preparing merged Program NCA (hash precompute)...');
        const preparedProgram = await preparePlaintextProgramNca(
            exefsData, mergedRomfs, null, base.cnmt.titleId, keys, log
        );
        mergedProgram = { hashHex: preparedProgram.hashHex, size: preparedProgram.size, id: preparedProgram.hashHex.slice(0, 32) };
        log('info', `Merged Program NCA: ${mergedProgram.size} bytes sha256=${mergedProgram.hashHex} contentId=${mergedProgram.id}`);

        const rebuilt = await rebuildCnmtNca(base, update, keys, log,
            { hashHex: mergedProgram.hashHex, size: mergedProgram.size });
        log('info', `Rebuilt CNMT NCA: ${rebuilt.nca.length} bytes sha256=${sha256(rebuilt.nca)}`);

        const otherNcas = collectOtherNcas(update);

        const { pw, pfs0Header, totalData, programNcaPfs0Offset } = buildFinalPfs0(`${mergedProgram.id}.nca`, mergedProgram.size, otherNcas, rebuilt);

        const adapter = await buildAdapter(output, null, { log, progress });
        await adapter.write(0, pfs0Header.buffer);
        log('info', `PFS0 header ${pfs0Header.headerSize} bytes, ${pw.files.length} members`);

        log('info', 'Packing merged Program NCA (streaming)...');
        await new Promise(r => setTimeout(r, 0));
        await writePlaintextProgramNca(preparedProgram, adapter, log, programNcaPfs0Offset);

        return finalizeOutputNsP(adapter, { pfs0Header, pw, otherNcas, programSize: mergedProgram.size, totalData, rebuilt, update, output, log, progress });
    }

    // ── Non-merge path (original, buffered) ─────────────────────────────────
    const rebuilt = await rebuildCnmtNca(base, update, keys, log, null);
    log('info', `Rebuilt CNMT NCA: ${rebuilt.nca.length} bytes sha256=${sha256(rebuilt.nca)}`);

    const members = [];

    if (mergedProgram) {
        members.push({ name: `${mergedProgram.id}.nca`, size: mergedProgram.size, data: mergedProgram.nca });
    }

    const otherNcas = [];
    for (const e of update.cnmt.contentEntries) {
        if (e.type === 6) continue;
        if (mergedProgram && e.type === 1) continue;
        const ncaId = e.ncaId;
        const src = update.entries.find(x =>
            x.name.toLowerCase().startsWith(ncaId) && !x.name.toLowerCase().endsWith('.cnmt.nca'));
        if (!src) continue;
        const outName = src.name.replace(/\.ncz$/i, '.nca');
        otherNcas.push({
            name: outName, size: e.size,
            src: { reader: update.reader, offset: src.offset, ncaLen: src.size,
                   isNcz: src.name.toLowerCase().endsWith('.ncz') },
        });
    }
    otherNcas.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    members.push(...otherNcas);

    // CNMT last (yanu member order)
    members.push({ name: rebuilt.name, size: rebuilt.nca.length, data: rebuilt.nca });

    const adapter = await buildAdapter(output, null, { log, progress });
    const pw = new PFS0Writer(true, null, 0x10);
    for (const m of members) pw.add(m.name, m.size);
    const pfs0Header = pw.buildHeader();
    await adapter.write(0, pfs0Header.buffer);
    log('info', `PFS0 header ${pfs0Header.headerSize} bytes, ${members.length} members`);

    let written = 0;
    const totalData = members.reduce((s, m) => s + m.size, 0);
    for (let i = 0; i < members.length; i++) {
        const m = members[i];
        const pos = pfs0Header.headerSize + pw.files[i].offset;
        if (m.data) {
            await adapter.write(pos, m.data);
        } else if (m.src.isNcz) {
            const nczReader = new AdapterNCZReader(m.src.reader, m.src.offset, m.src.ncaLen);
            const parsed = await parseNczSections(nczReader);
            const decomp = new NCZDecompressor(nczReader);
            await decomp.decompress(
                (p) => progress((written + m.size * p) / totalData, `Decompressing ${m.name}...`),
                async (chunk, offset) => { await adapter.write(pos + offset, chunk); }, parsed);
        } else {
            await copyRange(m.src.reader, m.src.offset, m.size,
                (off, chunk) => adapter.write(pos + off, chunk));
        }
        log('info', `[WRITTEN] ${m.name} (${m.size} bytes)`);
        written += m.size;
    }

    const totalSize = pfs0Header.headerSize + totalData;
    log('info', `Updated NSP: ${members.length} members, ${totalSize} bytes`);
    if (output.memory) {
        return { size: totalSize, blob: collectBlob(adapter, totalSize), memberCount: members.length };
    }
    return { size: totalSize, memberCount: members.length };
}
