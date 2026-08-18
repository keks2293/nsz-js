import { PFS0, PFS0Writer } from './pfs0.js';
import { buildAdapter, buildRead, collectBlob, copyRange } from './adapter.js';
import { XCIReader } from './xci.js';
import { NCZDecompressor, AdapterNCZReader, parseNczSections } from './ncz.js';
import { decryptNcaHeader, decryptNcaSection, parseCnmtFromDecryptedSection } from './nca.js';
import { Cnmt } from './cnmt.js';
import { sha256 } from '../crypto/sha256.js';
import { mergeRomFS } from './bktr-merge.js';
import { FileRangeSource, NczStreamSource, ViewRangeSource, SparseNcaView } from './range-source.js';
import { preparePlaintextProgramNca, writePlaintextProgramNca, packProgramNcaStream, extractExefsStream, createExefsAcidFilter, packMetaNca, extractExefs, extractRomfs, processNpdmAcid } from './nca-pack.js';
import { AesXts } from '../crypto/aes-ops.mjs';
import { hexToBytes, writeU64LE, writeU32LE, NCA_HEADER_SIZE } from './nca-utils.js';

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

function pad200(n) {
    return (n + 0x1FF) & ~0x1FF;
}

function pad4000(n) {
    return (n + 0x3FFF) & ~0x3FFF;
}

// Total plaintext Program NCA size from the ExeFS (PFS0 data) and RomFS (BKTR data)
// sizes — mirrors the layout in packProgramNcaStream/preparePlaintextProgramNca.
function programNcaSize(exefsSize, romfsDataSize) {
    const exeHtableSize = pad200(Math.ceil(exefsSize / 0x10000) * 0x20);
    const exeSectionSize = pad200(exeHtableSize + exefsSize);
    const h1 = pad4000(Math.ceil(romfsDataSize / 0x4000) * 0x20);
    const h2 = pad4000(Math.ceil(h1 / 0x4000) * 0x20);
    const h3 = pad4000(Math.ceil(h2 / 0x4000) * 0x20);
    const h4 = pad4000(Math.ceil(h3 / 0x4000) * 0x20);
    const h5 = pad4000(Math.ceil(h4 / 0x4000) * 0x20);
    const hashLevelsSize = h1 + h2 + h3 + h4 + h5;
    const romSectionSize = pad4000(hashLevelsSize + romfsDataSize);
    return 0xC00 + exeSectionSize + romSectionSize;
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

async function openContainer(r) {
    const magic = await r.reader.read(0, 4);
    const m = String.fromCharCode(magic[0], magic[1], magic[2], magic[3]);
    if (m === 'PFS0') {
        const pfs0 = await PFS0.open(r.reader);
        return { kind: 'pfs0', entries: pfs0.getFiles() };
    }
    let head = await r.reader.read(0x100, 4);
    let isHead = String.fromCharCode(head[0], head[1], head[2], head[3]) === 'HEAD';
    if (!isHead) {
        head = await r.reader.read(0x1100, 4);
        isHead = String.fromCharCode(head[0], head[1], head[2], head[3]) === 'HEAD';
    }
    if (isHead) {
        const xci = new XCIReader(r.reader);
        await xci.parse();
        const entries = await xci.getSecureFiles();
        if (entries.length === 0) {
            throw new Error(`update: no secure partition files found in ${r.name}`);
        }
        return { kind: 'xci', entries };
    }
    throw new Error(`update: unsupported container in ${r.name} (magic ${m})`);
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

export async function update(readers, output, options = {}) {
    const { log = () => {}, progress = () => {}, keys = null } = options;

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
                baseProgramEntry = { entry: e, src };
            }
        }
    }
    for (const e of update.cnmt.contentEntries) {
        if (e.type === 1) { // Program NCA
            const src = update.entries.find(x =>
                x.name.toLowerCase().startsWith(e.ncaId) && !x.name.toLowerCase().endsWith('.cnmt.nca'));
            if (src) {
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
        if (hasBktrRomfs && outRead !== null) {
            log('info', 'Streaming update (seekable output): ExeFS + RomFS streamed via BKTR merge (no data buffer)...');
            await new Promise(r => setTimeout(r, 0));

            // Precompute section data sizes from the update header (no buffering).
            const hdrKey = typeof keys.header_key === 'string' ? hexToBytes(keys.header_key) : keys.header_key;
            const updateDecBytes = new AesXts(hdrKey).decrypt(updateHeaderRaw, 0);
            const updateRomfsSecIdx = updateHeaderDec.sections.indexOf(updateRomfsSec);
            const updateRomfsFsHdr = updateDecBytes.subarray(0x400 + updateRomfsSecIdx * 0x200, 0x400 + (updateRomfsSecIdx + 1) * 0x200);
            const romfsDataSize = Number(new DataView(updateRomfsFsHdr.buffer, updateRomfsFsHdr.byteOffset + 0x98, 8).getBigUint64(0, true));
            const updateExefsSecIdx = updateHeaderDec.sections.indexOf(updateExefsSec);
            const updateExefsFsHdr = updateDecBytes.subarray(0x400 + updateExefsSecIdx * 0x200, 0x400 + (updateExefsSecIdx + 1) * 0x200);
            const exefsSize = Number(new DataView(updateExefsFsHdr.buffer, updateExefsFsHdr.byteOffset + 0x48, 8).getBigUint64(0, true));
            const programSize = programNcaSize(exefsSize, romfsDataSize);
            log('info', `Program NCA (streaming): exefs=${exefsSize} romfs=${romfsDataSize} total=${programSize}`);

            const adapter = await buildAdapter(output, outRead, { log, progress });

            // Other NCAs (sorted by name) — same selection as the buffered path.
            const otherNcas = [];
            for (const e of update.cnmt.contentEntries) {
                if (e.type === 6 || e.type === 1) continue;
                const src = update.entries.find(x =>
                    x.name.toLowerCase().startsWith(e.ncaId) && !x.name.toLowerCase().endsWith('.cnmt.nca'));
                if (src) otherNcas.push({ name: src.name.replace(/\.ncz$/i, '.nca'), size: e.size, src });
            }
            otherNcas.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

            // Placeholder Program id (32 zeros) + placeholder CNMT → PFS0 layout
            // before the real contentId is known. Both names are fixed-length, so the
            // header size is identical to the final one (only bytes are patched later).
            const placeholderId = '0'.repeat(32);
            const placeholderCnmt = await rebuildCnmtNca(base, update, keys, log, { hashHex: '0'.repeat(64), size: programSize });
            const placeholderPw = new PFS0Writer(true);
            placeholderPw.add(`${placeholderId}.nca`, programSize);
            for (const m of otherNcas) placeholderPw.add(m.name, m.size);
            placeholderPw.add(placeholderCnmt.name, placeholderCnmt.nca.length);
            const pfs0Header = placeholderPw.buildHeader();
            await adapter.write(0, pfs0Header.buffer);
            log('info', `PFS0 header ${pfs0Header.headerSize} bytes, ${placeholderPw.files.length} members (placeholder names)`);

            const programNcaPfs0Offset = pfs0Header.headerSize + placeholderPw.files[0].offset;

            // Stream the Program NCA (ExeFS + RomFS via BKTR merge) → contentId.
            // ExeFS is streamed (never buffered); the ACID zeroing is applied as a
            // filter over the stream (createExefsAcidFilter).
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
                        onChunk: (chunk, off) => emit(chunk, off),
                    });
                },
                log,
            });

            // Release the NCA sources — no longer needed after the merge.
            baseSource = null;
            updateSource = null;
            baseParsed = null;

            // Real names now: rebuild CNMT (real contentId) + patch PFS0 names.
            const rebuilt = await rebuildCnmtNca(base, update, keys, log, { hashHex: contentId, size: programSize });
            const realPw = new PFS0Writer(true);
            realPw.add(`${contentId.slice(0, 32)}.nca`, programSize);
            for (const m of otherNcas) realPw.add(m.name, m.size);
            realPw.add(rebuilt.name, rebuilt.nca.length);
            const realPfs0 = realPw.buildHeader();
            if (realPfs0.headerSize !== pfs0Header.headerSize) {
                throw new Error('update: PFS0 header size changed after contentId (placeholder/real name length mismatch)');
            }
            await adapter.write(0, realPfs0.buffer);
            log('info', `Patched PFS0 names → ${contentId.slice(0, 32)}.nca, ${rebuilt.name}`);

            // Write other NCAs (stream from source, sorted by name).
            let written = programSize;
            const totalData = realPw.files.reduce((s, f) => s + f.size, 0);
            for (let i = 0; i < otherNcas.length; i++) {
                const member = realPw.files[i + 1];
                const src = otherNcas[i].src;
                const pos = pfs0Header.headerSize + member.offset;
                if (src.name.toLowerCase().endsWith('.ncz')) {
                    const nczReader = new AdapterNCZReader(update.reader, src.offset, src.size);
                    const parsed = await parseNczSections(nczReader);
                    const decomp = new NCZDecompressor(nczReader);
                    await decomp.decompress(
                        (p) => progress((written + member.size * p) / totalData, `Decompressing ${member.name}...`),
                        async (chunk, offset) => { await adapter.write(pos + offset, chunk); },
                        parsed);
                } else {
                    await copyRange(update.reader, src.offset, member.size,
                        (off, chunk) => adapter.write(pos + off, chunk));
                }
                log('info', `[WRITTEN] ${member.name} (${member.size} bytes)`);
                written += member.size;
            }

            // Write CNMT last (matches yanu member order).
            const cnmtPfs0Offset = pfs0Header.headerSize + realPw.files[realPw.files.length - 1].offset;
            const cnmtSize = rebuilt.nca.length;
            await adapter.write(cnmtPfs0Offset, rebuilt.nca);
            log('info', `[WRITTEN] ${rebuilt.name} (${cnmtSize} bytes)`);

            const totalSize = pfs0Header.headerSize + totalData;
            log('info', `Updated NSP (streaming): ${realPw.files.length} members, ${totalSize} bytes`);
            if (output.memory) {
                return { size: totalSize, blob: collectBlob(adapter, totalSize), memberCount: realPw.files.length };
            }
            return { size: totalSize, memberCount: realPw.files.length };
        }

        // ── Merge RomFS / Extract sections ───────────────────────────────────
        let mergedRomfs;
        if (hasBktrRomfs) {
            log('info', `Merging RomFS (base streamed from ${baseIsNcz ? 'NCZ' : 'container'})...`);
            await new Promise(r => setTimeout(r, 0));
            const mergeResult = await mergeRomFS(baseInput, updateInput, {
                keys,
                baseTik: baseTikData,
                updateTik: updateTikData,
            });
            mergedRomfs = mergeResult.mergedData;
            log('info', `Merged RomFS: ${mergedRomfs.length} bytes, ${mergeResult.relocEntries} reloc entries, ${mergeResult.subsectionEntries} subsection entries`);
        } else {
            log('info', 'Update has no RomFS section (ExeFS-only) — using base RomFS as-is...');
            mergedRomfs = await extractRomfs(baseInput, keys, baseTikData);
            log('info', `Base RomFS: ${mergedRomfs.length} bytes`);
        }

        // Extract ExeFS from the update Program NCA
        log('info', 'Extracting ExeFS from update Program NCA...');
        await new Promise(r => setTimeout(r, 0));
        const exefsData = await extractExefs(updateInput, keys, updateTikData);
        log('info', `ExeFS: ${exefsData.length} bytes`);

        // hacpack parity: zero the ACID signature + key in main.npdm by default
        // (hacpack's --nozeronpdmsig / --nozeroacidkey → keepNpdmAcidSig / keepNpdmAcidKey)
        processNpdmAcid(exefsData, {
            keepSig: options.keepNpdmAcidSig === true,
            keepKey: options.keepNpdmAcidKey === true,
        }, log);

        // Release the NCA sources — and, for a .nsz update, the buffered sections
        // the sparse view references — no longer needed after merge + extraction.
        baseSource = null;
        updateSource = null;
        baseParsed = null;

        // ── Prepare Program NCA and learn its real contentId (no writes) ───
        // Emulators require the shipped NCA filename to be `<contentId>.nca`
        // (Switch looks up files by the content hash recorded in CNMT). The
        // NCA hash is deterministic, so we compute it up front — this lets us
        // build the PFS0 header with real names before streaming anything, no
        // seek-back needed.
        log('info', 'Preparing merged Program NCA (hash precompute)...');
        const preparedProgram = await preparePlaintextProgramNca(
            exefsData, mergedRomfs, null, base.cnmt.titleId, keys, log
        );
        mergedProgram = { hashHex: preparedProgram.hashHex, size: preparedProgram.size, id: preparedProgram.hashHex.slice(0, 32) };
        log('info', `Merged Program NCA: ${mergedProgram.size} bytes sha256=${mergedProgram.hashHex} contentId=${mergedProgram.id}`);

        // ── Build CNMT with correct Program NCA hash ─────────────────────────
        const rebuilt = await rebuildCnmtNca(base, update, keys, log,
            { hashHex: mergedProgram.hashHex, size: mergedProgram.size });
        log('info', `Rebuilt CNMT NCA: ${rebuilt.nca.length} bytes sha256=${sha256(rebuilt.nca)}`);

        // ── Build PFS0 header with real names (no seek-back needed) ─────────
        // Order: Program NCA → other NCAs (sorted by name) → CNMT last (yanu layout)
        const otherNcas = [];
        for (const e of update.cnmt.contentEntries) {
            if (e.type === 6 || e.type === 1) continue;
            const src = update.entries.find(x =>
                x.name.toLowerCase().startsWith(e.ncaId) && !x.name.toLowerCase().endsWith('.cnmt.nca'));
            if (src) otherNcas.push({ name: src.name.replace(/\.ncz$/i, '.nca'), size: e.size, src });
        }
        otherNcas.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

        const finalPw = new PFS0Writer(true);
        finalPw.add(`${mergedProgram.id}.nca`, mergedProgram.size);
        for (const m of otherNcas) finalPw.add(m.name, m.size);
        finalPw.add(rebuilt.name, rebuilt.nca.length);

        // ── Write PFS0 header at offset 0 (final, no patching needed) ─────────
        const adapter = await buildAdapter(output, null, { log, progress });
        const pfs0Header = finalPw.buildHeader();
        await adapter.write(0, pfs0Header.buffer);
        log('info', `PFS0 header ${pfs0Header.headerSize} bytes, ${finalPw.files.length} members`);

        // ── Stream Program NCA at its PFS0 offset ─────────────────────────────
        const programNcaPfs0Offset = pfs0Header.headerSize + finalPw.files[0].offset;

        log('info', 'Packing merged Program NCA (streaming)...');
        await new Promise(r => setTimeout(r, 0));
        await writePlaintextProgramNca(preparedProgram, adapter, log, programNcaPfs0Offset);

        // ── Write other NCAs (stream from source, sorted by name) ────────────
        let written = mergedProgram.size;
        const totalData = finalPw.files.reduce((s, f) => s + f.size, 0);
        for (let i = 0; i < otherNcas.length; i++) {
            const member = finalPw.files[i + 1];
            const src = otherNcas[i].src;
            const pos = pfs0Header.headerSize + member.offset;
            if (src.name.toLowerCase().endsWith('.ncz')) {
                const nczReader = new AdapterNCZReader(update.reader, src.offset, src.size);
                const parsed = await parseNczSections(nczReader);
                const decomp = new NCZDecompressor(nczReader);
                await decomp.decompress(
                    (p) => progress((written + member.size * p) / totalData, `Decompressing ${member.name}...`),
                    async (chunk, offset) => { await adapter.write(pos + offset, chunk); },
                    parsed);
            } else {
                await copyRange(update.reader, src.offset, member.size,
                    (off, chunk) => adapter.write(pos + off, chunk));
            }
            log('info', `[WRITTEN] ${member.name} (${member.size} bytes)`);
            written += member.size;
        }

        // ── Write CNMT last (matches yanu member order) ───────────────────────
        const cnmtMemberIdx = finalPw.files.length - 1;
        const cnmtPfs0Offset = pfs0Header.headerSize + finalPw.files[cnmtMemberIdx].offset;
        const cnmtSize = rebuilt.nca.length;
        await adapter.write(cnmtPfs0Offset, rebuilt.nca);
        log('info', `[WRITTEN] ${rebuilt.name} (${cnmtSize} bytes)`);

        const totalSize = pfs0Header.headerSize + totalData;
        log('info', `Updated NSP: ${finalPw.files.length} members, ${totalSize} bytes`);
        if (output.memory) {
            return { size: totalSize, blob: collectBlob(adapter, totalSize), memberCount: finalPw.files.length };
        }
        return { size: totalSize, memberCount: finalPw.files.length };
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
    const pw = new PFS0Writer(true);
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
