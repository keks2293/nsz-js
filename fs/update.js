import { PFS0, PFS0Writer } from './pfs0.js';
import { buildAdapter, collectBlob, copyRange } from './adapter.js';
import { XCIReader } from './xci.js';
import { NCZDecompressor, AdapterNCZReader, parseNczSections } from './ncz.js';
import { decryptNcaHeader, decryptNcaSection, parseCnmtFromDecryptedSection } from './nca.js';
import { Cnmt } from './cnmt.js';
import { AesXts, AesCtr } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';
import { sha256 } from '../crypto/sha256.js';
import { mergeRomFS } from './bktr-merge.js';
import { packPlaintextProgramNca, packMetaNca, extractExefs, extractRomfs } from './nca-pack.js';

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    return bytes;
}

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

const NCA_HEADER_SIZE = 0xC00;

function pad4000(n) {
    return (n + 0x3FFF) & ~0x3FFF;
}

function writeU64LE(buf, offset, value) {
    const n = typeof value === 'bigint' ? value : BigInt(value);
    const view = new DataView(buf.buffer, buf.byteOffset + offset, 8);
    view.setBigUint64(0, n, true);
}

function writeU32LE(buf, offset, value) {
    const view = new DataView(buf.buffer, buf.byteOffset + offset, 4);
    view.setUint32(0, value, true);
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


async function decompressNCZ(nczReader) {
    const parsed = await parseNczSections(nczReader);
    const result = new Uint8Array(parsed.ncaSize);
    const decomp = new NCZDecompressor(nczReader);
    await decomp.decompress(
        () => {},
        (chunk, offset) => { result.set(chunk, offset); },
        parsed,
    );
    return result;
}

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
    let baseProgramNcaData = null;
    let updateProgramNcaData = null;
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
        // Read base Program NCA (decompress if NCZ)
        if (baseProgramEntry.src.name.toLowerCase().endsWith('.ncz')) {
            log('info', 'Decompressing base Program NCA...');
        } else {
            log('info', 'Reading base Program NCA...');
        }
        await new Promise(r => setTimeout(r, 0));
        if (baseProgramEntry.src.name.toLowerCase().endsWith('.ncz')) {
            const nczReader = new AdapterNCZReader(base.reader, baseProgramEntry.src.offset, baseProgramEntry.src.size);
            baseProgramNcaData = await decompressNCZ(nczReader);
        } else {
            baseProgramNcaData = await base.reader.read(
                baseProgramEntry.src.offset, baseProgramEntry.src.size
            );
        }

        // Read update Program NCA (decompress if NCZ)
        if (updateProgramEntry.src.name.toLowerCase().endsWith('.ncz')) {
            log('info', 'Decompressing update Program NCA...');
        } else {
            log('info', 'Reading update Program NCA...');
        }
        await new Promise(r => setTimeout(r, 0));
        if (updateProgramEntry.src.name.toLowerCase().endsWith('.ncz')) {
            const nczReader = new AdapterNCZReader(update.reader, updateProgramEntry.src.offset, updateProgramEntry.src.size);
            updateProgramNcaData = await decompressNCZ(nczReader);
        } else {
            updateProgramNcaData = await update.reader.read(
                updateProgramEntry.src.offset, updateProgramEntry.src.size
            );
        }

        let mergedRomfs;
        if (hasBktrRomfs) {
            // Merge RomFS: base RomFS patched with BKTR delta.
            //
            // yanu extracts the update RomFS via hac2l ("--basenca base update --romfsdir ...",
            // see sources/hac2l + yanu's unpack_all in yanu/update.rs: NcaReader exposes the
            // merged BKTR RomFS starting at the IVFC level-5 offset) and re-packs it with
            // hacPack (romfs_build(), sources/hacpack/romfs.c:506). hactool takes the same
            // slice: "romfs_offset = ivfc_levels[IVFC_MAX_LEVEL-1].data_offset" (nca.c:1240).
            // mergeRomFS() therefore returns mergedData = the level-5 data region only (NOT the
            // whole virtual section incl. IVFC header + hash levels — that would be +1.26 MB too
            // big, see DOC-REPACK.md). This data blob is what we re-pack below.
            log('info', 'Merging RomFS...');
            await new Promise(r => setTimeout(r, 0)); // flush log before long-running merge
            const mergeResult = await mergeRomFS(baseProgramNcaData, updateProgramNcaData, {
                keys,
                baseTik: baseTikData,
                updateTik: updateTikData,
            });
            mergedRomfs = mergeResult.mergedData;
            log('info', `Merged RomFS: ${mergedRomfs.length} bytes, ${mergeResult.relocEntries} reloc entries, ${mergeResult.subsectionEntries} subsection entries`);
        } else {
            // ExeFS-only update: no RomFS section, use the base RomFS as-is
            log('info', 'Update has no RomFS section (ExeFS-only) — using base RomFS as-is...');
            mergedRomfs = await extractRomfs(baseProgramNcaData, keys, baseTikData);
            log('info', `Base RomFS: ${mergedRomfs.length} bytes`);
        }

        // Extract ExeFS from the update Program NCA: the update always carries the
        // full new executable (the base ExeFS is the old code and must not be used)
        log('info', 'Extracting ExeFS from update Program NCA...');
        await new Promise(r => setTimeout(r, 0));
        const exefsData = await extractExefs(updateProgramNcaData, keys, updateTikData);
        log('info', `ExeFS: ${exefsData.length} bytes`);

        // Pack new Program NCA with IVFC-protected sections (no Control — yanu doesn't use it)
        log('info', 'Packing merged Program NCA...');
        await new Promise(r => setTimeout(r, 0));
        const mergedNca = await packPlaintextProgramNca(exefsData, mergedRomfs, null, base.cnmt.titleId, keys, log);
        const hashHex = sha256(mergedNca);
        mergedProgram = { nca: mergedNca, hashHex, size: mergedNca.length, id: hashHex.slice(0, 32) };
        log('info', `Merged Program NCA: ${mergedProgram.size} bytes sha256=${mergedProgram.hashHex} contentId=${mergedProgram.id}`);
    }

    // Rebuild the base CNMT NCA (program content entry = merged NCA when available)
    const rebuilt = await rebuildCnmtNca(base, update, keys, log,
        mergedProgram ? { hashHex: mergedProgram.hashHex, size: mergedProgram.size } : null);
    log('info', `Rebuilt CNMT NCA: ${rebuilt.nca.length} bytes sha256=${sha256(rebuilt.nca)}`);

    // Output PFS0 members — match yanu: merged Program NCA first, other update
    // content NCAs (sorted by name), CNMT NCA last.
    const members = [];

    // Merged program NCA replaces the update Program NCA (named by its own content id)
    if (mergedProgram) {
        members.push({ name: `${mergedProgram.id}.nca`, size: mergedProgram.size, data: mergedProgram.nca });
    }

    // Other update content NCAs (manual/publicdata) — decompressed to .nca,
    // sorted by name (this places the manual NCA right after the Program NCA,
    // matching yanu's processing order — the manual is "attached" to Program).
    // With a BKTR merge the Program NCA is replaced above, so type 1 is skipped.
    const otherNcas = [];
    for (const e of update.cnmt.contentEntries) {
        if (e.type === 6) continue;
        if (mergedProgram && e.type === 1) continue;
        const ncaId = e.ncaId;
        const src = update.entries.find(x =>
            x.name.toLowerCase().startsWith(ncaId) && !x.name.toLowerCase().endsWith('.cnmt.nca'));
        if (!src) {
            throw new Error(`update: update content ${ncaId} (type ${e.type}) not found in update container`);
        }
        const outName = src.name.replace(/\.ncz$/i, '.nca');
        otherNcas.push({
            name: outName,
            size: e.size,
            src: {
                reader: update.reader,
                offset: src.offset,
                ncaLen: src.size,
                isNcz: src.name.toLowerCase().endsWith('.ncz'),
            },
        });
    }
    otherNcas.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    members.push(...otherNcas);

    // CNMT last (yanu member order)
    members.push({ name: rebuilt.name, size: rebuilt.nca.length, data: rebuilt.nca });

    // Phase 2: write output PFS0
    const read = (offset, size) => null;
    const adapter = await buildAdapter(output, read, { log, progress });

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
            if (parsed.ncaSize !== m.size) {
                throw new Error(`update: ${m.name} decompressed size ${parsed.ncaSize} != CNMT size ${m.size}`);
            }
            const decomp = new NCZDecompressor(nczReader);
            await decomp.decompress(
                (p) => progress((written + m.size * p) / totalData, `Decompressing ${m.name}...`),
                async (chunk, offset) => { await adapter.write(pos + offset, chunk); },
                parsed);
            log('info', `[WRITTEN] ${m.name} (${m.size} bytes)`);
        } else {
            await copyRange(m.src.reader, m.src.offset, m.size, (off, chunk) => adapter.write(pos + off, chunk));
            log('info', `[WRITTEN] ${m.name} (${m.size} bytes)`);
        }
        written += m.size;
    }

    const totalSize = pfs0Header.headerSize + totalData;
    log('info', `Updated NSP: ${members.length} members, ${totalSize} bytes`);
    if (output.memory) {
        return { size: totalSize, blob: collectBlob(adapter, totalSize), memberCount: members.length };
    }
    return { size: totalSize, memberCount: members.length };
}
