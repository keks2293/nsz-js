// Shared NSZ/XCZ converter logic: NCA hash verification, member meta
// collection, and per-member write (decompress-or-copy + verify).

import { NCZDecompressor, AdapterNCZReader, parseNczSections } from './ncz.js';
import { copyRange } from './adapter.js';
import { sha256 } from '../crypto/sha256.js';

// ── NCA hash verification ───────────────────────────────────────────────────

// Verify a computed NCA hash against the CNMT content-id → hash map.
export function verifyHashByNcaId(hash, ncaId, cnmtHashMap, onLog) {
    const log = onLog || ((level, msg) => console.log(`  ${msg}`));
    if (cnmtHashMap.size > 0) {
        const expected = cnmtHashMap.get(ncaId);
        if (expected && expected === hash) {
            log('success', `[VERIFIED]   ${ncaId} ${hash}`);
        } else {
            log('error', `[CORRUPTED]  ${ncaId} expected ${expected || 'none'}, got ${hash}`);
            throw new Error(`Verification detected hash mismatch: ${ncaId}`);
        }
    }
}

// Verify a computed NCA hash matches the source filename prefix
// (content-addressed naming: <first 32 hash chars>.ncz).
export function verifyFileNameHash(hash, nczName, ncaName, onLog) {
    const log = onLog || ((level, msg) => console.log(`  ${msg}`));
    const fileNameHash = nczName.replace(/\.[^.]+$/, '').toLowerCase().slice(0, 32);
    if (hash.slice(0, 32) === fileNameHash) {
        log('success', `[VERIFIED]   ${ncaName} ${hash}`);
    } else {
        log('error', `[MISMATCH]   Filename starts with ${fileNameHash} but ${hash.slice(0, 32)} was expected`);
        throw new Error(`Verification detected hash mismatch: ${ncaName}`);
    }
}

function isVerifiableNca(name) {
    return name.endsWith('.nca') && !name.endsWith('.cnmt.nca');
}

// Log + verify a computed NCA hash: CNMT content map if available,
// otherwise filename-prefix check.
export function verifyNcaHash({ hash, inputName, outputName, cnmtHashMap, log }) {
    log('info', `[NCA HASH]   ${hash}`);
    const ncaId = outputName.replace(/\.nca$/i, '');
    if (cnmtHashMap && cnmtHashMap.size > 0) {
        verifyHashByNcaId(hash, ncaId, cnmtHashMap, log);
    } else {
        verifyFileNameHash(hash, inputName, outputName, log);
    }
}

// ── Member meta + write ─────────────────────────────────────────────────────

// Collect output metas for PFS0/HFS0 members. NCZ files are probed (header
// only, first 0x10000 bytes) to learn the decompressed ncaSize.
export async function collectFileMetas(files, adapter) {
    const metas = [];
    for (const f of files) {
        const isNcz = f.name.toLowerCase().endsWith('.ncz');
        const outputName = isNcz ? f.name.replace(/\.ncz$/i, '.nca') : f.name;
        if (isNcz) {
            const headerReader = new AdapterNCZReader(adapter, f.offset, Math.min(f.size, 0x10000));
            const parsed = await parseNczSections(headerReader);
            metas.push({ name: outputName, size: parsed.ncaSize, isNcz: true, offset: f.offset, nczLen: f.size, inputName: f.name, parsed });
        } else {
            metas.push({ name: outputName, size: f.size, isNcz: false, offset: f.offset, inputName: f.name });
        }
    }
    return metas;
}

// Write one member at writePos: NCZ → streaming decompress + hash, or raw
// copy. With verify+createHash the output is hashed and verified via
// verifyNcaHash. progress(fraction, label) is called during the work.
export async function writeMember({ meta, adapter, writePos, verify, createHash, cnmtHashMap, log, progress, progressBase, pct }) {
    if (meta.isNcz) {
        const hasher = verify ? createHash() : null;
        const nczReader = new AdapterNCZReader(adapter, meta.offset, meta.nczLen);
        const decomp = new NCZDecompressor(nczReader);
        await decomp.decompress(
            (p) => progress(pct(progressBase + meta.size * p), `Decompressing ${meta.inputName}...`),
            async (chunk, offset) => {
                if (hasher) hasher.update(chunk);
                await adapter.write(writePos + offset, chunk);
            },
            meta.parsed);
        if (hasher && isVerifiableNca(meta.name)) {
            verifyNcaHash({ hash: hasher.hex(), inputName: meta.inputName, outputName: meta.name, cnmtHashMap, log });
        }
    } else {
        progress(pct(progressBase), `Copying ${meta.inputName}...`);
        const data = await adapter.read(meta.offset, meta.size);
        if (verify && isVerifiableNca(meta.name)) {
            const hash = await sha256(data);
            verifyNcaHash({ hash, inputName: meta.inputName, outputName: meta.name, cnmtHashMap, log });
        }
        await adapter.write(writePos, data);
    }
}

// ── Streaming member write (merge / update) ───────────────────────────────

// Write one member from a file reader: NCZ → streaming decompress, plain NCA
// → copyRange. For NCZ with sections, pass `parsed` to skip re-parsing.
// progress(fraction) is called during work.
export async function writeFromReader(adapter, writePos, { reader, offset, size, isNcz, parsed }, progress) {
    if (isNcz) {
        const nczReader = new AdapterNCZReader(reader, offset, size);
        const decomp = new NCZDecompressor(nczReader);
        await decomp.decompress(
            progress,
            (chunk, chunkOffset) => adapter.write(writePos + chunkOffset, chunk),
            parsed);
    } else {
        await copyRange(reader, offset, size,
            (off, chunk) => adapter.write(writePos + off, chunk),
            progress);
    }
}
