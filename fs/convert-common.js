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
        const kind = f.name.toLowerCase().endsWith('.ncz') ? 'ncz' : 'copy';
        const name = kind === 'ncz' ? f.name.replace(/\.ncz$/i, '.nca') : f.name;
        if (kind === 'ncz') {
            const headerReader = new AdapterNCZReader(adapter, f.offset, Math.min(f.size, 0x10000));
            const parsed = await parseNczSections(headerReader);
            metas.push({ kind: 'ncz', name, size: parsed.ncaSize, inputName: f.name, offset: f.offset, srcLen: f.size, parsed });
        } else {
            metas.push({ kind: 'copy', name, size: f.size, inputName: f.name, offset: f.offset });
        }
    }
    return metas;
}

// Write one member at writePos: NCZ → streaming decompress + hash, or raw
// copy. With verify+createHash the output is hashed and verified via
// verifyNcaHash. progress(fraction, label) is called during the work.
export async function writeMember({ meta, adapter, writePos, verify, createHash, cnmtHashMap, log, progress, progressBase, pct }) {
    if (meta.kind === 'ncz') {
        const hasher = verify ? createHash() : null;
        const nczReader = new AdapterNCZReader(adapter, meta.offset, meta.srcLen);
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

// Write one member from a file reader onto the adapter at writePos. Members are
// a discriminated union — the tag picks the operation and the shape dictates
// the fields, so no field ever has two meanings:
//   { kind: 'ncz',  reader, offset, srcLen, outLen, parsed? } → stream-decompress
//   { kind: 'copy', reader, offset, outLen }                  → copyRange as-is
// `srcLen` is ALWAYS the container (compressed) length to read; `outLen` is
// always the decompressed output size. progress(fraction) is called during work.
export async function writeFromReader(adapter, writePos, { kind, reader, offset, srcLen, outLen, parsed }, progress) {
    switch (kind) {
        case 'ncz': {
            // Reader length is the container (compressed) member size, never the
            // decompressed outLen: feeding past the zstd frame makes the WASM
            // wrapper call ZSTD_decompressStream on trailing garbage and fail
            // with error -10 (prefix_unknown).
            const nczReader = new AdapterNCZReader(reader, offset, srcLen);
            await new NCZDecompressor(nczReader).decompress(
                progress,
                (chunk, chunkOffset) => adapter.write(writePos + chunkOffset, chunk),
                parsed);
            break;
        }
        case 'copy': {
            let copiedBytes = 0;
            await copyRange(reader, offset, outLen,
                (off, chunk) => adapter.write(writePos + off, chunk),
                (n) => { copiedBytes += n; progress(copiedBytes / outLen); });
            break;
        }
        default:
            throw new Error(`writeFromReader: unknown member kind '${kind}'`);
    }
}