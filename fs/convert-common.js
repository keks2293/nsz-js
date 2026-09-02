// Shared NSZ/XCZ/merge/update logic: NCA hash verification, member meta
// collection, and per-member write (decompress-or-copy + optional verify).

import { NCZDecompressor, AdapterNCZReader, parseNczSections } from './ncz.js';
import { copyRange } from './adapter.js';

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
// only, first 0x10000 bytes) to learn the decompressed ncaSize. Metas carry the
// same discriminated union as writeFromReader members — `kind` picks the write
// operation, `srcLen` is the container (compressed) length, `size` the output
// length (== outLen):
//   { kind: 'ncz',  name, inputName, size, offset, srcLen, parsed } → decompress
//   { kind: 'copy', name, inputName, size, offset }                 → copy as-is
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

// ── Streaming member write (nsz/xcz/merge/update) ───────────────────────────

// Write one member from a reader onto the adapter at writePos. Members are a
// discriminated union — the tag picks the operation and the shape dictates the
// fields, so no field ever has two meanings:
//   { kind: 'ncz',  name?, inputName?, reader, offset, srcLen, outLen, parsed? } → stream-decompress
//   { kind: 'copy', name?, inputName?, reader, offset, outLen }                 → copyRange as-is
// `srcLen` is ALWAYS the container (compressed) length to read; `outLen` is
// always the decompressed output size. progress(fraction) is called during work.
// The source is `reader` — for nsz/xcz this is the shared adapter (its `read`
// serves the input container), for merge/update a dedicated member reader.
//
// With verifyOpts ({ verify, createHash, cnmtHashMap, log }) the written bytes
// are hashed (before the write, so SW/transfer adapters can't detach the
// buffer first) and checked via verifyNcaHash when `name` ends in a verifiable
// .nca. Abstracted from the old writeMember so there is a single branch-on-kind
// dispatch for all four pipelines.
export async function writeFromReader(adapter, writePos, { kind, name, inputName, reader, offset, srcLen, outLen, parsed }, progress, verifyOpts = {}) {
    const { verify = false, createHash = null, cnmtHashMap = null, log = null } = verifyOpts;
    // Hash bytes BEFORE the adapter write — SW/transfer adapters postMessage
    // the buffer with `transfer`, detaching it (length becomes 0).
    const writeAndHash = async (hasher, chunk, target) => {
        if (hasher) hasher.update(chunk);
        await adapter.write(target, chunk);
    };
    const verifyNca = (hasher) => {
        if (hasher && name && isVerifiableNca(name)) {
            verifyNcaHash({ hash: hasher.hex(), inputName: inputName || name, outputName: name, cnmtHashMap, log });
        }
    };

    switch (kind) {
        case 'ncz': {
            // Reader length is the container (compressed) member size, never the
            // decompressed outLen: feeding past the zstd frame makes the WASM
            // wrapper call ZSTD_decompressStream on trailing garbage and fail
            // with error -10 (prefix_unknown).
            const hasher = verify ? createHash() : null;
            const nczReader = new AdapterNCZReader(reader, offset, srcLen);
            await new NCZDecompressor(nczReader).decompress(
                progress,
                (chunk, chunkOffset) => writeAndHash(hasher, chunk, writePos + chunkOffset),
                parsed);
            verifyNca(hasher);
            break;
        }
        case 'copy': {
            const hasher = verify ? createHash() : null;
            let copiedBytes = 0;
            await copyRange(reader, offset, outLen,
                (off, chunk) => writeAndHash(hasher, chunk, writePos + off),
                (n) => { copiedBytes += n; progress(copiedBytes / outLen); });
            verifyNca(hasher);
            break;
        }
        default:
            throw new Error(`writeFromReader: unknown member kind '${kind}'`);
    }
}