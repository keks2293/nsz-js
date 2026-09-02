// Range sources: serve NCA ciphertext byte ranges by absolute NCA offset.
//
//   read(offset, length) -> Promise<Uint8Array>
//   registerRange(offset, length)  -- optional pre-registration
//
// Backends:
//  - BufferRangeSource: over an already-buffered NCA (Uint8Array).
//  - FileRangeSource: random access over a container reader (.nsp input).
//  - ViewRangeSource: over a SparseNcaView (sparse header + sections).
//  - NczStreamSource: ONE sequential pass of NCZ decompression (.nsz input).
//
// This is the same streaming discipline the NSZ→NSP converter uses
// (decompress chunk-by-chunk, consume, never buffer the whole NCA).

import { NCZDecompressor } from './ncz.js';

// Lazy zero-copy "sparse NCA" view. Serves subarray() over [header @0, sections at
// their original NCA offsets, zeros elsewhere] WITHOUT allocating an NCA-sized
// buffer (the old buildSparseNcaBuffer copied every section into a full-size
// zero-filled Uint8Array, doubling memory). A range fully inside one section
// returns a zero-copy subview; mixed ranges (zero gap + data, header straddles)
// are materialized — in practice those are small (exefs section gap, 0xC00).
export class SparseNcaView {
    constructor(header, sections) {
        this._header = header;
        this._sections = sections;
        let maxEnd = NCA_HEADER_SIZE;
        for (const s of sections) {
            maxEnd = Math.max(maxEnd, s.offset + s.data.length);
        }
        this.size = maxEnd;
    }
    get length() { return this.size; }
    subarray(start, end = this.size) {
        if (end <= start) return new Uint8Array(0);
        if (end <= NCA_HEADER_SIZE) {
            return this._header.subarray(start, end);
        }
        for (const s of this._sections) {
            if (start >= s.offset && end <= s.offset + s.data.length) {
                return s.data.subarray(start - s.offset, end - s.offset);
            }
        }
        const out = new Uint8Array(end - start);
        if (start < NCA_HEADER_SIZE) {
            out.set(this._header.subarray(start, Math.min(end, NCA_HEADER_SIZE)), 0);
        }
        for (const s of this._sections) {
            const a = Math.max(start, s.offset) - start;
            const b = Math.min(end, s.offset + s.data.length) - start;
            if (b > a) out.set(s.data.subarray(s.offset + a - s.offset, s.offset + b - s.offset), a);
        }
        return out;
    }
}

const NCA_HEADER_SIZE = 0xC00;

// Unified random-access range source. All three backends share the same
// structure; the only difference is how data is fetched:
//   - subarray() for in-memory buffers/views
//   - reader.read() for container files
//
// read(offset, length) -> Promise<Uint8Array>
// registerRange()      -> no-op (used by NczStreamSource which is sequential)
//
// Exported factory constructors preserve the original API:
//   new BufferRangeSource(ncaData)
//   new FileRangeSource(containerReader, fileOffset, fileSize)
//   new ViewRangeSource(view)

class RangeSource {
    constructor(length, readFn) {
        this._length = length;
        this._read = readFn;
    }
    get length() { return this._length; }
    registerRange() {}
    async read(offset, length) {
        if (offset < 0 || offset + length > this._length) {
            throw new Error(`RangeSource: read [${offset}, ${offset + length}) out of bounds (len ${this._length})`);
        }
        return this._read(offset, length);
    }
}

export function BufferRangeSource(data) {
    return new RangeSource(data.length, (offset, length) => data.subarray(offset, offset + length));
}

export function FileRangeSource(reader, fileOffset, fileSize) {
    return new RangeSource(fileSize, (offset, length) => reader.read(fileOffset + offset, length));
}

export function ViewRangeSource(view) {
    return new RangeSource(view.length, (offset, length) => view.subarray(offset, offset + length));
}

const STOP_PUMP = 'STOP_PUMP';

export class NczStreamSource {
    constructor(nczReader, parsed, log = () => {}) {
        this._reader = nczReader;
        this._parsed = parsed;
        this._log = log;
        this._ranges = [];
        this._nextRange = 0;
        this._pumpStarted = false;
        this._pumpError = null;
    }
    get length() { return this._parsed.ncaSize; }

    registerRange(offset, length) {
        const last = this._ranges[this._ranges.length - 1];
        if (last && offset < last.end) {
            throw new Error('NczStreamSource: ranges must be strictly increasing (NCZ is sequential)');
        }
        this._ranges.push({
            start: offset, end: offset + length,
            data: new Uint8Array(length), filled: 0,
            ready: null, resolve: null, reject: null,
        });
        return this._ranges.length - 1;
    }

    async read(offset, length) {
        const end = offset + length;
        if (offset < 0 || end > this._parsed.ncaSize) {
            throw new Error(`NczStreamSource: read [${offset}, ${end}) out of bounds (ncaSize ${this._parsed.ncaSize})`);
        }
        // Find a registered range that exactly matches [offset, end), or one that
        // CONTAINS it (a sub-range read returns a zero-copy view of the buffered
        // range data — lets the caller read a large registered range in chunks).
        let idx = this._ranges.findIndex(r => r.start === offset && r.end === end);
        let sub = null;
        if (idx < 0) {
            idx = this._ranges.findIndex(r => r.start <= offset && end <= r.end);
            if (idx < 0) {
                // All ranges are pre-registered up front (strictly increasing) by
                // the caller — a read outside them is a usage error, not lazy-fill.
                throw new Error(`NczStreamSource: read [0x${offset.toString(16)}, 0x${end.toString(16)}) has no registered range — register ranges up front (NCZ is sequential)`);
            }
            sub = { off: offset - this._ranges[idx].start, len: length };
        }
        const r = this._ranges[idx];
        // Fast path: the pump (unthrottled, runs ahead of a slow consumer) may
        // have filled this range before any read of it. r.ready was never
        // created, so awaiting it would deadlock — return the buffered data.
        if (r.filled === r.data.length) {
            return sub ? r.data.subarray(sub.off, sub.off + sub.len) : r.data;
        }
        if (this._pumpError) {
            throw this._pumpError;
        }
        if (!this._pumpStarted) {
            this._pumpStarted = true;
            this._pump();
        }
        if (!r.ready) {
            r.ready = new Promise((resolve, reject) => { r.resolve = resolve; r.reject = reject; });
        }
        const data = await r.ready;
        return sub ? data.subarray(sub.off, sub.off + sub.len) : data;
    }

    _pump() {
        const decomp = new NCZDecompressor(this._reader);
        this._pumpPromise = decomp.decompress(() => {}, (chunk, offset) => {
            const cStart = offset, cEnd = offset + chunk.length;
            while (this._nextRange < this._ranges.length) {
                const r = this._ranges[this._nextRange];
                if (cEnd <= r.start) {
                    break; // chunk precedes the range — discard
                }
                if (cStart > r.end) {
                    throw new Error('NczStreamSource: decompression skipped past a registered range');
                }
                const a = Math.max(cStart, r.start);
                const b = Math.min(cEnd, r.end);
                r.data.set(chunk.subarray(a - cStart, b - cStart), a - r.start);
                r.filled = b - r.start;
                if (r.filled === r.data.length) {
                    this._nextRange++;
                    if (r.resolve) r.resolve(r.data);
                    // chunk may cover the next range too — loop continues
                } else {
                    break; // range extends past this chunk — wait for more data
                }
            }
            if (this._nextRange >= this._ranges.length) {
                throw new Error(STOP_PUMP);
            }
        }, this._parsed).catch(e => {
            if (e && e.message === STOP_PUMP) { return; } // normal early stop — all ranges filled
            this._pumpError = e;
            for (const r of this._ranges) {
                if (r.reject) r.reject(e);
            }
        }).finally(() => {
            for (const r of this._ranges) {
                if (r.filled < r.data.length && r.reject) {
                    r.reject(this._pumpError || new Error('NczStreamSource: NCA data ended before registered range'));
                }
            }
        });
    }
}
