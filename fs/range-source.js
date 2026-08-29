// Range sources: serve NCA ciphertext byte ranges by absolute NCA offset.
//
//   read(offset, length) -> Promise<Uint8Array>
//   registerRange(offset, length)  -- optional pre-registration
//
// Backends:
//  - BufferRangeSource: over an already-buffered NCA (or NCA-sized view).
//  - FileRangeSource: random access over a container reader (.nsp input).
//    Reads only the requested ranges — no section buffering.
//  - NczStreamSource: ONE sequential pass of NCZ decompression (.nsz input).
//    NCZ is sequential, so ranges must be requested in non-decreasing order.
//    The pump only discards bytes that precede the earliest not-yet-delivered
//    range, so it can never skip past a needed byte; a chunk may straddle a
//    range boundary (partial fill carries across chunks). Decompression stops
//    as soon as the last registered range is served.
//
// This is the same streaming discipline the NSZ→NSP converter uses
// (decompress chunk-by-chunk, consume, never buffer the whole NCA).

import { NCZDecompressor } from './ncz.js';
import { markMerge, markPump } from './debug-trace.js';

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

// RangeSource over a SparseNcaView (for NCA inputs whose sections are buffered
// but not contiguous — e.g. .nsz update: BKTR + ExeFS sections, non-monotonic
// patch access forbids a streaming source).
export class ViewRangeSource {
    constructor(view) {
        this._view = view;
    }
    get length() { return this._view.length; }
    registerRange() {}
    async read(offset, length) {
        return this._view.subarray(offset, offset + length);
    }
}

export class BufferRangeSource {
    constructor(data) {
        this._data = data;
    }
    get length() { return this._data.length; }
    registerRange() {}
    async read(offset, length) {
        if (offset < 0 || offset + length > this._data.length) {
            throw new Error(`BufferRangeSource: read [${offset}, ${offset + length}) out of bounds (len ${this._data.length})`);
        }
        return this._data.subarray(offset, offset + length);
    }
}

export class FileRangeSource {
    constructor(reader, fileOffset, fileSize) {
        this._reader = reader;
        this._fileOffset = fileOffset;
        this._fileSize = fileSize;
    }
    get length() { return this._fileSize; }
    registerRange() {}
    async read(offset, length) {
        if (offset < 0 || offset + length > this._fileSize) {
            throw new Error(`FileRangeSource: read [${offset}, ${offset + length}) out of bounds (len ${this._fileSize})`);
        }
        return await this._reader.read(this._fileOffset + offset, length);
    }
}

const STOP_PUMP = 'STOP_PUMP';

export class NczStreamSource {
    constructor(nczReader, parsed, log = () => {}) {
        this._reader = nczReader;
        this._parsed = parsed;
        this._log = log;
        this._ranges = [];
        this._nextRange = 0;
        this._discardedUpTo = 0;
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
            if (idx >= 0) sub = { off: offset - this._ranges[idx].start, len: length };
        }
        if (idx < 0) {
            if (this._pumpStarted && offset < this._discardedUpTo) {
                throw new Error('NczStreamSource: non-monotonic read — bytes already discarded (NCZ is sequential)');
            }
            idx = this.registerRange(offset, length);
        }
        const r = this._ranges[idx];
        if (!this._pumpStarted) {
            this._pumpStarted = true;
            this._pump();
        }
        if (!r.ready) {
            r.ready = new Promise((resolve, reject) => { r.resolve = resolve; r.reject = reject; });
        }
        markMerge(`NczStreamSource: waiting range #${idx}/${this._ranges.length} [0x${r.start.toString(16)}..0x${r.end.toString(16)}) filled ${r.filled}/${r.data.length}`);
        const data = await r.ready;
        markMerge('NczStreamSource: range ready');
        return sub ? data.subarray(sub.off, sub.off + sub.len) : data;
    }

    _pump() {
        markPump('pump: started');
        const decomp = new NCZDecompressor(this._reader);
        this._pumpPromise = decomp.decompress(() => {}, (chunk, offset) => {
            const cStart = offset, cEnd = offset + chunk.length;
            while (this._nextRange < this._ranges.length) {
                const r = this._ranges[this._nextRange];
                if (cEnd <= r.start) {
                    this._discardedUpTo = cEnd;
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
                    markPump(`pump: range #${this._nextRange - 1}/${this._ranges.length} filled`);
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
            if (e && e.message === STOP_PUMP) return; // normal early stop
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
