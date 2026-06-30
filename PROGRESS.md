# NSZ to NSP Converter - Status Report

## ✅ Recent Changes (2026-06-30)

1. **Perf: simplify `AsyncBlockDecompressorReader.read()` to single block lookup, remove dead `concatBytes`** — `fs/ncz.js`. Replaced while-loop + `concatBytes(...)` pattern with direct single-block lookup. Each `read(n)` call now returns at most one block (subarray), eliminating the temporary buffer array and concat allocation. Function `concatBytes` removed as dead code. All existing tests pass.

2. **Refactor: split decompress back to streaming/block paths, add FakeSection** — `fs/ncz.js`. Removed `ZstdStreamReader` buffered-reader abstraction, reverted to two independent paths: `_decompressStream` (for `decodeStream`/CLI stdout — processes chunks immediately via `for await`) and `_decompressBlocks` (for `AsyncBlockDecompressorReader` sections loop). Added `FakeSection` when `sections[0].offset > 0x4000` (matches Python nsz behavior). Fixed CLI exit handler race — register `close` listener immediately after `spawn`. Benchmarked copy overhead: ~10ms on 221MB (~0.03%) — negligible, but correctness fix for WASM. WASM `decodeStream` yields views into mutable WASM memory that must be consumed synchronously; `ZstdStreamReader` deferred consumption, forcing an unnecessary `Uint8Array(chunk)` copy. Immediate consumption eliminates the copy. All existing tests pass.

## ✅ Recent Changes (2026-06-29)

1. **Refactor: extract converters into shared modules** — `fs/xcz-convert.js`, `fs/nsz-convert.js` (new).
   - `fs/xcz-convert.js`: `convertXCZStreaming` + `convertXCZMemory` with adapter interface `{ read, write, createHash, log, progress }`. XCI layout computed via `buildPartitionMetas`+`computeLayout`, written by `writeXciHeaders`+`writePartitions`. Shared with `converter.js` (browser) and `nsz-cli.js` (Node).
   - `fs/nsz-convert.js`: `convertNSZStreaming` + `convertNSZMemory` with same adapter pattern. `collectOutputMeta`/`collectCnmtHashes` helpers reused in both paths. `buildPfs0Blob` shared.
   - `converter.js`: 496→280 lines, delegates to shared modules. `nsz-cli.js`: ~170→~30 lines per function.
   - `fs/ncz.js`: `AdapterNCZReader` (colocated with `DataReader` base class), reused by both converter modules.
   - `verifyHash`/`verifyFileNameHash`: local functions in `fs/nsz-convert.js` + `fs/xcz-convert.js` (not a shared module — inline per consumer matches pre-refactoring pattern). Non-NCZ files are not hashed (matches Python nsz behavior).
   - **Regression benchmark** (commit `64fed88` vs `4e6330d`, 7 runs each, 109MB NSZ, `--no-verify`):
     - OLD: 0.320–0.424s (avg 0.386s). NEW: 0.315–0.339s (avg 0.325s).
     - **−15.6% faster**.

## ✅ Recent Changes (2026-06-28)

10. **Optimize SHA256 internal buffer: plain Array → Uint8Array** — `crypto/sha256.js:67`. Replaced `this.buf = []` (plain JS Array with byte-by-byte `.push()` → boxed Number heap allocations) with `this.buf = new Uint8Array(256)` + offset pointer `this.bufLen`. Hot path `.update()` now uses `buf.set(subarray, offset)` — zero boxing, zero GC. Padding/finalization in `hexdigest()` uses direct index assignment + `fill()` + `copyWithin()`. Single allocation at construction, no resizing. Microbenchmark: −4.5% on SHA256 alone.

9. **Remove sha256 verification for non-NCZ files, skip CNMT when verify=off, add `--no-verify` CLI flag** — `converter.js`, `nsz-cli.js`. Python nsz doesn't hash non-NCZ files (.tik, .cert, etc.); they're just copied. Removed 4 redundant `sha256(data)` calls. Also skip CNMT extraction entirely when verify=off (both NSZ and XCZ paths). CLI gains `--no-verify`/`-nv` flag — skips CNMT, SHA256 hashing, and hash verification. Benchmark: 0.535s vs 0.65s = 17% faster on 109MB NSZ.

8. **Fix Uint8Array counter increment overflow bug** — `crypto/aes128.js:264`, `crypto/aesctr.mjs:84-87`. `++counter[j]` on a `Uint8Array` returns the **full integer** (e.g. `256`) before truncation to `0x00`. The check `if (++counter[j]) break` was **always truthy on overflow**, breaking carry propagation past byte 0xFF → counter wrapped at 256 blocks (4096 bytes). Pure JS AES-CTR produced garbage for any data >64KB after block 256. Fix: separate `counter[j]++; if (counter[j]) break;` — the stored value is the correct truncated Uint8, and `0x00` is falsy so carry propagates correctly.

7. **Re-instate async WebCrypto path** — `crypto/aesctr.mjs`: `encrypt()`/`decrypt()` are `async`. Browser uses WebCrypto `crypto.subtle.encrypt('AES-CTR')` (hardware-accelerated), Node.js uses sync `crypto.createCipheriv()` (wrapped in async Promise — ~2ms overhead for 500MB, negligible). Pure JS `AesEcb` fallback only when WebCrypto unavailable. All callers in `fs/ncz.js`, `converter.js` use `await`.

## ✅ Recent Changes (2026-06-27)

1. **Decision: keep `%`/`Math.floor` in aes128.js for readability** — V8 TurboFan strength-reduces power-of-2 `%` to `&` automatically (< 1 ns difference per op). Manual `%`→`&` gave < 6% on full AES block encrypt/decrypt — not worth the readability loss. Refactor commit `c071523` already uses `%`/`Math.floor` directly.

2. **Cleanup: remove redundant `Number(remainder)` in ncz.js**, fixup'd revert into Refactor AES commit.

4. **Fix CNMT field offsets matching Python nsz** — `fs/cnmt.js`: `headerOffset`, `contentEntryCount`, `metaEntryCount` were at wrong offsets (18/20/22 instead of Python's 14/16/18). Caused `contentEntryCount=0` on all valid CNMT files → `Found 0 expected NCA hashes from CNMT`. Also: `converter.js`: `NSZConverter` constructor now accepts `keys` parameter (`constructor(keys = null)`). `nsz-cli.js`: passes `keys` when constructing `NSZConverter` for CNMT extraction.
5. **AES-XTS + AES-CTR NCA header decryption in `extractCnmtHashes`** — `converter.js`: XTS-decrypts NCA header (0xC00 bytes) with `header_key`, unwraps key block with `key_area_key_application`, AES-CTR decrypts section data, skips hash tree, extracts CNMT XML from PFS0. Verified: Trackline Express NSZ extraction matches Python nsz — all 3 NCA hashes `[VERIFIED]`.
6. **Browser-compatible AES-ECB in `extractCnmtHashes`** — `converter.js`: `import('crypto')` fails in browser (esbuild external). Wrapped in try/catch with pure-JS `AesEcb` fallback. Fixes `Found 0 expected NCA hashes from CNMT` in browser path.
7. **Fix sync/async mismatch in `AesCtr` for browser WebCrypto path** — `crypto/aesctr.mjs`: `_webTransform()` was async but `encrypt()`/`decrypt()` didn't `await` it, returning a Promise instead of Uint8Array when WebCrypto was active. Made `encrypt()`/`decrypt()` async. Updated all callers in `fs/ncz.js`, `converter.js` to `await` the result.

## ✅ Recent Changes (2026-06-26)

10. **Perf: slice→subarray, remove redundant await/Buffer.from** — `fs/ncz.js`: `slice`→`subarray`, removed `await` from sync calls, dropped `Buffer.from` wrapper. Benchmarked: −7.7% user CPU on 109MB NSZ.

11. **Fix NCAHeader/BKTR to handle both ArrayBuffer and Uint8Array** — `fs/nca.js`. Use `arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)` — zero excess allocations for Uint8Array input, one for ArrayBuffer.

## ✅ Recent Changes (2026-06-23)

10. **Fix pure JS AESECB in `aes128.js`** — Three bugs fixed:
    - `keySchedule()`: rcon lookup was off-by-one (`rcon_table[1]` used for round 1, should be `rcon_table[0]`). Fix: `rcon_table[Math.floor(i / constNk) - 1]`
    - `rotateOp()`: used arithmetic `>> 24` which sign-extends when MSB ≥ 0x80, corrupting key schedule for keys with bit 31 set in any word. Fix: `>>> 24`
    - `shiftRows()`/`invShiftRows()`: swapped rows 1&3 instead of rotating within each row. Fix: transpose then rotate via `state[j*4 + i] = tmp[i*4 + (j+i)%4]` (aes-js style)
    Verified against NIST vectors and 100 random roundtrips match Node.js native AES.

## ✅ Recent Changes (2026-06-25)

5. **Remove dead ArrayBuffer branch from PFS0 constructor** — `fs/pfs0.js:2-9`. Constructor had 3 branches: `Uint8Array` (no copy), `ArrayBuffer` (wrap), else (`new Uint8Array`). `ArrayBuffer` branch never called — all callers pass `Uint8Array` or `Buffer`. Simplified to `this._data = new Uint8Array(data)`.

6. **Remove dead `hfs0Data` field from nsz-cli partitionMetas** — `nsz-cli.js:129,139`. `hfs0Data: null` was set in partition metadata objects but never read. Left over from pre-HFS0Writer refactoring when CLI built HFS0 in memory. Still alive in `converter.js` (local variable, used for XCI build).

7. **Add CNMT verification to CLI NSZ path** — `nsz-cli.js:278-291,335-337,345-347`. `convertNSZ` was missing CNMT hash collection and `verifyHash` calls. Added: same pattern as `convertXCZ` — collect CNMT hashes from `.cnmt.nca` files via `NSZConverter.extractCnmtHashes`, then verify each NCA hash against the expected set. `[VERIFIED]`/`[CORRUPTED]` logs now appear for NSZ→NSP conversion too.

8. **Fix `extractCnmtHashes` returning 0 hashes** — `converter.js`. CNMT NCA section data is wrapped in a PFS0 filesystem, but `extractCnmtHashes` passed it directly to `Cnmt.parse`. Added PFS0 unwrapping: check for `PFS0\0` magic, parse as PFS0, extract first file, then pass to `Cnmt.parse`. This caused `Found 0 expected NCA hashes from CNMT` and no `[VERIFIED]`/`[CORRUPTED]` output even with Verify enabled.

9. **Remove dead `decompressNCZtoNCA`, add `verifyFileNameHash` fallback** — `converter.js`, `nsz-cli.js`. Standalone NCZ conversion (`decompressNCZtoNCA`) was dead code — never called from anywhere. Removed. Added `verifyFileNameHash(hash, nczName, ncaName, onLog)` — extracts first 32 chars from NCZ filename stem, compares against `hash[:32]`. Used as fallback in all verification paths when `cnmtHashes` is empty (no CNMT available). Follows Python nsz `NszDecompressor.py:28-32`.

## ✅ Recent Changes (2026-06-24)

1. **Extract `verifyHash` to standalone function** — `verifyHash` was defined inside `decompressNSZtoNSP` (line 92-101) but not in `decompressXCZtoXCI` (line 277). When `verify=true` was passed to XCZ conversion, all 4 call sites threw `ReferenceError: verifyHash is not defined`, crashing the conversion. Also: dead top-level `verifyHash` referenced undefined `onLog`. Fixed: single standalone `verifyHash(hash, name, fileHashes, onLog)` at module level. Follows ESLint `class-methods-use-this`.

2. **titlekek_source fallback in keys.js** — `keys.js:35` required `titlekek_source` key to be present; missing key caused silent failure (empty Uint8Array → wrong derived keys). Added fallback to `keys.titlekek` if `titlekek_source` is absent, with explicit error if neither is found.

3. **PFS0.open(reader) static factory** — `fs/pfs0.js`. Added `PFS0.open(reader)` static method that probes 16 bytes, reads exact header size, and creates PFS0 instance. Updated `converter.js` and `nsz-cli.js` to use `PFS0.open(reader)` instead of 1MB buffer reads. Matches Python nsz `Pfs0.open()` — reader-based, no fixed buffer size.

4. **AESCTR async→sync in Node.js** — `crypto/aesctr.mjs`. `encrypt()`/`decrypt()` were `async` even though `_nodeTransform()` is sync. Hot loop (`ncz.js:333,436`) created 2 microtask ticks per call. Fixed: sync in Node.js + pure JS fallback, async only for WebCrypto. ~2ms saved on 212MB file (within noise, not bottleneck).

### Performance Benchmarks (Trackline Express, 212MB NCA, 10 runs)
| Test | Result |
|---|---|
| AESCTR async→sync (b5701fe vs HEAD) | 447.6ms vs 445.5ms — ~2ms, within noise |
| PFS0: old 1MB readSync vs new PFS0.open | 0.20ms vs 0.26ms — negligible |
| ZSTD: CLI vs WASM in Node.js | 417.8ms vs 590.6ms — CLI 41% faster (native C++) |

## ✅ Recent Changes (2026-06-22)

9. **Fix AESECB decrypt() PKCS7 unpadding bug** — `crypto/aes128.js:128-144` — `decrypt()` stripped PKCS7 padding from last block, but key derivation (`keys.js:65,68,71`) passes raw 16-byte blocks with no padding. If `decrypted[15]` fell in [1,16], the key was truncated. ~18% chance of wrong key per derivation. Fixed: removed PKCS7 unpadding (matches Python nsz `AESECB.decrypt()` which does raw AES-ECB). Added block alignment check (`data.length % 16 !== 0` throws). Also fixed `encrypt()` to use PKCS7 padding for partial blocks (matches Python nsz `_pad_partial_block()`).
8. **Fix XCZ→XCI partition overlap** — Root HFS0 entry size was `pm.hfs0BufferSize` (header only), not `pm.hfs0BufferSize + pm.totalSize` (header + data). This caused partition N+1 header to overlap with partition N data when multiple non-empty partitions exist. Fixed in both `converter.js` streaming path and `nsz-cli.js` CLI path. Refactored to use `partSizes[]` array computed once, matching Python nsz pattern where `f['size']` stores full partition size. Added documentation to `HFS0-OFFSET-CONVENTION.md` explaining why JS uses pre-calculate (browser `FileSystemWritableFileStream` can't use Python's streaming `add()`+`resize()` approach).
7. **Full codebase bug review** — Found 11 bugs. Critical: XCZ partition overlap (converter.js:355-365, nsz-cli.js:166-178). Significant: AES-ECB PKCS7 padding in key derivation (aes128.js:128-139 → keys.js:65,68,71). Moderate: accumulatedBytes not updated on error, blockIndex uninitialized, DataView fragility, dead padding code. Low: iframe DOM leak, Content-Disposition injection, unchecked readSync. Awaiting user decision on which to fix.
1. **Fix `offsetInSection` → `offset` bug in CLI** — `nsz-cli.js:177` — `po.offset` was `undefined` (`offsetInSection: currentDataPos`), causing all `fs.writeSync` to write at cursor instead of absolute position. Fixed to `offset: ROOT_DATA_SECTION + currentDataPos`.
2. **Remove dead `hfs0Data` reference** — `converter.js:343` — `hfs0Data,` in `partitionMetas.push()` referenced undefined variable, left over from refactor. Removed (field was never consumed).
3. **Folded both fixes into original commits** — `hfs0Data` and `pHeaderSize` fixed in the refactor commit itself, no separate fix commits.
4. **Fix error cleanup: close writable and removeEntry on conversion failure** — `outputName` moved outside `try` block. On conversion failure, closes the writable stream and removes the partial output file from the filesystem.
5. **Fix `writable` ReferenceError in catch block** — `let writable = null;` was declared inside `try` with `let`, making it inaccessible in `catch` (block-scoped). Moved it alongside `outputName` before the `try` block. Without this, any error path would throw `ReferenceError: writable is not defined`, silently skipping error status and file list update.
6. **Load keys once at startup, not on every convert** — Moved `loadDefaultKeys()` from the convert button handler to after `converter.init()`. Keys file is static, no reason to re-fetch it on each conversion.

## ✅ Recent Changes (2026-06-21)

1. **iOS 27 segmented control for download mode** — Mode pills now use `.pills.segmented`: connected with shared border (`gap: 0`, `border-left: none` on siblings), first/last rounded corners, active pill uses accent fill (`var(--accent-glow)`). Options pills remain separate with `gap: 4px`.
2. **Compact mobile setting rows** — `.setting` padding reduced from `10px 14px` to `6px 14px`, eliminating scroll before drop. Desktop padding also reduced: `14px 16px` → `10px 16px`. Pills centered. Removed `flex-shrink: 0` (unused).
3. **12px pills on desktop** — `@media (min-width: 900px)` now sets `.pill { font-size: 12px }`.
4. **Label: "Download mode"** (not "Save mode").
5. **Removed `min-width: 0`** from `@media (max-width: 380px)` `.pill` rule.
6. **Removed `0%` default from progress percent** — stays empty until conversion starts.

## ✅ Recent Changes (2026-06-21) (Previous)

## ✅ Recent Changes (2026-06-19)

1. **esbuild bundle** — All JS modules bundled into single `out/app.mjs` (178KB) via esbuild. 1 HTTP request instead of 15+ separate module imports. Solves `ERR_HTTP2_PING_FAILED` on Netlify CDN caused by too many parallel HTTP/2 streams. Build: `npm run build`. Netlify needs build command set to `npm run build`.

## ✅ Recent Changes (2026-06-18)

0. **Zstd init with fallback UI** — `main.js` calls `converter.init()` at startup. On failure (e.g. network down), shows `#jsFallback` with Retry button (`location.reload()`). Added `window.addLog` in `index.html` so errors log before main.js loads. Initially added retries for both `index.html` (import) and `main.js` (init), but removed them — retrying dynamic imports doesn't help when the page itself needs a full reload. Errors seen: `ERR_HTTP2_PING_FAILED` (Netlify CDN drops HTTP/2 connections). Removed unnecessary `DOMContentLoaded` wrapper (import() is already deferred).

1. **Fixed "Ready" false state before JS loads** — Static HTML showed "Ready" in progressTitle (`index.html:672`) before any JS ran. If main.js (ES module with import chain) loaded slowly, user saw "Ready" but no log entries. Changed HTML default to empty, added spinner, JS sets "Ready" only after `converter.init()` completes (`main.js:462`). Also reset to "Ready" when file list becomes empty.

## ✅ Recent Changes (2026-06-18) (Previous)

1. **Simplified progress calculation — removed fixed offsets, byte-weighted overall** — Replaced `pct = (bytes) => 0.02 + 0.93 * (bytes / totalDataSize)` with `bytes / totalDataSize` in all 4 places in converter.js. Removed `onProgress(0.02, 'Reading container...')` call. Removed all `0.95` building-phase progress calls. Removed NSZ remapping `(p - 0.02) / 0.98` in main.js. Changed overall progress from file-count-weighted `(i + p) / totalFiles` to byte-weighted `(accumulatedBytes + file.size * p) / totalBytes`.

2. **Hidden Overwrite toggle for non-FSA modes** — Overwrite only works in FSA mode; now hidden when Stream or Blob is selected. Added `.pill.hidden` CSS class (index.html:383), toggle logic in download mode switch handler (main.js:259) and init (main.js:98).

3. **Fixed layout elongation after conversion** — Root cause: grid items (`.main-left`, `.main-right`) with default `min-height: auto` grow the grid row to fit all content, pushing past viewport. Fixed by `min-height: 0` on both grid column flex containers in desktop media query. Also: `height: auto` on `.drop-zone` desktop override to avoid conflict with mobile `height: clamp(...)`. Changes in `index.html` lines 549-568.

## ✅ Recent Changes (2026-06-17)

1. **Added Verify toggle to browser UI** — New `Verify` button in Options (`index.html`) defaults to OFF, skipping SHA-256 hash computation. Gives ~6x speedup in browser streaming path (pure JS SHA-256 is the dominant bottleneck). Guarded by `verify` option in all 3 converter methods (`decompressNSZtoNSP`, `decompressNCZtoNCA`, `decompressXCZtoXCI`). Default `verify=false` — no change for CLI (uses native `crypto.createHash` independently).

## ✅ Recent Changes (2026-06-14)

1. **Deleted `_decompressBuffered`** — Memory path now uses `_decompressStream` with `collectChunk` wrapper (`fs/ncz.js:220`). Reads input as stream, collects output into buffer. Removed ~80 lines of duplicated decompression logic.

2. **Aligned hash verification with Python nsz** — Extracted `verifyHash` method, removed dead `hash in cnmtHashes` bug, split NCZ/NCA verification, moved `.nca` check to call sites, added `[VERIFIED]`/`[CORRUPTED]` with hash, `[EXISTS]` logging, `[MISSMATCH]` for standalone NCZ.

3. **Per-partition XCZ hash verification** — Python nsz extracts CNMT hashes from each XCI partition independently. Now both NCZ and non-NCZ .nca files verified against partition-specific CNMT hashes.

4. **blockSizeExponent validation** — Added range check (14-32) matching Python nsz `BlockDecompressorReader`.

5. **Delete partial output on error** — CLI now deletes incomplete output files on conversion failure.

6. **Removed CLI Buffer.from(chunk) copies** — `fs.writeSync` accepts Uint8Array directly.

7. **Updated IMPROVEMENTS.md** — All items resolved, added speed/memory optimization attempts.

8. **Updated README** — Added Python nsz compatibility section, verification behavior, architecture notes.

## ✅ Recent Changes (2026-06-12)

1. **Added "Overwrite" toggle option** — New toggle in browser UI settings panel (`index.html`) allows controlling FSA file creation behavior. Defaults to on (overwrite existing files). Added as a `.toggle-group` alongside the existing "Fix Padding" toggle in the Options setting group. JavaScript handler not yet wired in `main.js`.

2. **Fixed ES modules CORS issue** — Browser `file://` protocol blocks ES module script loading. Fixed by using `python3 -m http.server 8080` to serve files via HTTP.

## ✅ Recent Changes (2026-05-30)

1. **HFS0 offset convention changed to match hactool** — All HFS0 writers (`HFS0Writer`, `XCIWriter`, `_buildPartitionHfs0*` in converter.js, `nsz-cli.js` root/partition entries) now store `absolutePos - actualHeaderSize` instead of `absolutePos`. The `HFS0Reader` reconstructs the absolute offset as `baseOffset + actualHeaderSize + storedOffset`. This matches Python nsz commit `b445f666` and hactool's `absolute = base + header_size + cur_file->offset`. 7 sites updated across 3 files.

2. **XCZ→XCI: proper nested XCI output** — `fs/xci.js`, `converter.js`, `nsz-cli.js` rewritten to produce full XCI with root HFS0 at `0xF000` containing partition entries (`secure`, `normal`, `update`, `logo`). Each partition is a nested HFS0 with `0x8000` header padding containing the decompressed NCA files. Matches Python nsz output structure. Previously produced a flat HFS0 at `0x200` which treated partition names as filenames.

3. **nsz-cli.js root HFS0 padded to 0x8000** — Root HFS0 now written as 0x8000 bytes (std. convention: partition offsets relative to HFS0 base at 0xF000, so first partition stored as 0x8000 - actualHeader). Partition HFS0 uses dynamic `pHeaderSize` for actual padding. Fix: `writePos` and file entry offsets now use `pHeaderSize` instead of hardcoded `PARTITION_HEADER_SIZE`.

4. **Removed dead code in converter.js** — Cleaned up unused `inputFile`/`origFiles` variables in streaming path (lines 411-412) and unused `hfs0`/`hfs0Data` variables in memory path (lines 461-463).

5. **Fixed `nsz-cli.js` unused HFS0Writer import** — Removed unused HFS0Writer import from nsz-cli.js.

## ✅ Recent Changes (2026-05-17)

1. **SW download: hidden iframes pre-created upfront, one per file** — All hidden `<iframe>` elements are created before the conversion loop (`main.js:265-270`). Each file in the loop uses its pre-allocated iframe, navigating it to the SW stream URL only after the stream is registered. No `window.open` calls, no new tabs. (`main.js:36-39`, `main.js:265-270`)

## ✅ Recent Changes (2026-05-15)

1. **Shared ZSTDDecoder instance in `crypto/zstd.js`** — WASM `ZSTDDecoder` is instantiated once and reused across all `decompressBuffer` calls. Eliminates repeated WASM module import + decoder init + memory allocation per decompress call. The WASM instance is captured for raw API access via `ZstdDecompressor.instance`. Removed unused `decompressStreaming` static method.

2. **Eliminated `compressedChunks` pre-buffering in `fs/ncz.js`** — `_decompressStream` no longer reads all compressed data into an array before decompressing. Node.js path reads chunks lazily and writes to zstd stdin; browser path uses new `crypto/zstddec-stream-wrapper.js` which wraps zstddec's raw WASM exports (`ZSTD_createDCtx`/`ZSTD_decompressStream`) as an async generator with lazy `readChunk`. Peak RAM drops from file-size to 16 MB chunks.

3. **Replaced hash-wasm with Web Crypto API SHA-256** — hash-wasm WASM was 1 min slower than pure JS (WASM init overhead, SHA-256 not the bottleneck). Now uses `crypto.subtle.digest('SHA-256')` (browser) and `crypto.createHash('sha256')` (Node.js) — native, hardware-accelerated, zero init overhead. Falls back to pure JS.
4. **Updated `TEST_RESULTS.md` with speed comparison** — hash-wasm was 2m53s vs pure JS 1m51s for 5 GB NSZ conversion.
5. **Fixed SHA256 class bit-length encoding** — `>>> 32` in JS is a no-op (shifts mask to 5 bits). Split into hi/lo 32-bit words. Also fixed padding math (was padding to 64 instead of 56 bytes, leaving the 8-byte length field untransformed). Both bugs caused incorrect SHA-256 for all non-empty inputs.

## ✅ Recent Changes (2026-05-13)

1. **SW streaming: fixed `<a download>` not intercepted by SW** — Chrome's download manager bypasses the Service Worker for `<a download>` fetches (no `[SW] fetch` log seen). Replaced with `window.open(streamUrl)` — navigation fetches are always routed through the SW. The SW responds with `Content-Disposition: attachment` which triggers the download.

2. **Blob parts instead of giant Uint8Array** — `buildPFS0Memory` now passes file data as individual Blob parts instead of allocating a contiguous `new Uint8Array(totalSize)` and copying. Eliminates peak 2× memory overhead during PFS0 container building.

3. **NCZ→NCA streaming write support** — Added `writable` path to `decompressNCZtoNCA`. Uses NCZ decompressor's `writeChunk` callback with correct absolute positions for random-access `createWritable` writes. Memory path unchanged (NCZ needs random-access, not sequential).

4. **Mobile: SW streaming download instead of Blob** — On mobile (broken `createWritable`), registers a Service Worker at `sw.js` that creates a `ReadableStream`. Data chunks are sent to the SW via `postMessage` with zero-copy `Transferable` buffers and enqueued into the stream. The browser download manager consumes the stream immediately — peak memory drops from file-size to chunk-size. Falls back to Blob download if SW unavailable.

5. **Download mode switch** — UI radio buttons in `index.html` let the user pick: Auto (FSA→SW→Blob), File System (force FSA), Stream (force SW), Blob (force memory download). Mode state in `downloadMode` variable in `main.js`.

## ✅ Recent Changes (2026-05-10)

1. **Consolidated PFS0 writing into `pfs0.js`** — All PFS0 header building logic moved into `PFS0Writer` class. Removed duplicated inline header builders from `converter.js`, `nsz-cli.js`, `node/decompressor.js`.

2. **PFS0 alignment: two modes matching Python nsz** — Default uses 16-byte alignment `(16 - n%16) % 16` (Python nsz default); `--fix-padding` uses 0x20 alignment via `0x20 - n%0x20` (Python's `align0x20`). Verified: JS default output is byte-identical to Python nsz output.

3. **Fixed absolute offset bug in `node/decompressor.js:writeNSP`** — Was writing absolute file positions instead of offsets relative to header end. Fixed by `PFS0Writer` which correctly tracks relative offsets from 0.

4. **Fixed `FileDescriptorReader.read` for Node v25** — `fs/promises` dropped the `read` export; switched to callback-based `fs.read` wrapped in Promise.

5. **Verified JS output vs Python nsz** — Both default and `--fix-padding` modes produce byte-identical file data to Python nsz. Default mode output is 100% byte-identical. `--fix-padding` provides 0x20-aligned headers.

6. **Moved modules to `fs/` directory** — `pfs0.js`, `ncz.js`, `xci.js`, `ticket.js` moved from root to `fs/` matching Python nsz's `Fs/` layout. Removed unused `node/fs/` directory. All imports updated.

7. **Cleanup: removed dead code** — Removed `crypto/aesxts.js` (never imported), `node/nsz.js` + `node/decompressor.js` + `node/fileExistingChecks.js` (broken CLI chain referencing deleted `node/fs/`), `node/pathTools.js` + `node/parseArguments.js` (both never imported). Removed dead `sha256` import/export from `fs/ticket.js`. Updated `package.json` — `main` → `nsz-cli.js`, scripts use `nsz-cli.js`.

8. **Added `--help`/`-h` flag to CLI** — `nsz-cli.js` now handles `--help` and `-h` flags to display usage. Previously fell through to `stat()` call and crashed with ENOENT.

9. **Renamed `nsz-convert.js` → `nsz-cli.js`** — Clearer name for the Node.js CLI entry point. Updated all references in `package.json`, `README.md`, `PROGRESS.md`, `BROWSER-ZSTD-LIMITATION.md`, `FIXES_PLAN.md`, and usage string.

10. **Removed `node/keys.js`** — Dead code; nothing imported it. Functionality superseded by `keys.js` (KeysParser) and `crypto/` modules.

## ✅ Recent Changes (2026-05-09)

1. **Node.js CLI rewritten for large files** — No more `fs.readFileSync`. Uses `FileDescriptorReader` for random access reads from file descriptor. Output written via `fs.writeSync` with positional writes. Works for files of any size (limited only by disk space). Handles NCZ, XCZ, and NSZ formats.

2. **XCZ browser path: streaming write support** — Stream-decompresses with `writeChunk` in pass 2. Uses File System Access API for large XCZ→XCI conversion. Memory path preserved as fallback.

3. **NSZ→NSP streaming decompression for large files** — Replaced the >1.5 GB guard with `zstddec.decodeStreaming()`. Reads compressed data in sub-2GB chunks, per-section AES-CTR decryption during streaming.

4. **XCZ input refactored** — `XCIReader` now uses `DataReader`, only reads 0x200-byte header + HFS0 header. `HFS0Reader` handles sliced `Uint8Array` correctly.

5. **DataReader abstraction** — `BufferReader`, `ChunkedBufferReader`, `FileSliceReader`, `FileDescriptorReader` for pluggable random-access reading.

6. **Native AES-CTR acceleration** — Node.js uses `crypto.createCipheriv('aes-128-ctr')` (OpenSSL/AES-NI), browser uses `crypto.subtle.encrypt('AES-CTR')` (Web Crypto API). ~2.3x speedup in browser (3min → 1m17s for 5GB NSZ). Dropped `aes-js` dependency entirely — no more pure-JS AES. Removed `AESCTR_BKTR` (dead code) and stale `node/crypto/` directory. Removed static `aes-js.js` from HTML.

7. **Removed compressed NCZ memory cache** — No longer caches 2GB+ compressed NCZ data in RAM. Pass 2 reads directly from the dropped File via `FileSliceReader`. Zero speed impact, eliminates peak memory bottleneck.

## ✅ Working Components

1. **PFS0 Container Parsing**
   - Reads uint32 at offset 4 (fileCount) and offset 8 (strTableSize)
   - Correctly parses 7 files from NSZ container

2. **PFS0 Writer**
   - Writes proper header structure with file entries and string table

3. **NCZ Discovery**
   - Finds NCZSECTION magic at offset 0x41D0 (16848)
   - Correctly parses 3 sections from section table

4. **zstd Decompression**
   - Uses zstddec WASM library for all decompression (browser and Node.js block)
   - Node.js streaming uses system `zstd` CLI via spawn piping
   - Successfully decompresses files of any size

5. **Section Handling**
   - Correctly calculates NCA size (0x4000 + sections)
   - Handles cryptoType: 1 (none), 3 (CTR), 4 (BKTR)

6. **AES-CTR Encryption**
   - Counter block: nonce[0:8] + BE64(blockIndex) matching PyCryptodome
   - Node.js: `crypto.createCipheriv('aes-128-ctr')` (OpenSSL/AES-NI)
   - Browser: `crypto.subtle.encrypt('AES-CTR')` (Web Crypto API)
   - Hardware-accelerated, ~2.3x faster than pure-JS aes-js

## ✅ Recent Fixes (2026-04-29)

1. **Fixed AESCTR class**
   - Was XORing data directly with key/nonce (wrong)
   - Now properly encrypts counter block with AES-ECB using aes-js
   - Counter format: nonce[0:8] + BE64(blockIndex) - matches Python PyCryptodome

2. **Fixed AESCTR_BKTR class** (since removed — dead code, BKTR uses AESCTR)

3. **Fixed decryptSection in ncz.js**
   - Removed double addition of UNCOMPRESSABLE_HEADER_SIZE
   - Removed `&& this.keys` condition that was blocking decryption
   - Now properly calls AESCTR/AESCTR_BKTR with correct offset

4. **Added aes-js library** (since removed — replaced by native crypto)

## ✅ Recent Fixes (2026-05-08)

5. **Fixed streaming decompression HACK in ncz.js**
   - Removed wrong pre-decryption of compressed data before zstd decompression
   - Correct order is now: zstd decompress → AES-CTR decrypt per section (matching Python nsz)
   - Fixed `ncaSize` scope bug (was undefined in sub-methods, would cause ReferenceError in progress callback)

6. **Improved zstd error handling in crypto/zstd.js**
   - Throws errors instead of silently returning empty Uint8Array
   - Uses console.error for error logging
   - Checks for empty decompressor output

7. **Rewrote nsz-cli.js (Node.js CLI)**
   - Now uses proper project modules (NCZDecompressor, PFS0Reader, KeysParser, sha256)
   - Supports optional keys file as third argument
   - No longer downloads fzstd from CDN at runtime
   - Proper PFS0 writing with correct 64-bit offsets

8. **Added NCA file type detection in ncz.js**
   - Detects NCA files (no NCZSECTN magic) and returns them as-is

9. **Fixed test-ncz.mjs test**
   - Was passing entire NSZ file to NCZDecompressor instead of sliced NCZ data

## ✅ Recent Fixes (2026-05-08, continued)

10. **Fixed fzstd decompression bug — 6-byte NCA SHA256 mismatch**
     - Root cause: fzstd (pure JS) produces 6 incorrect bytes at one location when decompressing large zstd streams (~600MB compressed, 1.6GB decompressed)
     - Fix: Node.js streaming decompression uses `zstd` CLI via `child_process`; browser uses zstddec WASM
     - Verification: Output NCA SHA256 matches working NSP reference byte-for-byte

11. **Node.js zstd CLI improvement: temp files → stdin/stdout piping**
     - Replaced `execSync` with temp files → `spawn('zstd', ['-d', '--no-check'])` with stdin/stdout pipes

12. **ncz.js code cleanup**
     - Removed dead classes and unused utility functions
     - Unified section decryption loop for both Node.js and browser paths

## ✅ Recent Changes (2026-05-08, continued)

15. **Dropped fzstd dependency entirely**
     - Replaced fzstd with zstddec WASM in all decompression paths (crypto/zstd.js, node/crypto/zstd.js, node/fs/ncz.js)
     - Removed `static/fzstd.mjs` and fzstd from `package.json`
     - All zstd decompression now uses a single library: zstddec (WASM-based, handles any window size)
     - Node.js streaming still uses system `zstd` CLI via spawn for performance
     - See `BROWSER-ZSTD-LIMITATION.md` for rationale

16. **Added .nspz/.nsx format support**
     - Browser UI and CLI now accept .nspz, .nsx files (same format as .nsz)
     - Updated accept filters, extension detection, and output naming

17. **Added standalone .ncz file support**
     - Browser: drop .ncz files → decompressed to .nca
      - CLI: `node nsz-cli.js game.ncz` → outputs game.nca
     - NCZDecompressor already detected standalone NCZ (NCZSECTN at offset 0); just needed UI/CLI routing

18. **Added XCZ decompression**
     - New `HFS0Writer` class in `xci.js` for building HFS0 partitions
     - Browser: drop .xcz files → decompressed to .xci
      - CLI: `node nsz-cli.js game.xcz` → outputs game.xci
     - Parses XCI secure partition, decompresses NCZ files inside, rebuilds HFS0

19. **Removed dead code**
     - Removed `getZstdWindowSize()` from `ncz.js` (no longer needed with zstddec)
     - Removed orphaned `decompressor.js` (not imported anywhere)

20. **Cleaned up test files**
     - Replaced hardcoded paths in `test_ticket_keys.mjs` and `test_decompress.mjs` with CLI args

## ⚠️ Known Limitations

1. **Memory download path (no File System Access API)**: Falls back to `Blob` download — builds full output in memory, fails for games >2 GB. Use browser with File System Access API (Chrome/Edge) for large files.

## ✅ Verified

- **Full end-to-end NSZ→NSP conversion** tested with `Little Nightmares II` (1.56 GB update NSZ)
- **All NCA data byte-identical** to Python nsz reference output
- **AES-CTR implementation** verified against Node.js native `crypto.createCipheriv('aes-128-ctr')` — both are correct
- **zstd CLI piping + Node.js native AES-CTR** confirmed to produce byte-identical output to the reference
- **PFS0 header padding**: Default uses 16-byte alignment (matching Python nsz). `--fix-padding` uses Python's `align0x20` (32-byte alignment, minimum 0x20 padding). All file data is identical between modes. Default mode output is byte-identical to Python nsz.
- **XCZ output is a proper nested XCI** — root HFS0 at `0xF000` with partition entries, each partition a nested HFS0 with `0x8000` header padding. Structure matches Python nsz output.

