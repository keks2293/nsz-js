# NSZ to NSP Converter - Status Report

## ✅ Recent Changes (2026-05-09)

1. **Node.js CLI rewritten for large files** — No more `fs.readFileSync`. Uses `FileDescriptorReader` for random access reads from file descriptor. Output written via `fs.writeSync` with positional writes. Works for files of any size (limited only by disk space). Handles NCZ, XCZ, and NSZ formats.

2. **XCZ browser path: streaming write support** — Caches compressed NCZ chunks in pass 1, stream-decompresses with `writeChunk` in pass 2. Uses File System Access API for large XCZ→XCI conversion. Memory path preserved as fallback.

3. **NSZ→NSP streaming decompression for large files** — Replaced the >1.5 GB guard with `zstddec.decodeStreaming()`. Reads compressed data in sub-2GB chunks, per-section AES-CTR decryption during streaming.

4. **XCZ input refactored** — `XCIReader` now uses `DataReader`, only reads 0x200-byte header + HFS0 header. `HFS0Reader` handles sliced `Uint8Array` correctly.

5. **DataReader abstraction** — `BufferReader`, `ChunkedBufferReader`, `FileSliceReader`, `FileDescriptorReader` for pluggable random-access reading.

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

6. **AES-CTR Encryption (Fixed!)**
   - Now uses `aes-js` library for correct AES-ECB encryption
   - Counter block: nonce[0:8] + BE64(blockIndex) matching PyCryptodome
   - Counter.new(64, prefix=nonce[0:8], initial_value=blockIndex)
   - aes-js loaded globally via `<script>` tag before main.js

## ✅ Recent Fixes (2026-04-29)

1. **Fixed AESCTR class**
   - Was XORing data directly with key/nonce (wrong)
   - Now properly encrypts counter block with AES-ECB using aes-js
   - Counter format: nonce[0:8] + BE64(blockIndex) - matches Python PyCryptodome

2. **Fixed AESCTR_BKTR class**
   - Was using wrong logic (XOR with key bytes)
   - Now uses same correct AES-CTR logic as AESCTR

3. **Fixed decryptSection in ncz.js**
   - Removed double addition of UNCOMPRESSABLE_HEADER_SIZE
   - Removed `&& this.keys` condition that was blocking decryption
   - Now properly calls AESCTR/AESCTR_BKTR with correct offset

4. **Added aes-js library**
   - Downloaded from https://github.com/ricmoo/aes-js
   - Added to HTML before main.js as global script
   - Provides proven AES-ECB implementation

## ✅ Recent Fixes (2026-05-08)
- **Progress callbacks wired in the NCZ/PFS0 builders (2026-05-06)** — `NCZDecompressor.decompress()`/`_decompressWithStreaming()`/`_decompressWithBlocks()` accept a `progressCallback`, called with the `decompressedOffset/ncaSize` ratio on every chunk (`ncz.js`); `buildPFS0Memory` reports progress during file copy (`converter.js`). The reported "redundant `setUint32`" in `buildPFS0Stream` was a non-bug — the builder already had no duplicate.

5. **Fixed streaming decompression HACK in ncz.js**
   - Removed wrong pre-decryption of compressed data before zstd decompression
   - Correct order is now: zstd decompress → AES-CTR decrypt per section (matching Python nsz)
   - Fixed `ncaSize` scope bug (was undefined in sub-methods, would cause ReferenceError in progress callback)

6. **Improved zstd error handling in crypto/zstd.js**
   - Throws errors instead of silently returning empty Uint8Array
   - Uses console.error for error logging
   - Checks for empty decompressor output

7. **Rewrote nsz-convert.js (Node.js CLI)**
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


16. **Added standalone .ncz file support**
     - Browser: drop .ncz files → decompressed to .nca
     - CLI: `node nsz-convert.js game.ncz` → outputs game.nca
     - NCZDecompressor already detected standalone NCZ (NCZSECTN at offset 0); just needed UI/CLI routing

17. **Added XCZ decompression**
     - New `HFS0Writer` class in `xci.js` for building HFS0 partitions
     - Browser: drop .xcz files → decompressed to .xci
     - CLI: `node nsz-convert.js game.xcz` → outputs game.xci
     - Parses XCI secure partition, decompresses NCZ files inside, rebuilds HFS0

18. **Removed dead code**
     - Removed `getZstdWindowSize()` from `ncz.js` (no longer needed with zstddec)
     - Removed orphaned `decompressor.js` (not imported anywhere)

19. **Cleaned up test files**
     - Replaced hardcoded paths in `test_ticket_keys.mjs` and `test_decompress.mjs` with CLI args

## ⚠️ Known Limitations

1. **Memory download path (no File System Access API)**: Falls back to `Blob` download — builds full output in memory, fails for games >2 GB. Use browser with File System Access API (Chrome/Edge) for large files.

## ✅ Verified

- **Full end-to-end NSZ→NSP conversion** tested with `Little Nightmares II` (1.56 GB update NSZ)
- **All NCA data byte-identical** to Python nsz reference output
- **AES-CTR implementation** verified against Node.js native `crypto.createCipheriv('aes-128-ctr')` — both are correct
- **zstd CLI piping + Node.js native AES-CTR** confirmed to produce byte-identical output to the reference
- **PFS0 header padding**: `--fix-padding` pads header to 16-byte boundary (528 bytes, matches reference); without it, header is minimal unpadded size (515 bytes). All file data is identical between modes. Use `--fix-padding` or toggle in UI to match Python nsz output size.
- XCZ output is a flat HFS0 partition without full XCI header/metadata — enough for game loading but not a byte-for-byte copy of the original XCI structure.

