# NSZ to NSP Converter - Status Report

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
   - Uses fzstd library from CDN
   - Successfully decompresses ~40MB to ~55MB

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
     - Fix: Added `PreDecompressedReader` class for serving pre-decompressed data; in Node.js, streaming decompression now uses `zstd` CLI tool via `child_process` instead of fzstd
     - Browser fallback: retains fzstd streaming for browser usage
     - Verification: Output NCA SHA256 (`a7c01cd...`) now matches working NSP reference byte-for-byte across all files

## ✅ Recent Improvements (2026-05-08)

11. **Browser zstd decompression cleanup**
     - Removed `DecompressionStream` API (not supported in any browser for 'zstd' format)
     - Removed `StreamingZstdReader` and `PreDecompressedReader` classes
     - Node.js path writes zstd CLI output directly to NCA output buffer
     - Both paths share same section loop (reads from output, decrypts AES-CTR in-place)

12. **Node.js zstd CLI improvement: temp files → stdin/stdout piping**
     - Replaced `execSync` with temp files → `spawn('zstd', ['-d', '--no-check'])` with stdin/stdout pipes
     - No more disk I/O for temp files; faster, cleaner, avoids race conditions

13. **Zstd window size detection (ncz.js)**
     - Added `getZstdWindowSize()` function that parses the zstd frame header to detect Window_Descriptor window size
     - Browser path checks window size before decompression: throws immediately if >32MB
     - Prevents silent 6-byte NCA corruption from fzstd's 32MB backreference limit
     - Small NSZ files (window ≤ 32MB) work in browser; large files get clear error message

14. **ncz.js code cleanup**
     - Removed `CompressionStreamZstdReader`, `StreamingZstdReader`, `PreDecompressedReader` classes
     - Removed unused utility wrapper functions
     - Unified section decryption loop for both Node.js and browser paths

## ✅ Verified

- **Full end-to-end NSZ→NSP conversion** tested with `Little Nightmares II` (1.56 GB update NSZ)
- **All NCA data byte-identical** to Python nsz reference output
- **AES-CTR implementation** verified against Node.js native `crypto.createCipheriv('aes-128-ctr')` — both are correct
- **zstd CLI piping + Node.js native AES-CTR** confirmed to produce byte-identical output to the reference
- **Output NSP size difference**: 13 bytes (PFS0 header padding only) — reference pads header to 16-byte alignment; our unpadded header is also valid

## ❌ Remaining Issues

- **Browser zstd decompression**: `DecompressionStream('zstd')` not supported in any browser. Uses non-streaming fzstd (`ZstdDecompressor.decompress()`) for all browsers — the 6-byte corruption bug may appear for large files (>32 MB window). Block decompression (NCZBLOCK) uses fzstd with smaller data chunks, which should work correctly.
- PFS0 header padding: reference NSP pads header to 16-byte alignment (528 bytes), ours does not (515 bytes). All file data is identical.
- Tests `test_crypto_key.mjs` and `test_offset.mjs` have incorrect assumptions about AES-CTR offset calculation (they apply decryption to compressed data and look for zstd magic, which is wrong — decryption happens after decompression)

## Files Modified
- `ncz.js` - Added `CompressionStreamZstdReader`, `getFzstd()`, rewritten `StreamingZstdReader`, Node.js path uses spawn piping, NCA detection, ncaSize fix
- `crypto/zstd.js` - Better error handling
- `nsz-convert.js` - Complete rewrite
- `PROGRESS.md` - This update
- `test-ncz.mjs` - Fixed NCZ data slicing
- `AGENTS.md` - Added instructions for AI agents

## Test Files
- Input: `Little Nightmares II [010097100EDD6800][v262144] (1.56 GB).nsz`
- Reference: `Little Nightmares II [010097100EDD6800][v262144] (1.56 GB) working.nsp`
- **All NCA DATA BYTE-IDENTICAL** (only PFS0 header padding differs by 13 bytes)

## Next Steps
1. **Test in browser** - Open index.html with NSZ file in Chrome 120+ (uses CompressionStream) or other browsers (fzstd fallback for small files)
2. **PFS0 header padding** - Could add optional 16-byte alignment padding to match Python nsz exactly
3. **Test other NSZ variants** - Different crypto types (BKTR), block compression (NCZBLOCK), multi-NCZ files
4. **Add PFS0 header padding** to match reference output (528 vs 515 byte headers)
