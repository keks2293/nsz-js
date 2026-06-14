# NCZ Decompression & PFS0 Writing Fixes

## ✅ Completed Fixes

All four fixes in this document were completed in commit `dac31b6` ("Wire up progress callbacks in browser NCZ decompressor and fix PFS0 writing").

1. **Progress callback in `_decompressBuffered`** ✅ — Done in `ncz.js`
2. **Progress callback in `_decompressWithBlocks`** ✅ — Done in `ncz.js`  
3. **Redundant `setUint32`** ✅ — `converter.js` already correct (no duplicate)
4. **Progress updates in `buildPFS0Memory`** ✅ — Done in `converter.js`

## New Fixes Applied (2026-05-08)

### A. Wrong streaming decompression HACK removed from `ncz.js`
- Was decrypting compressed data BEFORE zstd decompression (wrong order)
- Correct order (matching Python nsz): decompress first → then decrypt per section
- Also fixed `ncaSize` scope bug (was undefined in progress callback)

### B. NCA file type detection
- Added check in `getSections()`: if data starts with non-NCZ magic (e.g., uncompressed NCA), return empty sections for pass-through

### C. `crypto/zstd.js` error handling improved
- Throws on failure instead of returning empty Uint8Array
- Uses `console.error` instead of `console.log`
- Checks for empty decompressor output

### D. `nsz-cli.js` rewritten
- No longer downloads fzstd from CDN at runtime
- Uses proper project modules (NCZDecompressor, PFS0Reader, KeysParser, sha256)
- Supports optional keys file as third argument
- Proper PFS0 file entry writing with correct 64-bit offsets

### E. `test-ncz.mjs` test bug fixed
- Was passing entire NSZ file to NCZDecompressor instead of sliced NCZ data
