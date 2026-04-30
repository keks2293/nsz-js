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

## ❌ Remaining Issues

None identified in code. Need to test in browser to verify the fix works with real NSZ file.

## Files Modified
- `/browser/crypto/aesctr.js` - Complete rewrite to use aes-js, correct counter format
- `/browser/crypto/aes-js.js` - Added aes-js library (803 lines)
- `/browser/index.html` - Added script tag for aes-js
- `/browser/ncz.js` - Fixed decryptSection, removed blocking condition

## Test Files
- Input: `Super Chicken Jumper [01001DC018566000][v0] (0.05 GB).nsz`
- Reference: `Super Chicken Jumper [01001DC018566000][v0] (0.05 GB).nsp`
- Expected SHA256: `b46dffff5d030f22bb7cfd1e28459ab6fca52145f187b332e8a09e20279e7511`

## Next Steps
1. **Test in browser** - Open browser/index.html with NSZ file
2. **Compare SHA256** of output with expected hash
3. **If mismatch** - Debug offset calculation or counter format
4. **Success** - Celebrate! 🎉
