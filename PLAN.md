# NSZ to NSP Converter - Historical Plan

This document is kept for historical reference only. All tasks have been completed.

## ✅ Completed: AES-CTR Decryption Fix

The original goal was to implement correct AES-CTR decryption for NCZ sections so that the output NSP matches the Python nsz reference. This was achieved:

1. **AES-CTR counter format** — Matches PyCryptodome: `Counter.new(64, prefix=nonce[0:8], initial_value=blockIndex)`
2. **Counter block** — `nonce[0:8] + BE64(blockIndex)`
3. **AES-CTR encryption** — Uses native crypto: `crypto.createCipheriv` (Node.js) or `crypto.subtle.encrypt` (browser)

## Current Status

The project now supports:
- **Input formats**: `.nsz`, `.ncz`, `.xcz`
- **Output formats**: `.nsp`, `.nca`, `.xci`
- **Compression**: zstd streaming and NCZBLOCK block
- **Crypto**: AES-CTR (types 3, 4/BKTR), AES-XTS, key derivation from prod.keys
- **Decompression**: zstddec WASM (browser), zstd CLI (Node.js streaming)
- **Verification**: SHA256 hash matching, CNMT hash extraction

See `CHANGELOG.md` for the full status report.
