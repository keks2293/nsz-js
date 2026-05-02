# NSZ to NSP Converter (JavaScript)

A pure JavaScript implementation for converting Nintendo Switch NSZ (compressed NSP) files to NSP format. Works entirely in the browser.

## Features

- **Pure JavaScript**: No server-side processing required
- **Browser-based**: Works entirely in the browser with File System Access API
- **Zstandard decompression**: Full support for both streaming and block compression
- **NCA encryption**: Supports CTR, XTS, and BKTR encryption modes
- **Integrity verification**: Validates NCA file hashes against CNMT records
- **Large file support**: Streaming decompression for files up to 8GB+
- **Batch processing**: Process multiple NSZ files at once
- **Key management**: Automatic key derivation from prod.keys

## Usage

### Browser Version

1. Open `index.html` in a modern web browser
2. Drag and drop NSZ files or click to select
3. (Optional) Load default keys or paste your own prod.keys
4. Click "Convert to NSP" to decompress

## Architecture

```
nsz-js/
├── index.html          # Main browser UI
├── main.js             # Browser UI logic and event handling
├── converter.js        # Main NSZ to NSP conversion orchestrator
├── ncz.js              # NCZ decompression (NCZSECTN format)
├── pfs0.js             # PFS0 container parsing and writing
├── keys.js             # Browser key parsing and derivation
├── ticket.js           # Ticket, CNMT, NCA header parsing
├── xci.js              # XCI (game card) container support
├── crypto/             # Cryptographic utilities
│   ├── aes-js.js      # AES implementation (ECB, CBC modes)
│   ├── aes128.js      # AES-128 ECB/CBC implementation
│   ├── aesctr.js      # AES CTR and BKTR mode encryption
│   ├── aesxts.js      # AES XTS mode encryption
│   ├── sha256.js      # SHA-256 hash function
│   └── zstd.js        # Zstandard decompression (uses fzstd)
├── test_convert.js     # Conversion test script
├── test_aes_manual.js # Manual AES test
├── test_aes_ctr.py     # Python AES-CTR test
├── counter-test.js     # Counter mode test
├── test_aes_simple.html    # Simple AES browser test
├── test_ctr.html      # CTR mode browser test
├── test_ctr_browser.html   # CTR browser test UI
├── test_final.html    # Final integration test
├── nsz-convert.js     # Reference NSZ converter (WIP)
├── nsz-convert-ref.py # Python reference implementation
├── PLAN.md            # Project plan
└── PROGRESS.md        # Progress tracking
```

## File Descriptions

### Browser Files

- **index.html** - Main web UI with drag-and-drop support, progress bar, and log display
- **main.js** - UI controller handling file selection, drag-drop, conversion triggers, and progress updates
- **converter.js** - Core converter class `NSZConverter` that orchestrates NCZ decompression, PFS0 rebuilding, and hash verification
- **ncz.js** - `NCZDecompressor` class for decompressing NCZ files with support for section-based, block-based (NCZBLOCK), and streaming compression
- **pfs0.js** - `PFS0Reader` and `PFS0Writer` classes for parsing and building PFS0 containers
- **keys.js** - `KeysParser` class for parsing prod.keys files and deriving title KEKs and key area keys
- **ticket.js** - Classes for parsing Ticket, CNMT (Content Metadata), NCA headers, and BKTR structures. Also exports `sha256`
- **xci.js** - `XCIReader` and `HFS0Reader` for reading XCI game card images

### Crypto Files

- **crypto/aes-js.js** - Full AES implementation from aes-js library (ECB, CBC, CTR modes)
- **crypto/aes128.js** - Lightweight AES-128 implementation with ECB and CBC modes
- **crypto/aesctr.js** - AES-CTR and AES-CTR-BKTR encryption/decryption
- **crypto/aesxts.js** - AES-XTS mode for NCA section decryption
- **crypto/sha256.js** - Pure JavaScript SHA-256 implementation
- **crypto/zstd.js** - Zstandard decompression using fzstd library (loaded from CDN)

### Test Files

- **test_convert.js** - Tests the NSZ to NSP conversion process
- **test_aes_manual.js** - Manual AES encryption/decryption tests
- **test_aes_ctr.py** - Python script for AES-CTR verification
- **counter-test.js** - Tests counter mode operations
- **test_aes_simple.html** - Simple AES test page for browser
- **test_ctr.html** - CTR mode test page
- **test_ctr_browser.html** - Browser-based CTR test with UI
- **test_final.html** - Final integration test page

## File Format Support

- **Input**: `.nsz` (compressed NSP container)
- **Output**: `.nsp` (uncompressed NSP container)
- **Internal**: `.ncz` (compressed NCA files with NCZSECTN header)

## Compression Types

1. **Section-based compression**: Each NCA section compressed separately
2. **Block compression (NCZBLOCK)**: Files split into compressed blocks for random access
3. **Streaming compression**: Traditional zstd streaming decompression

## NCA Encryption Types

- **Type 1 (CRYPTO_NONE)**: No encryption
- **Type 2 (CRYPTO_XTS)**: AES-XTS mode
- **Type 3 (CRYPTO_CTR)**: AES-CTR mode
- **Type 4 (CRYPTO_BKTR)**: AES-CTR with BKTR relocation tables
- **Type 0x3041434E (CRYPTO_NCA0)**: Legacy NCA0 format (no crypto)

## Key Derivation

The implementation includes full key derivation from prod.keys:
- Master key generation from key sources
- Title KEK derivation using master keys
- Key area key generation (application, ocean, system)
- AES wrapped title key unwrapping

## Requirements

### Browser
- Modern browser with ES6+ module support
- File System Access API (for direct file writing)
- Web Crypto API support
