# NSZ to NSP Converter (JavaScript)

A pure JavaScript implementation for converting Nintendo Switch NSZ (compressed NSP) files to NSP format. Works entirely in the browser or Node.js.

## Features

- **Pure JavaScript**: No server-side processing required
- **Browser-based**: Works entirely in the browser with File System Access API
- **Zstandard decompression**: Full support for both streaming and block compression
- **NCA encryption**: Supports CTR and BKTR encryption modes
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

### Node.js Version

```bash
node nsz-cli.js <input> [output] [keys.txt] [-p]
```

## Architecture

```
nsz-js/
├── index.html          # Main browser UI
├── main.js             # Browser UI logic and event handling
├── converter.js        # Main NSZ to NSP conversion orchestrator
├── nsz-cli.js          # Node.js CLI entry point
├── keys.js             # Browser key parsing and derivation
├── fs/                 # File format modules (mirrors Python nsz Fs/)
│   ├── pfs0.js         # PFS0 container parsing and writing
│   ├── ncz.js          # NCZ decompression + DataReader abstractions
│   ├── xci.js          # XCI/HFS0 container support
│   └── ticket.js       # Ticket, CNMT, NCA header parsing
├── crypto/             # Cryptographic utilities
│   ├── aes128.js       # AES-128 ECB/CBC implementation
│   ├── aesctr.mjs      # AES-CTR mode (Node.js native crypto / Web Crypto API)
│   ├── sha256.js       # SHA-256 hash function
│   ├── unified.js      # Unified crypto wrapper (Node.js / pure JS)
│   └── zstd.js         # Zstandard decompression (uses zstddec WASM)
├── static/             # Static dependencies for browser (offline use)
│   ├── zstddec.mjs     # WASM-based zstd decompression
│   └── prod.keys       # Nintendo Switch keys file
├── test_*.mjs          # Test suites
├── test_*.{cjs,py,html}# Additional tests
├── nsz-convert-ref.py  # Python reference implementation
├── .md files           # Documentation
```

## File Descriptions

### Browser Files

- **index.html** - Main web UI with drag-and-drop support, progress bar, and log display
- **main.js** - UI controller handling file selection, drag-drop, conversion triggers, and progress updates
- **converter.js** - Core converter class `NSZConverter` that orchestrates NCZ decompression, PFS0 rebuilding, and hash verification
- **fs/pfs0.js** - `PFS0Reader` and `PFS0Writer` classes for parsing and building PFS0 containers
- **fs/ncz.js** - `NCZDecompressor` class for decompressing NCZ files with section-based, block-based (NCZBLOCK), and streaming compression. Contains DataReader hierarchy (`DataReader`, `FileDescriptorReader`, `BufferReader`, `FileSliceReader`, `ChunkedBufferReader`)
- **fs/xci.js** - `XCIReader`, `XCIWriter`, `HFS0Reader`, and `HFS0Writer` for XCI/HFS0 container support
- **fs/ticket.js** - Classes for parsing Ticket, CNMT (Content Metadata), NCA headers, and BKTR structures
- **keys.js** - `KeysParser` class for parsing prod.keys files and deriving title KEKs and key area keys

### Crypto Files

- **crypto/aes128.js** - Lightweight AES-128 implementation with ECB and CBC modes
- **crypto/aesctr.mjs** - AES-CTR encryption/decryption (Node.js native `crypto.createCipheriv` or browser Web Crypto API)
- **crypto/sha256.js** - Pure JavaScript SHA-256 implementation
- **crypto/unified.js** - Unified crypto wrapper (provides sha256, crc32 for both Node.js and browser)
- **crypto/zstd.js** - Zstandard decompression using zstddec WASM library

### Dependencies

**Browser (served from `static/` folder):**
- **zstddec** ([GitHub](https://github.com/StadiA/zstddec), [npm](https://www.npmjs.com/package/zstddec)) - WASM-based zstd decompression. Handles any window size. Served from `static/zstddec.mjs`.

### Static Folder

The `static/` folder contains downloaded copies of browser dependencies for offline use and to avoid CDN issues:

| File | Package | Version | Source |
|------|---------|---------|--------|
| `static/zstddec.mjs` | zstddec | 0.2.0 | Copied from `node_modules/zstddec/dist/zstddec-stream.modern.js` |
| `static/prod.keys` | - | - | Nintendo Switch keys file (user-provided) |

AES-CTR uses native crypto — Node.js `crypto.createCipheriv` or browser Web Crypto API. No external AES library needed.

To update dependencies: `npm install zstddec@x.x.x` then copy files to `static/`

### Test Files

- **test_vector.mjs** - AES-CTR keystream test vector verification (self-contained)
- **test_aesctr.mjs** - AES-CTR seek + encrypt test (self-contained)
- **test_aes_manual.cjs** - Standalone AES-CTR test using Node.js crypto (self-contained)
- **test-ncz.mjs** - NCZ decompressor component tests (file-dependent tests skip gracefully)
- **test_convert.mjs** - Full NSZ→NSP conversion pipeline (requires NSZ file)
- **test_decompress.mjs** - Byte-level decompression comparison against reference NSP
- **test_ticket_keys.mjs** - Ticket key and section analysis tool
- **test_aes_ctr.py** - Python reference script for AES-CTR verification
- **test_browser.html** - AES-CTR keystream test for browser (open in browser)

## File Format Support

| Input | Output | Description |
|-------|--------|-------------|
| `.nsz` | `.nsp` | Compressed NSP container |
| `.ncz` | `.nca` | Standalone compressed NCA file |
| `.xcz` | `.xci` | Compressed XCI (game card) image |

### Internal formats

- `.ncz` (compressed NCA files with NCZSECTN header)

## Compression Types

1. **Section-based compression**: Each NCA section compressed separately
2. **Block compression (NCZBLOCK)**: Files split into compressed blocks for random access
3. **Streaming compression**: Traditional zstd streaming decompression

## NCA Encryption Types

- **Type 1 (CRYPTO_NONE)**: No encryption
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

### Node.js
- Node.js 14+ with ES module support
- `zstd` CLI binary in PATH (for streaming decompression) or falls back to zstddec WASM
