# NSZ to NSP Converter (Local)

A **100% local** pure JavaScript converter for Nintendo Switch compressed game files (NSZ/NCZ/XCZ). Everything runs on your machine — no uploads, no servers, no cloud.

## Features

- **Pure JavaScript**: No server-side processing required
- **Browser-based**: Works entirely in the browser with File System Access API
- **Node.js CLI**: Command-line tool for batch processing
- **Zstandard decompression**: Full support for both streaming and block compression
- **NCA encryption**: Supports CTR and BKTR encryption modes
- **Integrity verification**: Validates NCA file hashes against CNMT records (per-partition for XCZ)
- **Python nsz compatible**: Output matches Python nsz byte-for-byte
- **Large file support**: Streaming decompression for files up to 8GB+
- **Batch processing**: Process multiple NSZ files at once
- **Key management**: Automatic key derivation from prod.keys
- **Error safety**: Deletes partial output on conversion failure (CLI)

## Usage

### Browser Version

1. Open `index.html` in a modern web browser
2. Drag and drop NSZ files or click to select
3. (Optional) Load default keys or paste your own prod.keys
4. Click "Convert" to decompress

### Node.js Version

```bash
node nsz-cli.js <input> [output] [keys.txt] [options]
```

Options:
- `-o, --output <dir>` - Output directory
- `-w, --overwrite` - Overwrite existing output files
- `--rm-source` - Delete input file after successful conversion
- `--keys <path>` - Path to prod.keys file
- `--no-verify, -nv` - Skip SHA256 verification (faster)
- `--fix-padding, -p` - Use 0x20-byte alignment (default: 16-byte)
- `-h, --help` - Show usage information

## Python nsz Compatibility

Output is byte-identical to Python nsz for default mode. Verified against Python nsz 4.6.1.

### Verification behavior

- **NSZ**: NCA hashes verified against CNMT records from top-level PFS0
- **XCZ**: NCA hashes verified against per-partition CNMT records (all partitions)
- **Standalone NCZ**: Filename fallback verification (`hash[:32] === filename`)
- Logs: `[VERIFIED]`, `[CORRUPTED]`, `[MISSMATCH]`, `[EXISTS]`

### Matching Python nsz

- PFS0 header padding (16-byte default, 0x20 with `--fix-padding`)
- HFS0 offset convention (matches hactool)
- Block size validation (14-32 exponent range)
- Error handling (partial output cleanup on failure)

## Architecture

```
nsz-js/
├── index.html              # Main browser UI
├── main.js                 # Browser UI logic and event handling
├── converter.js            # Main NSZ to NSP conversion orchestrator
├── nsz-cli.js              # Node.js CLI entry point
├── keys.js                 # Browser key parsing and derivation
├── download-worker.js      # Service Worker for streaming downloads
├── build.js                # esbuild bundler script (app.mjs + asset copy)
├── fs/                     # File format modules (mirrors Python nsz Fs/)
│   ├── pfs0.js             # PFS0 container parsing and writing
│   ├── ncz.js              # NCZ decompression, DataReader hierarchy, AsyncBlockDecompressorReader
│   ├── nsz-convert.js      # NSZ→NSP streaming/memory conversion (adapter pattern)
│   ├── xcz-convert.js      # XCZ→XCI streaming conversion (adapter pattern)
│   ├── xci.js              # XCI/HFS0 container support (XCIReader)
│   ├── hfs0.js             # HFS0 container parsing and writing
│   ├── ticket.js           # Ticket parsing
│   ├── cnmt.js             # CNMT (Content Metadata) parsing
│   └── nca.js              # NCA header parsing
├── crypto/                 # Cryptographic utilities
│   ├── aes128.js           # AES-128 ECB/CBC implementation
│   ├── aesctr.mjs          # AES-CTR mode (Node.js native crypto / Web Crypto API)
│   ├── aesxts.mjs          # AES-XTS mode (NCA header key area decryption)
│   ├── sha256.js           # SHA-256 hash function
│   ├── zstd.js             # Zstandard decompression (uses zstddec WASM)
│   └── zstddec-stream-wrapper.js  # WASM streaming decompression wrapper
├── static/                 # Static dependencies for browser (offline use)
│   ├── zstddec.mjs         # WASM-based zstd decompression
│   └── prod.keys           # Nintendo Switch keys file
├── test_*.mjs              # Test suites
├── test_browser.html       # Browser tests
├── nsz-convert-ref.py      # Python reference implementation
├── .md files               # Documentation
```

## File Descriptions

### Browser Files

- **index.html** - Main web UI with drag-and-drop support, progress bar, and log display
- **main.js** - UI controller handling file selection, drag-drop, conversion triggers, and progress updates
- **converter.js** - Core converter class `NSZConverter` that orchestrates NCZ decompression, PFS0 rebuilding, and hash verification
- **fs/pfs0.js** - `PFS0Reader` and `PFS0Writer` classes for parsing and building PFS0 containers
- **fs/ncz.js** - `NCZDecompressor` class for decompressing NCZ files with section-based, block-based (NCZBLOCK), and streaming compression. Contains DataReader hierarchy (`DataReader`, `BufferReader`) and `AsyncBlockDecompressorReader`
- **fs/xci.js** - `XCIReader` for XCI container support
- **fs/hfs0.js** - `HFS0Reader` and `HFS0Writer` for HFS0 container support
- **fs/ticket.js** - `Ticket` class for parsing ticket files
- **fs/cnmt.js** - `Cnmt` and `ContentEntry` classes for parsing Content Metadata
- **fs/nca.js** - `NCAHeader` class for parsing NCA headers
- **keys.js** - `KeysParser` class for parsing prod.keys files and deriving title KEKs and key area keys
- **build.js** - esbuild bundler script, builds `out/app.mjs` and copies runtime assets
- **fs/nsz-convert.js** - NSZ→NSP streaming/memory conversion (adapter pattern, shared with CLI)
- **fs/xcz-convert.js** - XCZ→XCI streaming conversion (adapter pattern, shared with CLI)

### Crypto Files

- **crypto/aes128.js** - Lightweight AES-128 implementation with ECB and CBC modes
- **crypto/aesctr.mjs** - AES-CTR encryption/decryption (Node.js native `crypto.createCipheriv` or browser Web Crypto API)
- **crypto/aesxts.mjs** - AES-XTS encryption/decryption (NCA header key area unwrap)
- **crypto/sha256.js** - Pure JavaScript SHA-256 implementation
- **crypto/zstd.js** - Zstandard decompression using zstddec WASM library

### Dependencies

**Browser (served from `static/` folder):**
- **zstddec** ([GitHub](https://github.com/StadiA/zstddec), [npm](https://www.npmjs.com/package/zstddec)) - WASM-based zstd decompression. Handles any window size. Served from `static/zstddec.mjs`.

### Static Folder

The `static/` folder contains downloaded copies of browser dependencies for offline use and to avoid CDN issues:

| File | Package | Version | Source |
|------|---------|---------|--------|
| `static/zstddec.mjs` | zstddec | 0.2.0 | Copied from `node_modules/zstddec/dist/zstddec-stream.modern.js`. Bundled into `out/app.mjs` by esbuild — no separate HTTP request at runtime. |
| `static/prod.keys` | - | - | Nintendo Switch keys file (user-provided) |

AES-CTR uses native crypto — Node.js `crypto.createCipheriv` or browser Web Crypto API. No external AES library needed.

To update dependencies: `npm install zstddec@x.x.x` then copy files to `static/`

### Test Files

- **test_vector.mjs** - AES-CTR keystream test vector verification (self-contained)
- **test_aesctr.mjs** - AES-CTR seek + encrypt test (self-contained)
- **test_aes_manual.cjs** - Standalone AES-CTR test using Node.js crypto (self-contained)
- **bench_aes.mjs** - AES-CTR throughput benchmark (encrypt/decrypt/seek MB/s)
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

## Implementation Notes

### Decompression architecture

All decompression paths (streaming, memory, block) use a unified `writeChunk` callback pattern:
- **Streaming**: `writeChunk` writes to File System Access API or Service Worker stream
- **Memory**: `collectChunk` wrapper writes to pre-allocated output buffer

### Hash verification

`verifyHash(hash, name, fileHashes, onLog)` is the single verification entry point:
- Standalone function (not a class method — follows `class-methods-use-this`)
- `onLog` passed explicitly for logging success/error
- `.nca` check is at call sites (matching Python nsz structure)
- Throws on mismatch (matching Python nsz `VerificationException`)
