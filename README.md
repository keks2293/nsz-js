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
├── scripts/                 # Comparison, analysis, debugging, and benchmark scripts
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

- **scripts/test_vector.mjs** - AES-CTR keystream test vector verification (self-contained)
- **scripts/test_aesctr.mjs** - AES-CTR seek + encrypt test (self-contained)
- **test_aes_manual.cjs** - Standalone AES-CTR test using Node.js crypto (self-contained)
- **scripts/bench_aes.mjs** - AES-CTR throughput benchmark (encrypt/decrypt/seek MB/s)
- **scripts/test-ncz.mjs** - NCZ decompressor component tests (file-dependent tests skip gracefully)
- **scripts/test_convert.mjs** - Full NSZ→NSP conversion pipeline (requires NSZ file)
- **scripts/test_decompress.mjs** - Byte-level decompression comparison against reference NSP
- **scripts/test_ticket_keys.mjs** - Ticket key and section analysis tool
- **test_aes_ctr.py** - Python reference script for AES-CTR verification
- **test_browser.html** - AES-CTR keystream test for browser (open in browser)

### Scripts Directory (scripts/)

The `scripts/` directory contains 54 comparison, analysis, debugging, and benchmarking scripts used during development and reverse-engineering. All scripts are run via Node.js and require either command-line arguments or predefined file paths.

| Prefix | Category | Description | Key Scripts |
|--------|----------|-------------|-------------|
| `analyze_` | Analysis | Analyze NSP/NSZ structure and crypto | `analyze_yanu3.mjs`, `analyze_romfs.mjs` |
| `bench_` | Benchmarks | Performance testing of crypto and decompression | `bench_aes.mjs`, `bench_aes128.mjs`, `bench_nczblock.mjs`, `bench_real_nsz.mjs` |
| `bktr_` | BKTR Crypto | BKTR encryption probing and verification | `bktr_key_probe3.mjs`, `bktr_full_probe.mjs`, `bktr_layout_probe.mjs`, `bktr_fsheader_probe.mjs`, `bktr_fsheader_compare.mjs`, `bktr_superblock_probe.mjs`, `bktr_sec0_probe.mjs`, `bktr_compare_probe.mjs`, `bktr_compare_merge.mjs`, `bktr_facts_probe.mjs`, `bktr_verify_hashes.mjs`, `bktr_verify_merged.mjs` |
| `check_` | Inspection | Inspect file structure, crypto properties, sizes | `check_cnmt_nca.mjs`, `check_cnmt_sizes.mjs`, `check_ncz.mjs`, `check_new.mjs`, `check_romfs_header.mjs`, `check_romfs_sizes.mjs`, `check_merged_size.mjs` |
| `compare_` | Comparison | Advanced file comparisons | `compare_nsp.mjs`, `compare_with_yanu.mjs`, `compare_program_nca.mjs`, `compare_merged_nca.mjs`, `diff_romfs.mjs` |
| `dbg_` | Debugging | Debugging decompression, streaming, and conversion | `dbg_decomp2.mjs`, `dbg_stream4.mjs` |
| `debug_` | Debugging | CNMT debugging | `debug_cnmt2.mjs` |
| `dump_` | Extraction | Dump and display file contents | `dump_base_cnmt.mjs`, `dump_cnmt.mjs`, `dump_fsheader.mjs` |
| `hexdump_` | Hex Dump | Hexadecimal dumps | `hexdump_cnmt.mjs` |
| `inspect_` | Inspection | Detailed file inspection | `inspect_base_romfs.mjs`, `inspect_entries.mjs`, `inspect_yanu.mjs` |
| `repro_` | Reproduction | Reproduce bugs or specific issues | `repro_stream3.mjs` |
| `test_` | Tests | Component and integration tests | `test-ncz.mjs`, `test_aes128.mjs`, `test_aesctr.mjs`, `test_convert.mjs`, `test_decompress.mjs`, `test_vector.mjs`, `test_ticket_keys.mjs`, `test_merge_ncz.mjs`, `test_update_e2e.mjs` |
| `verify_` | Verification | Verify conversions, hashes, and merged outputs | `verify_update.mjs`, `verify_updated_output.mjs`, `verify_merged_nca.mjs`, `verify_ivfc_output.mjs` |

#### Key Probe Scripts

**Comparison tools:**
- `compare_nsp.mjs <file1.nsp> <file2.nsp>` - Compare PFS0 headers of two NSP files
- `compare_with_yanu.mjs <our.nsp> <yanu.nsp>` - Detailed comparison of our output vs reference
- `compare_program_nca.mjs <our.nsp> <ref.nsp>` - Compare program NCA structure and crypto
- `compare_merged_nca.mjs <merged.nsp> <ref.nsp>` - Compare merged NCA files
- `diff_romfs.mjs <nspA> <nspB> [maxRanges]` - Byte-level diff of the level-5 (RomFS) data region of two Program NCAs (needs `static/prod.keys`)

**BKTR crypto:**
- `bktr_key_probe3.mjs` - Probe BKTR key derivation (final iteration)
- `bktr_layout_probe.mjs` - Analyze BKTR layout
- `bktr_fsheader_probe.mjs` - Probe BKTR FS header
- `bktr_fsheader_compare.mjs` - Compare BKTR FS headers (base/update/yanu)
- `bktr_full_probe.mjs` - Full BKTR analysis
- `bktr_superblock_probe.mjs` - Probe BKTR superblock
- `bktr_sec0_probe.mjs` - Verify section 0 (ExeFS) decryption
- `bktr_compare_probe.mjs` - Compare BKTR probes
- `bktr_compare_merge.mjs` - Compare BKTR in merged files
- `bktr_facts_probe.mjs` - Dump BKTR facts
- `bktr_verify_hashes.mjs` - Verify BKTR hashes
- `bktr_verify_merged.mjs` - Verify BKTR in merged output

**Analysis tools:**
- `analyze_yanu3.mjs [keys] [nsz]` - Extended yanu analysis (final iteration)
- `analyze_romfs.mjs <nsp> [outputJson]` - Analyze level-5 RomFS: header, file table walk, last file, blob area, trailing gap (needs `static/prod.keys`)

**Inspection tools:**
- `check_cnmt_nca.mjs [keys] [nsz]` - Inspect CNMT NCA section crypto
- `inspect_base_romfs.mjs [keys] [base_nsp]` - Inspect base ROMFS
- `inspect_yanu.mjs [keys] [nsz]` - Inspect yanu NSZ structure

**Debugging tools:**
- `dbg_decomp2.mjs` - Debug NCZ decompression (final iteration)
- `dbg_stream4.mjs` - Debug streaming decompression (final iteration)
- `debug_cnmt2.mjs` - Debug CNMT NCA structure

**Benchmarks:**
- `bench_aes.mjs` - AES-CTR benchmark
- `bench_aes128.mjs` - AES-128 benchmark
- `bench_nczblock.mjs` - NCZ block benchmark
- `bench_real_nsz.mjs` - Real NSZ file benchmark

**Verification:**
- `verify_update.mjs` - Verify update conversion
- `verify_updated_output.mjs` - Verify updated NSP output
- `verify_merged_nca.mjs` - Verify merged NCA output
- `verify_ivfc_output.mjs <nsp> [expectedMasterHash]` - Verify the packed Program NCA's IVFC hash tree against the stored update hashes (ALL CHECKS PASS output)

**Tests:**
- `test-ncz.mjs` - NCZ decompressor tests
- `test_convert.mjs` - Conversion tests
- `test_decompress.mjs` - Decompression tests
- `test_merge_ncz.mjs` - NCZ merge tests
- `test_update_e2e.mjs` - Update end-to-end tests

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
