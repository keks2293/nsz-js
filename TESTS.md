# nsz-js Test Suite

## Overview

This document describes the test files available in the nsz-js project for verifying correctness of the implementation against Python nsz reference.

---

## 1. AES-CTR Crypto Tests

### test_aes_ctr.py (Python - Reference)
**Location:** `/test_aes_ctr.py`
**Purpose:** Generate reference AES-CTR keystream using Python PyCryptodome
**What it tests:**
- AES-CTR keystream generation matching Python nsz
- Counter format: `Counter.new(64, prefix=nonce[0:8], initial_value=(offset >> 4))`
- Verifies big-endian encoding of block index in counter bytes 8-15

**How to run:**
```bash
python3 test_aes_ctr.py
```

**Expected output:** Keystream hex string starting with `e95fed2b7d0afca982d145a0ddea1c84...`

---

### test_vector.mjs (Node.js)
**Location:** `/test_vector.mjs`
**Purpose:** AES-CTR test vector verification matching Python nsz
**What it tests:**
- AES-CTR keystream matches Python output
- Counter block construction (nonce[0:8] + BE64 blockIndex)
- Native AES-CTR encrypt/decrypt (Node.js `crypto.createCipheriv` or browser Web Crypto API)

**How to run:**
```bash
node test_vector.mjs
```

**Expected output:**
```
Result: ✅ PASS
```

---

### test_aesctr.mjs (Node.js)
**Location:** `/test_aesctr.mjs`
**Purpose:** AES-CTR with explicit seek and encrypt
**What it tests:**
- AES-CTR seek to specific offset
- Encrypt known plaintext and compare with expected output

**How to run:**
```bash
node test_aesctr.mjs
```

**Expected output:** Shows encrypted zstd magic matching `874786d3`

---

### test_aes_manual.cjs (Node.js - Manual)
**Location:** `/test_aes_manual.cjs`
**Purpose:** Standalone AES-CTR test with no dependencies
**What it tests:**
- Manual AES-CTR implementation using Node.js crypto
- Counter construction without external libraries

**How to run:**
```bash
node test_aes_manual.cjs
```

---

### bench_aes.mjs (Node.js - Benchmark)
**Location:** `/bench_aes.mjs`
**Purpose:** AES-CTR throughput benchmark
**What it measures:**
- Encrypt throughput (MB/s) for large contiguous data
- Decrypt throughput (MB/s) for large contiguous data
- Seek+decrypt throughput (simulates per-section NCZ decrypt pattern)

**How to run:**
```bash
node bench_aes.mjs
```

**Output:**
```
AES-CTR encrypt 500MB: 456ms (1096 MB/s)
AES-CTR decrypt 500MB: 462ms (1082 MB/s)
AES-CTR seek+decrypt 500MB (500 seeks): 481ms (1039 MB/s)
```

---

## 2. Browser-based AES-CTR Tests

### test_browser.html
**Location:** `/test_browser.html`
**Purpose:** AES-CTR keystream verification in browser
**What it tests:**
- AES-CTR with PyCryptodome-compatible counter
- Uses `crypto.subtle.encrypt` (Web Crypto API, hardware-accelerated)

**How to run:** Open in browser

---

## 3. Conversion & Analysis Tests

### test_convert.mjs (Node.js)
**Location:** `/test_convert.mjs`
**Purpose:** Full NSZ to NSP conversion pipeline
**What it tests:**
- PFS0 parsing
- NCZ decompression with AES-CTR
- SHA256 hashing of output

**How to run:**
```bash
node test_convert.mjs path/to/file.nsz
```

**Prerequisites:**
- Requires NSZ file input

---

### test_decompress.mjs (Node.js)
**Location:** `/test_decompress.mjs`
**Purpose:** Compare decompressed output against reference NSP
**What it tests:**
- NCZ decompression
- Byte-by-byte comparison with working NSP
- SHA256 hash comparison

**How to run:**
```bash
node test_decompress.mjs input.nsz [working.nsp]
```

When `working.nsp` is provided, finds and reports the first mismatching byte.

---

### test_ticket_keys.mjs (Node.js)
**Location:** `/test_ticket_keys.mjs`
**Purpose:** Analyze ticket keys and AES-CTR decryption in NSZ files
**What it tests:**
- NCZSECTN parsing
- Section key/counter extraction
- Ticket (.tik) parsing and comparison
- AES-CTR decryption with various keys (section key, title key, etc.)
- zstd magic detection in decrypted data

**How to run:**
```bash
node test_ticket_keys.mjs input.nsz [working.nsp]
```

Useful for debugging key derivation and verifying section decryption manually.

---

### test-ncz.mjs (Node.js)
**Location:** `/test-ncz.mjs`
**Purpose:** NCZ decompressor component tests
**What it tests:**
- AES-CTR encrypt produces correct bytes
- NCZ section parsing from NSZ container
- Full NCZ decompression vs working NCA (when files available)
- Zstd decompressor error handling

**How to run:**
```bash
node test-ncz.mjs
```

Tests with hardcoded paths skip gracefully when files are not present.

### Merge / Split NSP (Node.js + Browser)

**Purpose:** verify the new NSP merge and split operations (`fs/merge.js`, `fs/split.js`).

**What merge does:** unions the members of 2+ NSPs/NSZs/XCIs/XCZs into one NSP, deduplicating by output filename (first occurrence wins). Compressed `.ncz` members are decompressed to `.nca` on the fly (both streaming-zstd and NCZBLOCK modes; section AES keys come from the NCZ headers, so no keys file needed). XCI/XCZ inputs contribute their secure-partition files (read header-only via `XCIReader.getSecureFiles()`); mixed `base.xci + update.nsp` → `.nsp` works. Output: `<stem of first input>_merged.nsp`.

**What split does:** for each `.cnmt.nca` in the input, decrypts the NCA header (XTS) and the first section (AES-CTR), parses the inner PFS0 → CNMT, groups the referenced NCAs into a per-title NSP, and attaches the matching `.tik`/`.cert` via rights-id lookup. Needs `header_key` + title-key derivation (any `static/prod.keys`). Output: `{titleId}_{base|update|dlc}_v{version}.nsp` per title.

**How to run (CLI):**
```bash
node nsz-cli.js --merge base.nsp update.nsp dlc.nsp -o ./out          # merge NSPs (dedup by name)
node nsz-cli.js --merge base.xci update.nsp -o ./out                  # merge XCI base + NSP update -> NSP
node nsz-cli.js --merge base.nsz update.nsp -o ./out                  # merge NSZ base (decompresses .ncz members) + NSP update
node nsz-cli.js --merge base.xcz dlc.nsp -o ./out                     # merge XCZ base (decompresses .ncz members) + NSP DLC
node nsz-cli.js --split merged.nsp ./static/prod.keys -o ./out        # split per title
node nsz-cli.js --merge a.nsp b.nsp -o ./out --rm-source              # delete sources after
```

**Synthetic component tests** (build valid-PFS0 NSPs and synthetic XCIs; split uses real `static/prod.keys` with generated NCA headers):
- merge: 5 members after dedup, member data copied byte-identically
- merge with XCI input: XCI secure-partition files unioned with NSP files, first-wins dedup across containers, data verified byte-identically (both `[xci, nsp]` and `[nsp, xci]` orders)
- merge with NSZ input (`test_merge_ncz.mjs`, needs `zstd` CLI for generating synthetic fixtures): streaming-zstd and NCZBLOCK `.ncz` members decompressed to `.nca`, bytes verified against expected NCA; plain members copied; `.ncz`/`.nca` same-stem dedup across inputs keeps the first input. On Node the `.ncz` streaming decompression uses in-process `zlib.createZstdDecompress` (no CLI subprocess); verified separately with a 200MB synthetic NCZ (byte-identical, ~144ms)
- split: 1 title group, output has 4 members (meta NCA, program NCA, `.tik`, `.cert`), meta NCA byte-identical to source
- split round-trip: `--split` then `--merge` reproduces the original member set

**Browser:** Mode switcher (Convert / Merge / Split). Merge needs ≥2 `.nsp`/`.nsz`/`.xci`/`.xcz`, Split needs exactly 1 `.nsp`. Works with File System (FSA), Stream (Service Worker), or Blob download modes.

---

## 4. Test Coverage Summary

| Component | Python Ref | Node.js | Browser |
|-----------|-------------|---------|---------|
| AES-CTR keystream | ✅ test_aes_ctr.py | ✅ test_vector.mjs | ✅ test_browser.html |
| Counter format (BE64) | ✅ test_aes_ctr.py | ✅ test_vector.mjs | ✅ test_browser.html |
| AES-CTR seek + encrypt | - | ✅ test_aesctr.mjs | - |
| AES-CTR manual (Node crypto) | - | ✅ test_aes_manual.cjs | - |
| NCZ decompression | - | ✅ test_convert.mjs, test-ncz.mjs | - |
| Byte-level decompress verify | - | ✅ test_decompress.mjs | - |
| PFS0 parsing | - | ✅ test_convert.mjs | - |
| Ticket key analysis | - | ✅ test_ticket_keys.mjs | - |
| AES-CTR + zstd | - | ✅ test_convert.mjs | - |
| NSP/XCI merge (union + dedup, XCI inputs) | ✅ FinalRom merger | ✅ CLI (synthetic NSP + XCI) | ✅ browser/Playwright |
| NSZ/XCZ merge (NCZ decompression to .nca) | - | ✅ test_merge_ncz.mjs (streaming + NCZBLOCK) | ✅ browser/Playwright |
| NSP split (CNMT grouping, per-title NSP) | ✅ FinalRom unmerger | ✅ CLI (synthetic NSP + real keys) | ✅ browser/Playwright |

---

## 5. Key Test Vectors

### AES-CTR Test Vector (from Python nsz)

This test verifies that keystream generation matches Python nsz.

**Inputs:**
- `Key` — encryption key (16 bytes, AES-128)
- `Nonce` — initial counter (16 bytes)
- `Offset` — file position where keystream is needed

**Calculation:**
1. `BlockIdx = Offset >> 4` (divide offset by AES block size = 16 bytes)
2. Build counter block: first 8 bytes = nonce[0:8], last 8 bytes = BlockIdx in big-endian
3. Encrypt counter block with AES-ECB → get keystream block

**Result:**
```
Key:       3c8358e37c54aca5bb20fc36741c1727
Nonce:    00000002000000000000000000000000 (16 bytes)
Offset:    131072 (0x20000)
BlockIdx:  8192 (offset >> 4)

Counter block (BE64): 00000002000000000000000000002000
Expected keystream (48 bytes): e95fed2b7d0afca982d145a0ddea1c84799cd6049be13c145365e02e7c0cd67c7dda265086d308349093deb0c56bd1e5
```

**Run the test:**
```bash
node test_vector.mjs
```

---

## 6. Running All Tests

### Self-contained (no external files needed):
```bash
# AES-CTR test vector (section 5)
node test_vector.mjs

# AES-CTR with seek + encrypt
node test_aesctr.mjs

# AES-CTR manual (uses Node crypto)
node test_aes_manual.cjs

# NCZ component tests (skips file-dependent tests)
node test-ncz.mjs
```

### Require NSZ file input:
```bash
# Full conversion pipeline
node test_convert.mjs path/to/file.nsz

# Decompression comparison against reference NSP
node test_decompress.mjs input.nsz [working.nsp]

# Ticket key and section analysis
node test_ticket_keys.mjs input.nsz [working.nsp]
```

### Browser tests:
Open `test_browser.html` in a browser.

---

## 7. Debugging Tips

1. **AES-CTR mismatch:** Check counter byte order (bytes 8-15 must be big-endian)
2. **NCZ magic not found:** Check if NCA header is present (0x4000 bytes before "NCZSECTN")
3. **Decompression fails:** Enable debug logs in `ncz.js` (already added)
4. **Hash mismatch:** Verify AES-CTR is using correct offset (must be `offset >> 4`, not `offset`)

---

## 8. Adding New Tests

When adding new tests:
1. Use Python nsz as reference implementation
2. Test against known-good keystream/output
3. Include both Node.js and browser versions if testing crypto
4. Document test vectors and expected output
