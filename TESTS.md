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
- aes-js AES-ECB encryption of counter blocks

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

## 2. Browser-based AES-CTR Tests

### test_browser.html
**Location:** `/test_browser.html`
**Purpose:** AES-CTR keystream verification in browser
**What it tests:**
- AES-CTR with PyCryptodome-compatible counter
- Uses aes-js library loaded via `<script>` tag

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

# AES-CTR manual (uses Node crypto, no aes-js dep)
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
