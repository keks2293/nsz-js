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

### test_aes_node.mjs (Node.js)
**Location:** `/test_aes_node.mjs`
**Purpose:** Test AES-CTR in Node.js using aes-js library
**What it tests:**
- AES-CTR keystream matches Python output
- Counter block construction (nonce[0:8] + BE64 blockIndex)
- aes-js AES-ECB encryption of counter blocks

**How to run:**
```bash
node --experimental-vm-modules test_aes_node.mjs
```

**Expected output:** Keystream starting with `e95fed2b7d0afca982d145a0ddea1c84...`

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

### test_ctr.html
**Location:** `/test_ctr.html`
**Purpose:** Basic AES-CTR test in browser
**What it tests:**
- AES-CTR with PyCryptodome-compatible counter
- Uses aes-js library loaded via `<script>` tag

**How to run:** Open in browser

---

### test_ctr_browser.html
**Location:** `/test_ctr_browser.html`
**Purpose:** Test AES-CTR in browser environment
**What it tests:**
- Multiple test cases for AES-CTR
- PyCryptodome counter format verification

**How to run:** Open in browser

---

### test_final.html
**Location:** `/test_final.html`
**Purpose:** Final verification of AES-CTR implementation
**What it tests:**
- Complete AES-CTR flow matching Python nsz
- Counter block: nonce[0:8] + BE64(blockIndex)
- Keystream verification against Python reference

**How to run:** Open in browser

---

### test_aes_simple.html
**Location:** `/test_aes_simple.html`
**Purpose:** Simplified AES-CTR test
**What it tests:**
- Basic AES-CTR functionality
- PyCryptodome-compatible counter format

**How to run:** Open in browser

---

## 3. NSZ Conversion Test

### test_convert.cjs (Node.js)
**Location:** `/test_convert.cjs`
**Purpose:** Quick NSZ to NSP converter using fixed crypto modules
**What it tests:**
- Full NSZ decompression pipeline
- PFS0 parsing
- NCZ decompression with AES-CTR
- NCA output verification

**How to run:**
```bash
node test_convert.cjs
```

**Prerequisites:**
- Requires NSZ file input
- Requires `crypto/aesctr.mjs`

---

## 4. Test Coverage Summary

| Component | Python Ref | Node.js | Browser |
|-----------|-------------|---------|---------|
| AES-CTR keystream | ✅ test_aes_ctr.py | ✅ test_aes_node.mjs | ✅ test_ctr.html |
| Counter format (BE64) | ✅ test_aes_ctr.py | ✅ test_aes_node.mjs | ✅ test_final.html |
| NCZ decompression | - | ✅ test_convert.cjs | - |
| PFS0 parsing | - | ✅ test_convert.cjs | - |
| AES-CTR + zstd | - | ✅ test_convert.cjs | - |

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

### Quick verification:
```bash
# Test test vector (section 5)
node test_vector.mjs

# Test AES-CTR in Node
node --experimental-vm-modules test_aes_node.mjs

# Test full conversion (requires NSZ file)
# node test_convert.cjs path/to/file.nsz
```

### Browser tests:
Open any `test_*html` file in a browser with `crypto/aes-js.js` in the same directory.

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
