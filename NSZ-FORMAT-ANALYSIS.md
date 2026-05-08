# NSZ File Format Analysis

## Overview

The Python `nsz` tool processes multiple Nintendo compressed file formats. Each format has distinct structures and compression methods.

---

## 1. NSZ (Compressed NSP)

**Detection:** `isNspNsz(filePath)` — checks if file is a valid NSP container with `.ncz` files inside.

**Structure:**
- NSP container (PFS0 header + string table + files)
- Contains `.ncz` files (compressed NCA data)
- `.nca` files stored uncompressed

**Decompression flow:**
1. Parse PFS0 header from container
2. For each `.ncz` file: decompress using `__decompressNcz()`
3. For `.nca` files: copy as-is
4. Output: `.nsp` file

**Verification:**
- Hashes each `.nca` file and compares first 32 chars of SHA256 against filename stem
- Optionally verifies NSP SHA256 against original file

---

## 2. XCZ (Compressed XCI)

**Detection:** `isXciXcz(filePath)` — checks for XCI signature.

**Structure:**
- XCI container with HFS0 partition
- Contains `.ncz` files inside HFS0 partition
- May have both Fixed-Key and Encrypted partitions

**Decompression flow:**
1. Parse XCI header, locate HFS0 partition
2. For each partition: extract hashes, decompress `.ncz` files
3. Write to new XCI stream using `Xci.XciStream`
4. Copy XCI container settings (card info, maker version, etc.) from original
5. Output: `.xci` file

**Key handling:**
- Uses `originalXciPath` to copy XCI metadata from source

---

## 3. NCZ (Compressed NCA — Single File)

**Detection:** `isCompressedGameFile(filePath)` — checks extension `.ncz`.

**Structure (VERIFIED AGAINST ORIGINAL nsz AND real files — same format whether inside NSZ/XCZ container or standalone .ncz):**
```
Offset (in NCZ file)  Size     Description
0x0000               0x4000    NCA header (first 0x4000 bytes of original NCA, still encrypted)
0x4000               0x08      Magic: "NCZSECTN" (8 bytes, ASCII)
0x4008               0x08      Section count (u64 LE)
0x4010               variable   Section headers (64 bytes each, see below)
...                  variable   Compressed data (zstd stream or NCZBLOCK header + blocks)
```

**Key finding: NCA header is ALWAYS present at offset 0.** Verified against real files:
- NCZ inside NSZ container: offset 0x0000 = NCA header, offset 0x4000 = NCZSECTN
- Standalone .ncz (extracted from NSZ): same format — offset 0x0000 = NCA header, offset 0x4000 = NCZSECTN
- Section offsets are NCA-level coordinates (e.g. 0x4000 = start after NCA header)
- Expected NCA size = 0x4000 + sum(section sizes) — matches original NCA file size

**Python nsz reference (`NszDecompressor.__decompressNcz()`):**
1. `nspf.seek(0)` → `header = nspf.read(0x4000)` — reads NCA header first
2. `magic = nspf.read(8)` — reads "NCZSECTN" at position 0x4000
3. `f.write(header)` — NCA header written to output BEFORE decompression
4. `sections[i].offset` = position within NCZ file (absolute, not relative to compressed data)
5. If `sections[0].offset > 0x4000`, insert `FakeSection(cryptoType=1)` for the gap
6. Gap size = `sections[0].offset - 0x4000` bytes of uncompressed (plaintext) data

**JS implementation approach:**
- Check magic at offset 0x4000: if "NCZSECTN", NCA header present
- Save NCA header (sliceBytes(data, 0, 0x4000)) and set nczhdrOffset = 0x4000
- Parse sections starting at offset nczhdrOffset + 8
- Handle first section gap via FakeSection

**Section header (`Header.Section`):**
```
Offset  Size  Description
0x00    0x08   NCA-level offset (u64 LE) — position in decompressed NCA output
0x08    0x08   Size of section (u64 LE)
0x10    0x08   Crypto type (u64 LE) — see crypto types below
0x18    0x08   Padding
0x20    0x10   Crypto key (16 bytes)
0x30    0x10   Crypto counter IV (16 bytes)
```

**Decompression (all NCZ files — same flow):**
1. Read first 0x4000 bytes as NCA header (saved for output)
2. Find "NCZSECTN" magic at offset 0x4000 within NCZ data
3. Read section count and parse each section (starting at offset 0x4008)
4. If `section[0].offset > 0x4000`, create `FakeSection` for the gap (cryptoType=1, plaintext)
5. Check for "NCZBLOCK" magic to determine compression type
6. Decompress each section with appropriate method
7. Apply AES decryption if cryptoType is 3 or 4
8. Prepend NCA header to decompressed output
9. SHA256 verify against filename stem

---

## 4. NCZ Sub-type: Standard zstd Compression

**Detection:** Block magic is NOT "NCZBLOCK" (i.e., magic is zstd frame).

**Flow:**
```python
decompressor = ZstdDecompressor().stream_reader(nspf)
```

- Uses zstd streaming decompressor
- Reads 0x10000 byte chunks
- Applies AES-CTR decryption per section (cryptoType 3 or 4)
- Writes decompressed data sequentially

---

## 5. NCZ Sub-type: Block Compression (NCZBLOCK)

**Detection:** Block magic == `b'NCZBLOCK'`.

**Block header structure:**
```
Offset  Size  Description
0x00    0x08   Magic: "NCZBLOCK"
0x08    0x01   Version (i8)
0x09    0x01   Type (i8)
0x0A    0x01   Unused (i8)
0x0B    0x01   Block size exponent (i8)
0x0C    0x04   Number of blocks (i32 LE)
0x10    0x08   Decompressed size (i64 LE)
0x18    variable Compressed block size list (i32 LE per block)
```

**Decompression:**
- Uses `BlockDecompressorReader.BlockDecompressorReader` for block-level decompression
- Each block is independently decompressed (no cross-block dependencies)
- More robust against corruption than standard zstd

---

## 6. Crypto Types

| cryptoType | Description | Applied? |
|------------|-------------|----------|
| 1 | Plaintext (no encryption) | No |
| 2 | ? | No |
| 3 | AES-CTR with section key/IV | Yes |
| 4 | AES-CTR with section key/IV | Yes |

**AES-CTR implementation (`aes128.AESCTR`):**
```python
class AESCTR:
    def __init__(self, key, nonce, offset=0):
        self.key = key
        self.nonce = nonce
        self.seek(offset)

    def seek(self, offset):
        self.ctr = Counter.new(64, prefix=self.nonce[0:8], initial_value=(offset >> 4))
        self.aes = AES.new(self.key, AES.MODE_CTR, counter=self.ctr)

    def encrypt(self, data):
        return self.aes.encrypt(data)  # AES-CTR: encrypt = decrypt

    def decrypt(self, data):
        return self.encrypt(data)
```

**Counter construction:**
- 64-bit counter value = `offset >> 4` (offset in bytes, divided by 16-byte blocks)
- 8-byte prefix = `nonce[0:8]`
- Total nonce = 8 bytes prefix + 8 bytes counter = 16 bytes (standard AES-CTR)

**AES-CTR implementation history:**

*Why Node.js `crypto` module was implemented:*
- Initial implementation used Node.js `crypto.createCipheriv('aes-128-ecb', ...)` for AES-ECB keystream generation
- Native crypto module provides better performance than pure-JS AES implementations
- Works well in Node.js environments where `require('crypto')` is available

*Why Node.js `crypto` module was dropped:*
- Browser environments do NOT support Node.js `crypto` module
- AES-ECB (required for AES-CTR keystream generation) is NOT available in Web Crypto API (`crypto.subtle` does not support ECB mode)
- Maintained two separate files (`aesctr.cjs` for Node.js, `aesctr.mjs` for browsers) which increased complexity
- Solution: Use `crypto/aesctr.mjs` with a pure-JS AES implementation (`aes-js`) for cross-platform compatibility
- Files `crypto/aesctr.js` and `crypto/aesctr.cjs` have been removed (2026-05-06)

---

## 7. FakeSection (Gap Handling)

When `sections[0].offset > 0x4000`, there's an uncompressed gap between the NCA header and the first compressed section. A `FakeSection` is inserted:

```python
class FakeSection:
    def __init__(self, offset, size):
        self.offset = offset
        self.size = size
        self.cryptoType = 1  # plaintext
```

This gap data is copied as-is (no decompression or decryption needed).

---

## 8. Hash Verification

**NCA hash verification:**
```python
hexHash = sha256().hexdigest()
if hexHash[:32] == fileNameHash:
    # VERIFIED
```
- Full SHA256 hash of decompressed NCA content
- First 32 hex chars compared against filename stem (lowercase)

**NSP SHA256 verification:**
- Full SHA256 of the entire NSP container
- Used when verifying against an original file path

---

## 9. Nintendo AES-XTS (XTSN)

**Used in:** XCI/container-level encryption (not NCZ sections).

**`AESXTSN` class:**
- Two 16-byte keys (K1, K2) for XTS mode
- Configurable sector size (default 0x200)
- Uses `get_tweak(sector)` for sector-based tweak computation
- XEX (XEX2) tweak left-shift with carry reduction per 128-byte block

---

## 10. Key Differences from Our Implementation

### Bugs found and FIXED in nsz-js (during debugging session):

1. **NCZ header handling (FIXED)** — NCZ data from NSZ container includes NCA header (0x4000 bytes) at offset 0, with "NCZSECTN" magic at offset 0x4000. Code now checks both locations and preserves NCA header for output.

2. **FakeSection cryptoType (FIXED)** — Was incorrectly set to 0, should be 1 (plaintext). Fixed in `ncz.js` line 80.

3. **First section gap handling (FIXED)** — Missing logic to skip uncompressed gap for first section. Python code: `if firstSection: uncompressedSize = UNCOMPRESSABLE_HEADER_SIZE - sections[0].offset; i += uncompressedSize`. Added `firstSection` flag to both `_decompressWithStreaming` and `_decompressWithBlocks`.

4. **AES-CTR counter endianness (FIXED)** — Python's `Counter.new(64, prefix=nonce[0:8], initial_value=(offset >> 4))` uses big-endian for counter bytes. Fixed in `crypto/aesctr.mjs` to write counter bytes in big-endian order using `Buffer.writeBigUInt64BE()`.

5. **Node.js crypto dropped** — Removed `crypto/aesctr.js` and `crypto/aesctr.cjs` (Node.js `crypto` module) because they're not supported in browsers. AES-ECB is not available in Web Crypto API. Now using pure-JS AES (aes-js) in `crypto/aesctr.mjs` for cross-platform compatibility. See section 6 for full history.

### Issues still to verify in nsz-js:

1. **NCZBLOCK magic detection** — Must check for `b'NCZBLOCK'` magic at the right position after sections. If present, use block decompression; otherwise use zstd stream.

2. **Crypto type filtering** — Only apply AES-CTR when `cryptoType in (3, 4)`. Types 1 and 2 are not decrypted.

3. **Section offset interpretation** — `s.offset` is the offset INTO the compressed data, not absolute file offset. The first section's offset minus 0x4000 gives the gap size.

4. **Block header reading** — Block header is read immediately after sections, before compressed data. The `compressedBlockSizeList` array has `numberOfBlocks` entries of i32 LE.

5. **XCI decompression** — When decompressing XCZ, the HFS0 partition is processed per-partition with `ExtractHashes`. The XCI stream copies original container settings via `originalXciPath`.

6. **PFS0 stream for NSZ** — Uses `container.getPaddedHeaderSize()` or `container.getFirstFileOffset()` for the PFS0 header size. Also uses `getStringTableSize()` for the string table.

7. **Verification mode** — In verify mode, `f=None` for `__decompressNcz`, which skips writing but still computes SHA256 hash.

8. **BlockDecompressorReader** — This is a separate module for NCZBLOCK format. Need to check if our implementation handles this or if it only supports zstd.

---

## 11. Python nsz vs nsz-js: File Type Support Comparison

### File types supported by Python nsz (`factory()` in `__init__.py`):

| Extension | Python nsz handler | nsz-js support | Status |
|-----------|-------------------|----------------|--------|
| `.xci` | `Xci` | ✅ Partial (`xci.js` — XCIReader + HFS0Reader exist) | Read-only parser, no decompression |
| `.xcz` | `Xci` | ❌ Not supported | Missing |
| `.nsp` | `Nsp` | ✅ Partial (PFS0 reader/writer in `pfs0.js`) | Can parse, but no explicit NSP handling |
| `.nsz` | `Nsp` | ✅ Fully implemented | Main focus of nsz-js |
| `.nca` | `Nca` | ❌ Not supported | Missing |
| `.ncz` | `File` | ✅ Partial (`ncz.js` — NCZDecompressor) | Only via NSZ container, not standalone |
| `.nacp` | `Nacp` | ❌ Not supported | Missing |
| `.tik` | `Ticket` | ❌ Not supported | Missing |
| `.cnmt` | `Cnmt` | ❌ Not supported | Missing |
| `normal` | `Hfs0` | ❌ Not supported | Missing |
| `logo` | `Hfs0` | ❌ Not supported | Missing |
| `update` | `Hfs0` | ❌ Not supported | Missing |
| `secure` | `Hfs0` | ❌ Not supported | Missing |

### Key gaps in nsz-js:

1. **XCZ decompression** — XCI/XCZ is the primary format for Switch cartridge dumps. Python nsz handles both XCI (uncompressed) and XCZ (compressed) via the same `Xci` handler. nsz-js has `xci.js` with `XCIReader` and `HFS0Reader` parsers, but no decompression logic.



4. **Standalone `.ncz`** — Python nsz supports `.ncz` as a single-file format (not just inside NSZ). nsz-js only handles NCZ sections within NSZ containers.

5. **`.nca` files** — Python nsz supports parsing and processing individual `.nca` files. Not implemented in nsz-js.

6. **`.nacp`, `.tik`, `.cnmt` files** — Python nsz has dedicated parsers for these Nintendo formats. nsz-js has partial CNMT parsing in `ticket.js` but no standalone file handlers.

7. **HFS0 partitions (`normal`, `logo`, `update`, `secure`)** — Python nsz handles these as virtual partitions within XCI. nsz-js has `HFS0Reader` in `xci.js` but no partition-level processing.

8. **Extension detection** — Python nsz uses `isNspNsz()` and `isXciXcz()` functions that check file content (magnets), not just extensions. nsz-js only checks file extension strings.

### Crypto type constants (✅ aligned):

| Constant | Python nsz | nsz-js | Match |
|----------|-----------|--------|-------|
| `CRYPTO_NONE` | 1 | 1 | ✅ |
| `CRYPTO_XTS` | 2 | 2 | ✅ |
| `CRYPTO_CTR` | 3 | 3 | ✅ |
| `CRYPTO_BKTR` | 4 | 4 | ✅ |
| `CRYPTO_NCA0` | 0x3041434E | 0x3041434E | ✅ |

### NCZ format implementation (✅ mostly aligned, bugs fixed):
- Magic: `NCZSECTN` — ✅ matches
- Section header layout (offset/size/crypto/key/counter) — ✅ matches
- FakeSection gap handling — ✅ FIXED (cryptoType=1, not 0)
- First section gap handling — ✅ FIXED (skip UNCOMPRESSABLE_HEADER_SIZE - sections[0].offset)
- NCZBLOCK detection — ✅ implemented in nsz-js
- Block decompressor — ✅ implemented in `ncz.js`
- AES-CTR counter (nonce[0:8] + BE64 blockIndex) — ✅ FIXED (big-endian counter)
- NCA header preservation — ✅ FIXED (detect and prepend when present)
- AES-XTS support — ✅ implemented in `aesxts.js`
- Browser zstd decompression — `DecompressionStream('zstd')` NOT supported in any browser. Uses zstddec WASM library via `static/zstddec.mjs`. Handles any window size. See `BROWSER-ZSTD-LIMITATION.md`.
