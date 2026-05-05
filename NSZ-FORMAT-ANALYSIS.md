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

**Structure:**
```
Offset  Size  Description
0x0000 0x4000  Uncompressable header (NCA header)
0x4000  0x08   Magic: "NCZSECTN"
0x4008  0x08   Section count (u64 LE)
...   variable   Section headers (Header.Section per section)
...   variable   Block header (if NCZBLOCK) or zstd stream
```

**Section header (`Header.Section`):**
```
Offset  Size  Description
0x00    0x08   Offset into compressed data (u64 LE)
0x08    0x08   Size of section (u64 LE)
0x10    0x08   Crypto type (u64 LE) — see crypto types below
0x18    0x08   Padding
0x20    0x10   Crypto key (16 bytes)
0x30    0x10   Crypto counter IV (16 bytes)
```

**Decompression:**
1. Read 0x4000 byte uncompressable header
2. Read "NCZSECTN" magic
3. Read section count and parse each section
4. If `section[0].offset > 0x4000`, create `FakeSection` for the gap (cryptoType=1, plaintext)
5. Check for "NCZBLOCK" magic to determine compression type
6. Decompress each section with appropriate method
7. Apply AES decryption if cryptoType is 3 or 4
8. SHA256 verify against filename stem

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

### Issues to check in nsz-js:

1. **FakeSection handling** — When `section[0].offset > 0x4000`, a FakeSection is inserted for the uncompressed gap. Does our code handle this?

2. **NCZBLOCK magic detection** — Must check for `b'NCZBLOCK'` magic at the right position after sections. If present, use block decompression; otherwise use zstd stream.

3. **Crypto type filtering** — Only apply AES-CTR when `cryptoType in (3, 4)`. Types 1 and 2 are not decrypted.

4. **AES-CTR counter** — Uses `offset >> 4` (not `offset`) as the initial counter value. The offset is divided by 16 (block size).

5. **Section offset interpretation** — `s.offset` is the offset INTO the compressed data, not absolute file offset. The first section's offset minus 0x4000 gives the gap size.

6. **Block header reading** — Block header is read immediately after sections, before compressed data. The `compressedBlockSizeList` array has `numberOfBlocks` entries of i32 LE.

7. **XCI decompression** — When decompressing XCZ, the HFS0 partition is processed per-partition with `ExtractHashes`. The XCI stream copies original container settings via `originalXciPath`.

8. **PFS0 stream for NSZ** — Uses `container.getPaddedHeaderSize()` or `container.getFirstFileOffset()` for the PFS0 header size. Also uses `getStringTableSize()` for the string table.

9. **Verification mode** — In verify mode, `f=None` for `__decompressNcz`, which skips writing but still computes SHA256 hash.

10. **BlockDecompressorReader** — This is a separate module for NCZBLOCK format. Need to check if our implementation handles this or if it only supports zstd.

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

### NCZ format implementation (✅ mostly aligned):

- Magic: `NCZSECTN` — ✅ matches
- Section header layout (offset/size/crypto/key/counter) — ✅ matches
- FakeSection gap handling — ✅ implemented in nsz-js
- NCZBLOCK detection — ✅ implemented in nsz-js
- Block decompressor — ✅ implemented in `ncz.js`
- AES-CTR counter (nonce[0:8] + BE64 blockIndex) — ✅ matches Python PyCryptodome
- AES-XTS support — ✅ implemented in `aesxts.js`
