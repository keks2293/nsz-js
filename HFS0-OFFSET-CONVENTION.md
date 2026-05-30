# HFS0 Offset Convention Research

## Summary

We aligned **all HFS0 writers and readers** across the codebase to use the **hactool offset convention**:

```
stored = absolute - actualHeaderSize
reader: absolute = base + actualHeaderSize + stored
```

This matches Python nsz (commit `b445f666`) and hactool (source `hfs0.c:78`):
```
absolute = ctx->offset + header_size + cur_file->offset
```

Without this, output XCIs would have partition/file offsets off by `actualHeaderSize` bytes when read by hactool or emulators (Yuzu, Ryujinx).

---

## The Convention

There are two possible conventions for storing HFS0 file offsets:

### Convention A (old — broken for hactool)
```
stored = absolute        # store absolute offset within buffer
reader: abs = base + stored
```

### Convention B (hactool — correct)
```
stored = absolute - actualHeaderSize   # relative to end of actual header
reader: abs = base + actualHeaderSize + stored
```

`actualHeaderSize = 0x10 + fileCount * 0x40 + stringTableSize`

**Note:** `actualHeaderSize` is NOT the same as the padded header size (e.g., `0x8000`). It's the actual bytes consumed by the HFS0 header in memory. The padded header is `max(0x8000, actualHeaderSize)`.

---

## What Changed

### 1. HFS0Writer.build() — `fs/xci.js:103`

**Before:**
```js
view.setBigUint64(pos, BigInt(filePos), true);
```

**After:**
```js
view.setBigUint64(pos, BigInt(filePos - actualHeaderSize), true);
```

`actualHeaderSize` was already computed at the top of `build()`:
```js
const actualHeaderSize = 0x10 + this.files.length * 0x40 + stringTableBytes.length;
```

### 2. HFS0Reader.parse() — `fs/xci.js:50`

**Before:**
```js
offset: baseOffset + storedOffset,
```

**After:**
```js
offset: baseOffset + this._headerSize + storedOffset,
```

`this._headerSize` is computed during `parse()` as `0x10 + fileCount * 0x40 + stringTableSize`.

### 3. XCIWriter.build() — `fs/xci.js:278`

Root HFS0 partition entries:

**Before:**
```js
view.setBigUint64(pos, BigInt(entry.dataOffset - rootHfs0Base), true);
```

**After:**
```js
view.setBigUint64(pos, BigInt(entry.dataOffset - rootHfs0Base - rootActualHeader), true);
```

### 4. converter.js streaming path root entries — `converter.js:365`

**Before:**
```js
rootView.setBigUint64(pos, BigInt(po.offset - ROOT_HFS0_OFFSET), true);
```

**After:**
```js
rootView.setBigUint64(pos, BigInt(po.offset - ROOT_HFS0_OFFSET - rootActualHeader), true);
```

This was a bug found during review — the streaming path was still using the old convention while every other writer had been updated.

### 5. `_buildPartitionHfs0Header` — `converter.js:523`

**Before:**
```js
view.setBigUint64(pos, BigInt(filePos), true);
```

**After:**
```js
view.setBigUint64(pos, BigInt(filePos - actualHeader), true);
```

### 6. `_buildPartitionHfs0Buffer` — `converter.js:559`

**Before:**
```js
view.setBigUint64(pos, BigInt(filePos), true);
```

**After:**
```js
view.setBigUint64(pos, BigInt(filePos - actualHeader), true);
```

### 7. nsz-cli.js root partition entries — `nsz-cli.js:221`

The root HFS0 is padded to `ROOT_HFS0_PADDED_SIZE = 0x8000`. Partitions start at `po.offsetInSection + ROOT_HFS0_PADDED_SIZE` within the XCI section.

**Before:**
```js
rootHeader.writeBigUInt64LE(BigInt(po.offsetInSection + ROOT_HFS0_PADDED_SIZE), pos);
```

**After:**
```js
rootHeader.writeBigUInt64LE(BigInt(po.offsetInSection + ROOT_HFS0_PADDED_SIZE - rootActualHeader), pos);
```

### 8. nsz-cli.js partition file entries — `nsz-cli.js:263`

The partition HFS0 header is padded to `pHeaderSize = Math.max(PARTITION_HEADER_SIZE, pActualHeader)`. File data starts at `writePos = po.offset + pHeaderSize`.

**Before:**
```js
pHeader.writeBigUInt64LE(BigInt(pHeaderSize + pfOff), pos);
```

**After:**
```js
pHeader.writeBigUInt64LE(BigInt(pHeaderSize + pfOff - pActualHeader), pos);
```

---

## Verification

### Proof by example (XCIWriter root HFS0)

For the first partition (e.g., `secure`):
- `entry.dataOffset = ROOT_HFS0_OFFSET + rootActualHeader`
- `stored = (ROOT_HFS0_OFFSET + rootActualHeader) - ROOT_HFS0_OFFSET - rootActualHeader = 0`
- hactool: `absolute = ROOT_HFS0_OFFSET + rootActualHeader + 0 = ROOT_HFS0_OFFSET + rootActualHeader`
- ✓ Correctly points to the partition HFS0 header

For the second partition:
- `entry.dataOffset = ROOT_HFS0_OFFSET + rootActualHeader + firstPartitionPaddedSize`
- `stored = firstPartitionPaddedSize`
- hactool: `absolute = ROOT_HFS0_OFFSET + rootActualHeader + firstPartitionPaddedSize`
- ✓ Correctly points to the second partition

### Proof by example (nsz-cli.js partition file entries)

For the first file in a partition:
- `pfOff = 0`, `pHeaderSize = max(0x8000, pActualHeader) = 0x8000` (typical case)
- `stored = 0x8000 - pActualHeader`
- hactool: `partition_base + pActualHeader + (0x8000 - pActualHeader) = partition_base + 0x8000`
- Data IS at `writePos = po.offset + 0x8000`
- ✓ Correct

For the second file:
- `pfOff = firstFileSize`
- `stored = 0x8000 + firstFileSize - pActualHeader`
- hactool: `partition_base + pActualHeader + 0x8000 + firstFileSize - pActualHeader = partition_base + 0x8000 + firstFileSize`
- ✓ Correct

### Self-consistency: HFS0Writer ↔ HFS0Reader

HFS0Writer stores: `filePos - actualHeaderSize` (relative to end of actual header)
HFS0Reader reads: `baseOffset + actualHeaderSize + storedOffset` (adds actual header back)

Both embedded in the same file (`fs/xci.js`). Round-trip verified by construction.

---

## PFS0 Comparison

PFS0 uses a **different** convention that already works:

```js
// PFS0Reader (fs/pfs0.js:43)
offset: relOffset + this.headerSize,

// PFS0Writer (fs/pfs0.js:122)
view.setBigUint64(pos, BigInt(f.offset), true);
```

Where `f.offset` is 0-based relative to the data start (not header-relative). The reader adds `headerSize` to get the absolute position. This is conceptually equivalent to hactool convention with `stored = absolute - headerSize`, since PFS0's `headerSize` is the padded/aligned header size, and PFS0 stores `fileOffset` directly (which is already 0 at data start).

**Key insight:** PFS0 was already correct because it happened to use a convention where stored = absolute - paddedHeaderSize. HFS0 needed the fix because `actualHeaderSize ≠ paddedHeaderSize (0x8000)`.

---

## References

- **Python nsz commit `b445f666`:** "Achieved hactoolnet compatibility for XCZ to XCI decompression"
- **hactool source `hfs0.c:78`:** `absolute = ctx->offset + header_size + cur_file->offset`
- **hactoolnet:** Uses the same convention (derived from hactool)
- **Python nsz `Hfs0Stream.getHeader()`:** `stored = f['offset'] - headerSize`
- **Test self-contained tests:** All pass (crypto, zstd, AES-CTR)
