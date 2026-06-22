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

All HFS0 writers now use `HFS0Writer` class (`fs/hfs0.js`) which handles the convention internally.

### 1. HFS0Writer._writeHeader() — `fs/hfs0.js:104`

```js
view.setBigUint64(pos, BigInt(filePos - actualHeader), true);
```

`actualHeader` is computed via `_getActualHeaderSize()`: `0x10 + entries.length * 0x40 + stringTable.length`.

### 2. HFS0Reader.getFiles() — `fs/hfs0.js:42`

```js
offset: this.baseOffset + this._headerSize + e.offset,
```

`this._headerSize` is computed during `parse()` as `0x10 + fileCount * 0x40 + stringTableSize`.

### 3. XCIWriter.build() — `fs/xci.js:99`

Root HFS0 partition entries use `HFS0Writer`:
```js
const rootWriter = new HFS0Writer(0);
for (const p of this.partitions) rootWriter.addEntry(p.name, p.data.length);
```

`p.data.length` = full partition size (HFS0 header + file data).

### 4. converter.js streaming path — `converter.js:356-370`

Uses `HFS0Writer` for root and partition HFS0:
```js
const rootWriter = new HFS0Writer(ROOT_HFS0_PADDED_SIZE);
const partSizes = [];
for (const pm of partitionMetas) {
    const partSize = pm.raw ? pm.size : pm.hfs0BufferSize + pm.totalSize;
    partSizes.push(partSize);
    rootWriter.addEntry(pm.name, partSize);
}
```

Root HFS0 entry size = `hfs0BufferSize + totalSize` (header + file data). This was previously `hfs0BufferSize` (header only), causing partition overlap.

### 5. nsz-cli.js — `nsz-cli.js:169-195`

Uses `HFS0Writer` for root and partition HFS0:
```js
const rootWriter = new HFS0Writer(ROOT_HFS0_PADDED_SIZE);
const partSizes = [];
for (const pm of partitionMetas) {
    const partSize = pm.raw ? pm.rawData.length : PARTITION_HEADER_SIZE + pm.totalSize;
    partSizes.push(partSize);
    rootWriter.addEntry(pm.name, partSize);
}
```

Partition HFS0 headers also via `HFS0Writer`:
```js
const pWriter = new HFS0Writer(PARTITION_HEADER_SIZE);
for (const m of pm.files) pWriter.addEntry(m.name, m.size);
const pHeader = Buffer.from(pWriter.buildHeader());
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

### Self-consistency: HFS0Writer ↔ HFS0Reader

HFS0Writer stores: `filePos - actualHeaderSize` (relative to end of actual header)
HFS0Reader reads: `baseOffset + actualHeaderSize + storedOffset` (adds actual header back)

Both in `fs/hfs0.js`. Round-trip verified by construction.

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

## Streaming vs Pre-Calculate: Browser Limitation

Python nsz uses streaming approach for root HFS0:
1. `add()` with placeholder size (0x200)
2. Write partition data via `Hfs0Stream`
3. `resize()` updates `files[]` with actual size
4. Next `add()` — `self.written` flag sets `addpos = self.actualSize`
5. `getHeader()` writes sizes/offsets from `files[]`

JS **cannot** use this approach in browser because `FileSystemWritableFileStream`:
- No `seek()` for reading (only `write({ position: ... })`)
- Root HFS0 header at 0xF000 must be written **before** partition data
- Root header needs all partition sizes → must pre-calculate

JS solution: pre-calculate in two passes:
1. First pass: read metadata, compute `hfs0BufferSize + totalSize` per partition
2. Second pass: build root header, stream partition data

---

## References

- **Python nsz commit `b445f666`:** "Achieved hactoolnet compatibility for XCZ to XCI decompression"
- **hactool source `hfs0.c:78`:** `absolute = ctx->offset + header_size + cur_file->offset`
- **hactoolnet:** Uses the same convention (derived from hactool)
- **Python nsz `Hfs0Stream.getHeader()`:** `stored = f['offset'] - headerSize`
- **Test self-contained tests:** All pass (crypto, zstd, AES-CTR)
