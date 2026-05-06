# NCZ Decompression & PFS0 Writing Fixes

## 1. Wire up progress callback in browser `ncz.js` `_decompressWithStreaming`

**File:** `ncz.js`, line 94, 160

**Problem:** `decompressedOffset` tracks progress (initialized at line 97, incremented at line 196) but the progress callback is never called. Node version (`node/fs/ncz.js:115-117`) has this wired up.

**Fix:**
```
- Add `progressCallback = null` parameter to `decompress()` method (line 94)
- Add `progressCallback` parameter to `_decompressWithStreaming()` (line 160)
- Add progress callback at end of each chunk loop (after line 196):
    if (progressCallback) {
        progressCallback(decompressedOffset / ncaSize);
    }
- Pass progressCallback through from `decompress()` to `_decompressWithStreaming()`
```

---

## 2. Wire up progress callback in browser `ncz.js` `_decompressWithBlocks`

**File:** `ncz.js`, line 203

**Problem:** Same as #1 but for block-based decompression path. `decompressedOffset` is tracked at line 212/245 but never consumed.

**Fix:**
```
- Add `progressCallback = null` parameter to `_decompressWithBlocks()` (line 203)
- Add progress callback at end of each chunk loop (after line 245):
    if (progressCallback) {
        progressCallback(decompressedOffset / ncaSize);
    }
- Pass progressCallback through from `decompress()` to `_decompressWithBlocks()`
```

---

## 3. Remove redundant `setUint32` call in `buildPFS0Stream`

**File:** `converter.js`, line 149

**Problem:** `view.setUint32(4, fileEntries.length, true)` is called twice (lines 148 and 149) - second call is redundant.

**Fix:** Remove line 149.

---

## 4. Add progress updates during file copy in `buildPFS0Memory`

**File:** `converter.js`, line 303-311

**Problem:** Progress jumps from 0.85 to 1.0 with no intermediate updates during the file copy loop.

**Fix:** Add progress update inside the loop (after line 310):
```
const progress = 0.85 + (0.15 * (offset - fullHeaderSize) / totalDataSize);
onProgress(progress, `Building file ${i + 1}/${fileEntries.length}...`);
```
