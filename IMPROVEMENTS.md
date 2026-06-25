# Improvement Opportunities

Prioritized areas for improvement identified 2026-05-30.

## High Impact

1. ✅ **HFS0 header building duplicated 6x** — `converter.js:339-375,504-570`, `nsz-cli.js:184-274`, `fs/xci.js:76-141`. `HFS0Writer` class exists but is unused by converter/CLI. Any HFS0 bug needs fixing in 6 places. Refactor to use `HFS0Writer` consistently.

2. ✅ **Verification logic duplicated + undefined in XCZ** — `converter.js` had duplicate `verifyHash` (defined inside `decompressNSZtoNSP` but not `decompressXCZtoXCI`), plus dead top-level function referencing undefined `onLog`. Fixed: single standalone `verifyHash(hash, name, fileHashes, onLog)` at module level. Follows ESLint `class-methods-use-this`.

3. ❌ **Ad script in HTML blocks page load** — `index.html:4`. External ad `<script>` injected before `<title>`. Slows rendering if CDN is slow/down. **Not a problem.**

4. ❌ **`aes128.js` rcon_table oversized** — `crypto/aes128.js:6-26`. AES-128 only needs 10 rcon entries; table has ~100+ entries (repeating every 255). **Keeping as-is to match Python nsz.**

5. ❌ **`AESCBC` class in `aes128.js` is unused** — `crypto/aes128.js:291-335`. Defined and exported, but no file imports it. Web Crypto API supports AES-CBC natively anyway. **Keeping as-is to match Python nsz (`nut/aes128.py` has the same dead code).**

6. ✅ **titlekek_source без fallback** — `keys.js:35`. Python nsz searches both `titlekek_source` and `titlekek` keys; JS code only checked `titlekek_source`. Fixed: falls back to `keys.titlekek` if `keys.titlekek_source` is absent, with explicit error if neither is found.

7. ❌ **NCZ hash сравнение** — `converter.js:249,265`. Bug report claimed 8-byte comparison. **Not a bug**: code uses `hash.substring(0, 32)` = 32 hex chars (16 bytes). NCZ filename convention (`NSZ-FORMAT-ANALYSIS.md:286`) stores `hexHash[:32]` = first 32 hex chars of SHA-256. Full 64-char comparison is impossible with filename-based verification — limited by format spec, not implementation.

8. ❌ **Нет финального flush zstd** — `fs/ncz.js:_decompressStream`, `crypto/zstddec-stream-wrapper.js`. Bug report claimed flush needed after all blocks. **Not a bug**: `ZSTD_decompressStream` returns `0` only when frame fully decoded with no residual output. Calling with empty input (`srcSize = 0`) is a no-op — API already drains all output internally.

## Medium Impact

15. ⏳ **Duplicated XCZ→XCI logic between converter.js and nsz-cli.js** — ~124 lines of identical algorithm (partition iteration, HFS0 building, NCZ decompression, hash verification) reimplemented with different I/O APIs. Core logic should be extracted into a shared module with Reader/Writer/Hasher abstractions (Ports & Adapters). Browser and CLI each provide platform-specific adapters (`WritableStream`/`fs.writeSync`, `SHA256`/`crypto.createHash`). CLI could also switch to sequential writes (`wb+`, seek-back for headers) for cleaner code matching Python nsz, but this doesn't enable sharing with browser (FSA requires absolute positions).


5. ❌ **No `npm test` script** — `package.json:8-10`. Tests exist but require manual discovery. Prevents automated CI. **Not needed for this project.**

6. ✅ **Deleted `_decompressBuffered`** — Memory path now uses `_decompressStream` with `collectChunk` wrapper. Reads input as stream, collects output into buffer. `_decompressBuffered` (entire file in memory before decompression) removed.

7. ❌ **Missing NACP parser** — `fs/ticket.js` has NCA/CNMT/Ticket but no NACP. Python nsz has one; needed for game metadata extraction. **Not needed for NSZ→NSP conversion** — NACP stays inside NCA and is preserved in output NSP. Only useful for `--info` style features.

9. ❌ **Ненадёжная проверка magic bytes** — `fs/nca.js`. Bug report claimed `view.getUint8(4)` is used. **Not a bug**: code reads 4 bytes at `0x200-0x203` via `String.fromCharCode(buffer[0x200], buffer[0x201], buffer[0x202], buffer[0x203])` and compares against `'NCA3'`/`'NCA2'`. No single-byte check exists in this file.


## Polish

8. ❌ **No CI setup** — Not needed for this project.

9. ❌ **SW `writable.close()` error handling** — Not needed. Browser handles failed downloads gracefully. No way to determine appropriate timeout value without profiling.

10. ✅ **UI redesign** — `site-v2.md` suggests a redesign may be planned.

11. ✅ **Мёртвое поле hfs0Data** — `nsz-cli.js:129,139`. Поле `hfs0Data: null` в partitionMetas никогда не читалось — осталось от рефакторинга на HFS0Writer. Удалено.

## Speed Optimization

11. ❌ **Remove SW slice(0) copy** — Attempted to remove `view.slice(0)` in SWDownloader.write. **Reverted** — zstddec yields Uint8Array views into WASM memory; Transferable would transfer entire WASM ArrayBuffer, crashing the WASM instance.

12. ✅ **Remove CLI Buffer.from(chunk) copies** — `nsz-cli.js` used `Buffer.from(chunk)` before `fs.writeSync`. Removed — `fs.writeSync` accepts Uint8Array directly, no copy needed.

## Memory Optimization

13. ❌ **Reduce READ_CHUNK_SIZE** — `fs/ncz.js:52` uses 16MB. **Keeping as-is** — matches Python nsz `SolidCompressor.CHUNK_SZ = 0x1000000`.

14. ❌ **Delete _decompressBuffered for memory savings** — Attempted to eliminate full NCA buffer allocation in memory path. **Not possible** — blob-requirement needs full buffer for `new Blob([data])`.

## Info

- ❌ **accumulatedBytes not updated on error** — `main.js:449`. `accumulatedBytes += file.size` is only on success path. Not a bug: progress bar reaches 100% via `updateProgress(1)` at end. Error files are removed, shouldn't count toward progress. Best practice: only count successfully processed bytes.

- ❌ **NCAHeader.parse offset parameter** — `fs/nca.js`. Wanted to add offset parameter like Python nsz `struct.unpack_from(data, offset)` to avoid `buffer.slice()` copies and read NCA headers from any position in a larger buffer. But NCA header uses fixed absolute offsets (0x200, 0x204, 0x208...), and DataView offset shifts all reads — so offset=0x200 would make `view.getUint8(0x204)` read from 0x404. Can't use relative offsets without subtracting offset from every read, which defeats the purpose.

- ✅ **NCAHeader.parse: match Python nsz style** — `fs/nca.js`. Used `buffer.slice()` for byte arrays (like Python `data[start:end]`) and `buffer[i]` for magic bytes. Scalar reads use DataView (like Python `struct.unpack_from`). Consistent with Python nsz patterns.

- ❌ **SW download behavior**: Wanted the same UX as FSA mode: first show a folder picker, then download to the chosen location. This is impossible with SW — SW always saves to browser Downloads folder. Save As dialog is controlled by browser settings, not by SW code — no API exists to show it programmatically. [Chrome setting: chrome://settings/downloads → "Ask where to save each file before downloading"](chrome://settings/downloads).

- ✅ **Lazy SW registration on first use in convert handler (`main.js`)** — SW no longer registers at DOMContentLoaded. Registration happens only when convert is triggered in SW or FSA mode, guarded by `window._swRegistered` flag.

- ❌ **_decompressStream gap for first section** — Bug report claimed `_decompressStream` doesn't account for gap between `UNCOMPRESSABLE_HEADER_SIZE` (0x4000) and first real section. **Not a bug**: `getSections()` already inserts a `FakeSection` when `sections[0].offset > UNCOMPRESSABLE_HEADER_SIZE`, and `_processStreamDecompressedChunk` uses section-aware positioning for every decompressed byte with correct `ncaPos` tracking. Python nsz's approach (raw offset arithmetic) is equivalent.
