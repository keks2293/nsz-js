# Improvement Opportunities

Prioritized areas for improvement identified 2026-05-30.

## High Impact

- ✅ **HFS0 header building duplicated 6x** — `converter.js:339-375,504-570`, `nsz-cli.js:184-274`, `fs/xci.js:76-141`. `HFS0Writer` class exists but is unused by converter/CLI. Any HFS0 bug needs fixing in 6 places. Refactor to use `HFS0Writer` consistently.

- ✅ **Verification logic duplicated + undefined in XCZ** — `converter.js` had duplicate `verifyHash` (defined inside `decompressNSZtoNSP` but not `decompressXCZtoXCI`), plus dead top-level function referencing undefined `onLog`. Fixed: single standalone `verifyHash(hash, name, fileHashes, onLog)` at module level. Follows ESLint `class-methods-use-this`.

- ❌ **Ad script in HTML blocks page load** — `index.html:4`. External ad `<script>` injected before `<title>`. Slows rendering if CDN is slow/down. **Not a problem.**

- ❌ **`aes128.js` rcon_table oversized** — `crypto/aes128.js:6-26`. AES-128 only needs 10 rcon entries; table has ~100+ entries (repeating every 255). **Keeping as-is to match Python nsz.**

- ✅ **`AESCBC` class in `aes128.js` is unused** — `crypto/aes128.js:291-335`. Defined and exported, but no file imports it. Web Crypto API supports AES-CBC natively anyway. **Удалено** — класс удалён из `aes128.js`.

- ✅ **titlekek_source без fallback** — `keys.js:35`. Python nsz searches both `titlekek_source` and `titlekek` keys; JS code only checked `titlekek_source`. Fixed: falls back to `keys.titlekek` if `keys.titlekek_source` is absent, with explicit error if neither is found.

- ✅ **Phantom "16-byte alignment" in PFS0 `fixPadding=false`** — `fs/pfs0.js`. Old code did `namesLen + (16 - rawSize%16) % 16` for the default branch, claiming it "matches Python nsz default". It does **not**. Root cause: commit `18923f7` saw nsz output had a `stringTableSize` a few bytes larger than the raw `namesLen` (e.g. real file: input 160 vs raw 154 = 6 bytes) and **misread that as a "16-byte alignment rule"**. In reality Python nsz, in the `!fixPadding` branch, copies the **input container's** `stringTableSize` field verbatim (`container.getStringTableSize()` returns the parsed `_stringTableSize`, never recomputed). It inherits the source NSP's alignment, not a 16-byte rule. Fixed: `PFS0Writer` now takes `inputStringTableSize` and uses it verbatim when `!fixPadding` (matching nsz); when `fixPadding` it recomputes via `allign0x20(rawSize)` (matching nsz `getStringTableSize()`). Verified byte-identical to Python nsz on a real Trackline Express .nsz (stringTableSize=160, headerSize=272, file size=223285520). Also unified the header build into one `PFS0Writer` path (streaming + memory both pass `pfs0.stringTableSize`).

- ❌ **NCZ hash сравнение** — `converter.js:249,265`. Bug report claimed 8-byte comparison. **Not a bug**: code uses `hash.substring(0, 32)` = 32 hex chars (16 bytes). NCZ filename convention (`NSZ-FORMAT-ANALYSIS.md:286`) stores `hexHash[:32]` = first 32 hex chars of SHA-256. Full 64-char comparison is impossible with filename-based verification — limited by format spec, not implementation.

- ❌ **Нет финального flush zstd** — `fs/ncz.js:_decompressStream`, `crypto/zstddec-stream-wrapper.js`. Bug report claimed flush needed after all blocks. **Not a bug**: `ZSTD_decompressStream` returns `0` only when frame fully decoded with no residual output. Calling with empty input (`srcSize = 0`) is a no-op — API already drains all output internally.

- ❌ **Manual `%`→`&` for power-of-2 in aes128.js** — `crypto/aes128.js`. V8 TurboFan strength-reduces `% 4`, `% 16` to `& 3`, `& 15` automatically. Manual replacement gave < 6% on full AES block — not worth readability loss. **Keeping `%`/`Math.floor` for readability.**

## Medium Impact

- ✅ **Duplicated XCZ→XCI logic between converter.js and nsz-cli.js** — ~124 lines of identical algorithm (partition iteration, HFS0 building, NCZ decompression, hash verification) reimplemented with different I/O APIs. Core logic extracted into `fs/xcz-convert.js` with adapter pattern: `{ read, write, createHash, log, progress }`. Browser and CLI each provide platform-specific adapters. CLI `convertXCZ` reduced from ~170 to ~30 lines. Browser streaming path reduced from ~100 to ~15 lines.

- ✅ **Duplicated NSZ→NSP streaming logic between converter.js and nsz-cli.js** — ~113 lines of identical streaming algorithm reimplemented with different I/O APIs. Core logic extracted into `fs/nsz-convert.js` with same adapter interface. CLI `convertNSZ` reduced from ~113 to ~30 lines.

- ✅ **NSZ→NSP memory path duplicated PFS0 header build** — `fs/nsz-convert.js` had `buildPfs0Blob`/`buildPfs0Header` reimplementing the PFS0 assembly that `convertNSZStreaming` already did, and crucially NOT reusing the input `stringTableSize` (so it diverged from nsz). Fixed: `convertNSZMemory` is now a thin wrapper over `convertNSZStreaming` with a blob-backed adapter that accumulates `write(offset, data)` chunks and assembles a `Blob` at the end. Single PFS0 build path (`PFS0Writer`) for both streaming (FS Access / CLI) and memory (browser download) routes. Verified byte-identical output on Trackline Express .nsz (size 223285520) for both paths.

- ❌ **No `npm test` script** — `package.json:8-10`. Tests exist but require manual discovery. Prevents automated CI. **Not needed for this project.**

- ✅ **Deleted `_decompressBuffered`** — Memory path now uses `_decompressStream` with `collectChunk` wrapper. Reads input as stream, collects output into buffer. `_decompressBuffered` (entire file in memory before decompression) removed.

- ❌ **Missing NACP parser** — `fs/ticket.js` has NCA/CNMT/Ticket but no NACP. Python nsz has one; needed for game metadata extraction. **Not needed for NSZ→NSP conversion** — NACP stays inside NCA and is preserved in output NSP. Only useful for `--info` style features.

- ❌ **Ненадёжная проверка magic bytes** — `fs/nca.js`. Bug report claimed `view.getUint8(4)` is used. **Not a bug**: code reads 4 bytes at `0x200-0x203` via `String.fromCharCode(buffer[0x200], buffer[0x201], buffer[0x202], buffer[0x203])` and compares against `'NCA3'`/`'NCA2'`. No single-byte check exists in this file.

- ✅ **Bit-shift overflow (`>>>`) в AES-CTR/XTS/block reader** — `crypto/aesctr.mjs`, `crypto/aesxts.mjs`, `fs/ncz.js`. `>>>` converts to Uint32 before shifting, silently truncating values above 2^32. **Что ломает**:
    - **`aesctr.mjs:51`** — `tmp >>>= 8` в `seek()`: counter блока обрезается для файлов >64GB (offset/16 > 2^32). Результат: неправильный keystream → битые расшифрованные данные → NSP повреждён.
    - **`aesxts.mjs:30`** — `sector >>>= 8` в `getTweakBytes()`: XTS tweak для sector > 2^32 получает неверные байты. На практике sector числа маленькие (<2^32), но код некорректен по спецификации.
    - **`ncz.js:477`** — `position >>> blockSizeExp` в `AsyncBlockDecompressorReader.read()`: blockId обрезается для NCZ >2^(32+blockSizeExp). Блок-ридер пропускает данные или читает не тот блок → битая декомпрессия.
    - **`aesctr.mjs:48`** — `offset >> 4` (арифметический сдвиг) ломался уже на >2GB. `>>>` ломается на >64GB. Python nsz использует произвольную точность int — проблем нет.
    - **Фикс**: все три места заменены на `Math.floor(x / N)` — эквивалент питоновского `>> N` без overflow.


## Polish

- ❌ **No CI setup** — Not needed for this project.

- ❌ **SW `writable.close()` error handling** — Not needed. Browser handles failed downloads gracefully. No way to determine appropriate timeout value without profiling.

- ✅ **UI redesign** — `site-v2.md` suggests a redesign may be planned.

- ✅ **Мёртвое поле hfs0Data** — `nsz-cli.js:129,139`. Поле `hfs0Data: null` в partitionMetas никогда не читалось — осталось от рефакторинга на HFS0Writer. Удалено.

- ❌ **verifyHash/verifyFileNameHash дублирование** — `fs/nsz-convert.js:5-26`, `fs/xcz-convert.js:6-27`. Функции идентичны в обоих файлах. Python nsz делает то же самое — verification inline в `__decompressContainer()` и `decompress()`. Не будем выносить в общий модуль — это соответствует паттерну Python nsz.

- ✅ **CNMT ContentEntry size — строго 48-bit** — `fs/cnmt.js:20-22`. Поле size в CNMT занимает 6 байт (offset 48-53), nsz читает `readInt48()`. Нельзя использовать `getBigUint64(48)` — он читает 8 байт (48-55) и захватывает `type` (offset 53) + junk в старшие биты размера. Реализация: `sizeLow = getUint32(48)`, `sizeHigh = getUint16(52)`, `size = sizeLow + sizeHigh * 0x100000000`. **Регрессия**: коммит `72b24dc` («matches rest of codebase») заменил 48-bit на `getBigUint64` — баг прожил с 1 июля по 2026-07-20, исправлен в `6c6ce11`. `ContentEntry.size` не используется в логике конвертации (hash берётся из `section.size` NCA), так что на байтовую идентичность выхода не влияло, но расходилось с nsz. Правило: НЕ менять на `getBigUint64`.

## SHA256 Optimization

- ✅ **W schedule: Array vs Uint32Array** — `crypto/sha256.js`. SHA-256 message schedule `w[64]` хранит промежуточные 32-bit слова. `Uint32Array` создаёт C-backed typed array с автоматическим `>>> 0` при записи, но `Array` в V8 (TurboFan) оптимизируется так же хорошо — оба типа попадают в fast path для целочисленных операций. Benchmark (300MB): до 10% быстрее с `Array`. **Array предпочтительнее**: (1) не требует приведения типов при вычислении `w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0` — `Uint32Array` автоматически обрезает, но `Array` делает то же через `>>> 0`; (2) совпадает с emn178/js-sha256 (самая быстрая pure-JS SHA-256 библиотека); (3) проще для JIT — V8 не создаёт отдельный backing store.

- ✅ **js-sha256 optimizations: h0-h7, 4x unrolling, HEXES, lastByteIndex** — `crypto/sha256.js`. Step 2 ported from emn178/js-sha256:
  - Individual h0-h7 properties (was `h[8]` array) — avoids bounds-checked array access
  - 4x loop unrolling in compression rounds — 16 iterations instead of 64, fewer branch predictions
  - HEXES lookup table — precomputed `['00'..'ff']` for hex output
  - `lastByteIndex` tracking — correctly handles exact-block-boundary inputs in hexdigest padding
  - **Bug fixed**: hexdigest was using `this.start` for padding position, but after full-block compress `this.start` resets to 0 while the last byte was at position 64. Original js-sha256 tracks `lastByteIndex = i` separately. This caused stale message data in `blocks[0]` to be OR'd with padding bit, producing wrong hashes for exact-multiple-of-64 inputs (64, 128, 512, 1024, 1048576... bytes).
  - **Benchmark**: 3000ms → 2063ms for 300MB (31% faster). Node native: 114ms. hash-wasm pool: 1240ms.

## Speed Optimization

- ✅ **Optimize SW slice(0) copy** — `SWDownloader.write()` now checks if data is a WASM memory view via `view.buffer === wasmInstance.exports.memory.buffer`. WASM views still get `slice(0)`, standalone buffers (e.g. WebCrypto output) are transferred directly. Added `ZstdDecompressor.wasmBuffer` getter. No copy for ~90%+ of data (encrypted sections).

- ✅ **Remove CLI Buffer.from(chunk) copies** — `nsz-cli.js` used `Buffer.from(chunk)` before `fs.writeSync`. Removed — `fs.writeSync` accepts Uint8Array directly, no copy needed.

- ❌ **Remove await от writeChunk и aesCtr.decrypt** — `fs/ncz.js`. Пробовали убрать `await` с `writeChunk` и `aesCtr.decrypt` в `_decompressBlocks` и `_processStreamDecompressedChunk` (коммит 9cf9ec47). В Node.js оба синхронные (`fs.writeSync`, `cipher.update`), так что `await` не нужен. Но:
    - **Сломали кодер**: `aesCtr.decrypt()` стал async (WebCrypto в браузере). Без `await` — `data` получал Promise вместо Uint8Array. `writeChunk` писал Promise-объект в выходной файл → битый NSP.
    - **Сломали плавность**: `writeChunk` асинхронный (FSA `writable.write`). Без `await` — fire-and-forget, конкурентные записи. `progressCallback` вызывался до завершения записи → прогресс скачками.
    - **Вывод**: `await` восстановлен на обоих вызовах. Добавляет ~650μs на 13,000 чанков (212MB). Плавность и корректность важнее.

- ❌ **Cache AesCtr by key+nonce in `_decompressBlocks`** — `fs/ncz.js`. Кешировали `AesCtr` по `key+nonce` через `Map`, чтобы переиспользовать cipher при одинаковых крипто-параметрах секций. **Не работает**: в реальных NSZ файлах counter всегда разный для каждой секции (Trackline Express: key один, counter `00000002...` vs `00000001...`). Кеш даёт 100% промахов, добавляя накладные расходы на `toString()` + `Map.get()` без выигрыша.

- ✅ ~~**ZstdStreamReader**~~ **Отказ от ZstdStreamReader** — `fs/ncz.js`. Пробовали ввести `ZstdStreamReader` — буферизированную обёртку `.read(n)` для потокового zstd (CLI spawn + WASM async generator), чтобы и блоки, и стриминг шли через единый цикл секций.
    - **Проблема**: `ZstdStreamReader` откладывал потребление chunk'ов через async границы. WASM `decodeStream` возвращает `Uint8Array` view в `instance.exports.memory.buffer` — mutable WASM память. Если view не потребить синхронно, следующий вызов `ZSTD_decompressStream` перезаписывает данные.
    - **Фикс**: вернулись к двум независимым путям. `_decompressStream` потребляет chunk'и сразу в `for await` без буферизации. `_decompressBlocks` использует `AsyncBlockDecompressorReader.read(n)` — работает с независимыми 16KB блоками, там нет этой проблемы.
    - **Дополнительно**: добавлен `FakeSection` при `sections[0].offset > 0x4000` (совместимость с Python nsz). Пофикшен race condition в CLI — `close` listener теперь регистрируется сразу после `spawn`.
    - **Benchmark**: копия при push в WASM давала ~10ms на 221MB (0.03%) — не проблема производительности, а корректности.

- ✅ **AsyncBlockDecompressorReader ~30% faster — sequential block iteration** — `fs/ncz.js`. Removed per-read `position & (blockSize - 1)`, `getBlock()` cache lookup and `sliceBytes(block, blockOffset, …)` in favour of simple `nextBlock()` + consume-from-front pattern. Benchmarked on a generated block-mode NSZ (`NCZBLOCK` magic, 658 MB → 1.56 GB, 3 warm runs): OLD position-aware 0.11/0.08/0.12 s, NEW sequential 0.07/0.07/0.07 s → ~30% faster. On streaming NSZ the reader is not exercised, so refactor is a no-op there (~0.08 s both).

- ❌ **Pipeline overlap: prefetch + async write** — `fs/ncz.js`, `crypto/zstddec-stream-wrapper.js`. Тестировали перекрытие записи/чтения с декомпрессией в обоих режимах:
    - **Block mode** (`_decompressBlocks`): prefetch следующего блока — `nextBlock()` в фоне пока текущий блок проходит AES + write. Без изменений — block reader уже prefetch'ит следующий блок при consumption текущего.
    - **Streaming mode** (`_decompressStream`): prefetch compressed read в `decodeStream` — `nextRead = readChunk()` до yield, I/O перекрывается с `processChunk` (AES + write).
    - **Pending writes**: `pendingWrite` паттерн — ждать завершения предыдущей записи перед стартом следующей. Без изменений в скорости — write и так моментальный (буферизуется на уровне ОС/браузера).
    - **Замер**: 1.56GB NSZ (Little Nightmares II, SW streaming): 34.8 MB/s (с prefetch) vs 35.0 MB/s (без) — в пределах погрешности.
    - **Root cause**: WASM `ZSTD_decompressStream` — синхронный, блокирует event loop. Пока WASM работает, никакой I/O overlap невозможен. Write буферизуется на уровне ОС (CLI), FSA writable (браузер) или SW — моментально возвращает промис.
    - **Аналогия**: Python nsz использует тот же sync pipeline — декомпрессия и обработка в одном потоке.
    - **Потенциал**: Web Worker + SharedArrayBuffer дали бы ~33% ускорение (параллельная декомпрессия + AES/write), но требует cross-origin isolation заголовков (COOP/COEP) и значительной переработки архитектуры. Пока оставляем как есть.

## Memory Optimization

- ❌ **Reduce READ_CHUNK_SIZE** — `fs/ncz.js:52` uses 16MB. **Keeping as-is** — matches Python nsz `SolidCompressor.CHUNK_SZ = 0x1000000`.

- ❌ **Delete _decompressBuffered for memory savings** — Attempted to eliminate full NCA buffer allocation in memory path. **Not possible** — blob-requirement needs full buffer for `new Blob([data])`.



## Info

- ❌ **accumulatedBytes not updated on error** — `main.js:449`. `accumulatedBytes += file.size` is only on success path. Not a bug: progress bar reaches 100% via `updateProgress(1)` at end. Error files are removed, shouldn't count toward progress. Best practice: only count successfully processed bytes.

- ❌ **NCAHeader.parse offset parameter** — `fs/nca.js`. Wanted to add offset parameter like Python nsz `struct.unpack_from(data, offset)` to avoid `buffer.slice()` copies and read NCA headers from any position in a larger buffer. But NCA header uses fixed absolute offsets (0x200, 0x204, 0x208...), and DataView offset shifts all reads — so offset=0x200 would make `view.getUint8(0x204)` read from 0x404. Can't use relative offsets without subtracting offset from every read, which defeats the purpose.

- ✅ **NCAHeader.parse: match Python nsz style** — `fs/nca.js`. Used `buffer.slice()` for byte arrays (like Python `data[start:end]`) and `buffer[i]` for magic bytes. Scalar reads use DataView (like Python `struct.unpack_from`). Consistent with Python nsz patterns.

- ❌ **NCAHeader.parse dead fields** — `fs/nca.js`. 18 fields returned, only 4 used downstream (`sections[0].offset/size/cryptoKey/cryptoCounter` + `masterKey` in error log). 14 fields never read. **Keeping as-is** — matches Python nsz `NcaHeader` which parses all fields (needed for write path, printInfo, key management). Our JS is read-only decompressor, but fields kept for parity.

- ❌ **SW download behavior**: Wanted the same UX as FSA mode: first show a folder picker, then download to the chosen location. This is impossible with SW — SW always saves to browser Downloads folder. Save As dialog is controlled by browser settings, not by SW code — no API exists to show it programmatically. [Chrome setting: chrome://settings/downloads → "Ask where to save each file before downloading"](chrome://settings/downloads).

- ✅ **Lazy SW registration on first use in convert handler (`main.js`)** — SW no longer registers at DOMContentLoaded. Registration happens only when convert is triggered in SW or FSA mode, guarded by `window._swRegistered` flag.

- ❌ **_decompressStream gap for first section** — Bug report claimed `_decompressStream` doesn't account for gap between `UNCOMPRESSABLE_HEADER_SIZE` (0x4000) and first real section. **Not a bug**: `getSections()` inserts FakeSection when `sections[0].offset > UNCOMPRESSABLE_HEADER_SIZE`. Python nsz's raw offset arithmetic is equivalent.
