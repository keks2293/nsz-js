 # NSZ to NSP Converter - Status Report

   ## ✅ Recent Changes (2026-08-16)

0. **`--update` output member order now matches yanu (Program → Manual → Control → CNMT)** — `fs/update.js`, `DOC-REPACK.md`. Root cause analysis: yanu does NOT sort NSP members at all — `Nsp::pack()` delegates to hacpack `pfs0_build()` (`pfs0.c:65`), which enumerates the NCA directory with `readdir()` without sorting, so member order = directory entry order = the processing order of `update_nsp()` (Control moved first, then packed Program, then meta CNMT; Manual/PublicData are copied in and land right after the Program NCA — "attached" to it). We reproduce the observed reference order (verified: yanu/StormX reference = Program `8dc3f778…` → Manual `99636bbd…` → Control `af613c75…` → CNMT `ee048d85…`; ours = `01f0e396…` → `99636bbd…` → `af613c75…` → `7107f145…`) by: Program first, remaining non-meta update NCAs sorted by name (Manual `99636bbd…` < Control `af613c75…`, which is why the manual lands right after Program), CNMT last. Manual/Control are the same physical NCAs as in the update (identical contentIds). Documented in `DOC-REPACK.md` → "Member order (yanu NSP sorting)".

   ## ✅ Recent Changes (2026-08-14)

0. **Perf: `--update` BKTR merge — streaming NCA pack, no output buffering** — `fs/nca-pack.js`, `fs/update.js`. Previously buffered full Program NCA (~699MB) in memory after BKTR merge. Now: `packPlaintextProgramNcaStreaming()` writes NCA directly to output adapter with SHA256 hash computed incrementally. Integration: PFS0 header built with placeholders first → Program NCA streamed at its PFS0 offset → CNMT built with hash → final PFS0 header written at offset 0 (seek-back). Memory: ~2GB → ~1.2GB (40% reduction for BKTR merge path). Verified: byte-identical output `01f0e396...` / 701767968 bytes.

1. **Perf: `--update` BKTR merge — selective NCZ decompression** — `fs/update.js`. Previously fully decompressed both Program NCAs into memory. Now: reads only needed sections via streaming NCZ decompression:
     - Base: loads only RomFS section, skips ExeFS (BKTR merge doesn't need base ExeFS).
     - Update: loads BKTR section + ExeFS section.
     - `extractNcaSection()`: streams NCZ decompression, buffers only the requested [offset, size] range via selective writeChunk callback.
     - `buildSparseNcaBuffer()`: assembles minimal NCA buffer (header + needed sections at correct offsets, zeros between) so `mergeRomFS()`/`extractExefs()` work with original offset expectations.
     - Verified: Stardew Valley BKTR merge, output byte-identical `01f0e396...` / 701767968 bytes (`scripts/test_update_e2e.mjs`).

2. **Fix: IVFC hash tree — zero-pad the final partial block before hashing** — `fs/nca-pack.js` `buildIvfcHashTree`. The last data block (shorter than 0x4000) was hashed without padding, so `lvl4[37011]` was wrong → the whole level-0..4 chain diverged from the real update → emulators rejected the merged Program NCA. Nintendo (and yanu) hash a full blockSize, zero-filled after the real bytes. Confirmed byte-identical: stored update `lvl4[37011]` = `sha256(pad4000(final block))` = `40baee67…` (unpadded = `df07e695…` ≠), and yanu output's stored hash = padded hash too (`f04eec97…`). NOTE: hacPack's `ivfc_create_level` (ivfc.c) itself feeds only read bytes to `sha_update`; the packer must zero-pad to a 0x4000 multiple before hashing — we do it inline in `buildIvfcHashTree`.
   - After fix, E2E output is hash-identical to the real update: `lvl4` 37012 real hashes + zero tail = 37376 total, `lvl3` 73/512, `lvl2`/`lvl1`/`lvl0` 1/512 each, and `master hash = sha256(lvl0) = 156d4a09…` == update's stored master hash (verified by `scripts/verify_ivfc_output.mjs <nsp> [expectedMasterHash]`: ALL CHECKS PASS). Program NCA contentId `01f0e396…`, E2E EXIT=0.
   - The 4-byte RomFS difference vs yanu (606,401,864 vs 606,401,860) is **not** a filename difference — both file tables end with `manifest.txt` (full 12-byte name, name_size=12) pointing at an identical blob (offset 0x24202050, size 118257). Verified with `scripts/analyze_romfs.mjs` + `scripts/diff_romfs.mjs`: all 3,554 file entries, every blob size, and all table sizes are identical. **Root cause found**: the gap between the blob area and `dir_hash_table_ofs` contains real data — a ~512-byte tail of `manifest.txt` (its blob is truncated; the file list continues `joja_furnitureFront.xnb`, `junimo_furniture.xnb`… in the gap) — identical in both, followed by zero padding. Nintendo aligns `dir_hash_table_ofs` to **8** (0x2421f048, data ends 0x2421f040 → 7 pad bytes); hacPack `romfs_build()` aligns to **4** (0x2421f044 → 3 pad bytes). Deleting our 4 pad bytes `[dirHashTableOfs-4, dirHashTableOfs)` and subtracting 4 from the header offsets reproduces yanu byte-for-byte. Our output is byte-for-byte the original update (verified: `our[A+4+k] == yanu[A+k]` for the whole shifted region). Not a hash/crypt type issue — fs/hash/crypt types are identical to yanu (sec[0]: ver=2 fsType=1 hashType=2 cryptType=1; sec[1]: ver=2 fsType=0 hashType=3 cryptType=1).

3. **Fix: BKTR merge output size — use the IVFC level-5 data region, not the whole virtual section** — `fs/bktr-merge.js`, `fs/update.js`. Previously `mergedSize = relocBlock.totalSize` (607,663,616 B = IVFC header + hash levels 0-4 + level-5 data + 184-byte tail), so the merged RomFS passed to `packPlaintextProgramNca` was +1,261,756 B too big. hactool/hac2l take only `ivfc_levels[IVFC_MAX_LEVEL-1].data_offset`/`.hash_data_size` (hactool nca.c:1240). Now:
    - `mergeRomFS` parses the IVFC superblock from the update FsHeader (BKTR superblock = ivfc_header @ FsHeader+0x8; level_headers[6] @ +0x10, 0x18 each) and reads level-5 `logical_offset` (0x134000) + `hash_data_size` (0x2424f548 = 606,401,864).
    - `merged` is still built at full `relocBlock.totalSize` — required so level-4's last 0x4000 hash block (which covers the trailing 184-byte virtual-image tail) verifies against the stored hash. Level-4→level-5 chain now fully verifies: 37,373/37,373 blocks match.
    - Return value now has `merged` (full virtual image, for verification) and `mergedData = merged.subarray(dataLevelOffset, dataLevelOffset + dataLevelSize)` (level-5 data only = the RomFS blob). `fs/update.js` uses `mergeResult.mergedData`.
    - `mergedData` parses as a valid RomFS: romfs_header (u64 fields, per hacpack romfs.h), tables walk exactly to `fileMeta_end == mergedData.length`, last entry = `manifest.txt`. Size = 606,401,864 = update's declared IVFC l5 size. yanu's rebuilt RomFS is 606,401,860 (4 B smaller) — a re-pack artifact of hacPack `romfs_build()` rebuilding tables from extracted files, not a bug in our merge.
    - Added source-reference comments in `bktr-merge.js`/`update.js` (hactool nca.c:1240, yanu unpack_all via hac2l `--basenca ... --romfsdir`, hacPack romfs.c `romfs_build`/`romfs_get_hash_table_count`/`file_table_size`).
    - Persisted `scripts/bktr_verify_merged.mjs` (logs mergedData size; needs real titlekeys). Verified with `scripts/bktr_compare_merge.mjs` and `scripts/tmp_walk.mjs`.

4. **Fix: `extractTitlekeyFromTik` rejected scene "dummy" tickets — now matches yanu** — `fs/bktr.js`. The function read the rights_id at tik offset `0x10` (garbage/all-FF for scene tickets) and rejected tickets whose magic/rightsId looked dummy, so both base and update titlekeys were unavailable (`BKTR: cannot get update titlekey`) and `--update` failed on scene dumps. yanu's `TitleKey::try_new` (yanu_ticket.rs:32-72) reads rights_id at `0x2A0` and the titlekek-encrypted key at `0x180` with NO validation — scene tickets (sigType 0x10004, all-0xFF signature, dummy rightsId@0x10) still carry a real rightsId@0x2A0 (== NCA header rightsId@0x230) and a real key@0x180. Fixed to match: check expectedRightsId against tik `0x2A0`, drop magic/all-FF rejection. E2E now passes: `Merged RomFS: 606401864 bytes`, EXIT=0.

 ## ✅ Recent Changes (2026-08-13)

0. **Fix: BKTR titlekey lookup — titlekeys database support + key_area offset fix + tik validation** — `fs/bktr.js`, `fs/bktr-merge.js`. Three bugs blocked BKTR table decryption for has_rights_id=true NCAs (update NCAs with Rights ID crypto):
   - **Wrong key area offset in deriveTitlekeyFromKeyArea**: read decHeader[0x100:0x300] instead of correct key area at [0x300:0x340], returning garbage bytes. Fixed to read from correct offset and validate key isn't all-same (encrypted key area marker).
   - **No titlekeys database support**: for has_rights_id=true NCAs, the key area contains encrypted keys (not usable titlekeys), so titlekey must come from tik file or titlekeys database. Tik files in most NSPs are dummy/placeholder files. Added `loadTitlekeysFile(path)` (format: `rights_id = titlekey`, one per line) and `lookupTitlekeyFromDatabase(rightsId, map)`. Updated mergeRomFS to accept `titlekeysFile` option and try titlekeys database before tik/key_area. Usage: `mergeRomFS(base, update, { keys, titlekeysFile: './title.keys' })`. This is required for any BKTR update NCA with has_rights_id=true where tik is unavailable/dummy.
   - **Silent use of garbage tik titlekeys**: `extractTitlekeyFromTik` blindly decrypted tik[0x180:0x190] without validating the tik file, returning garbage "titlekey" for dummy tik files (magic=garbage, rights_id=all-F's). Added tik validation: checks magic != all-zeros/garbage, rights_id != all-same byte, and optional expectedRightsId match. mergeRomFS now passes expectedRightsId to ensure tik matches the NCA. Clear error message when titlekey unavailable.
   - Updated FsHeader counter investigation: FsHeader.aes_ctr_upper_iv is ALL ZEROS for Stardew Valley update NCA, so counter fix produced no change. RomFS difference vs yanu remains at 1.26 MB.

1. **Fix: BKTR merge counter construction — match Stratosphere AesCtrCounterExtendedStorage** — `fs/bktr.js`, `fs/bktr-merge.js`. Counter was wrong in `decryptPatchRegion`: used reversed FsHeader `section_ctr` for ctr[0:8], ctr[4:8] = ctrVal BE. Stratosphere counter (from `fssystem_aes_ctr_counter_extended_storage.cpp` + `MakeIv`): ctr[0:4] = FsHeader.secure_value BE (FsHeader[0x144:0x148], u32 LE → BE), ctr[4:8] = subEntry.ctrVal BE (generation from BKTR entry, u32 LE → BE), ctr[8:16] = fileOffset/16 BE. Changed `decryptPatchRegion` signature from `(ncaData, titlekey, sectionCtrRev, subEntry, fileOffset, size)` to `(ncaData, titlekey, secureValue, subEntry, fileOffset, size)`. FsHeader.aes_ctr_upper_iv is ALL ZEROS for Stardew Valley update NCA, so counter fix produced no change. RomFS difference vs yanu remains at 1.26 MB. Root cause likely in BKTR merge logic itself (table parsing, relocation application). See `DOC-REPACK.md`.

1. **Doc: hac2l/hacPack algorithm comparison added to `DOC-REPACK.md`** — Added sections "External Tools Overview" (hac2l extraction-only via Stratosphere, hacPack repacking algorithm from `nca.c`), "Comparison: hacPack vs nsz-js" (field-by-field tables for NCA header, IVFC, PFS0, key area, header/section encryption, padding), "Key differences / missing features" (ACID sig skipped, BKTR divergence source of 1.26 MB RomFS difference). Cloned references: `sources/hac2l` (Atmosphere-NX/hac2l, 27 commits), `sources/hacPack` (XITRIX/hacPack). Added `sources/` to `.gitignore`.

1. **Fix: `--update` merged Program NCA layout — match yanu section order + cryptoTypes** — `fs/nca-pack.js`. The merged Program NCA had sections in wrong order (ExeFS first, RomFS second), wrong cryptoTypes (both=1/None), and unencrypted header (cryptoType=0). Emulators require: RomFS at lowest mediaOffset, ExeFS at higher offset; ExeFS cryptoType=3 (AesCtr), RomFS cryptoType=4 (BKTR/IVFC); header cryptoType=2 (AesXts encrypted, masterKey=1). Added `buildIvfcHashTree(data)` — 6-level IVFC hash tree (64KB blocks, SHA-256 each level, 0xE0 header with master hash), matching hacPack layout. `packPlaintextProgramNca` rebuilt: RomFS section placed at NCA_HEADER_SIZE (0xC00) with IVFC tree + data, ExeFS placed after RomFS; FsHeader cryptoType=3/4; header cryptoType=2, keyIndex=1, keyArea=key_area_key_application_0a slot 2; section hashes at 0x280/0x2A0; header double-encrypted (hashes written, then size written). `fs/update.js` removed Control extraction (yanu doesn't use it). Output: 702 MB / 8 members, CNMT hash matches merged NCA, all tests pass.

1. **Fix: `--update` in browser crashes with "Buffer is not defined"** — `fs/bktr.js`, `fs/bktr-merge.js`. Used Node-only `Buffer.from(x, 'hex')` for hex key parsing (header_key, titlekek_02, tikData). Added `hexToBytes(hex)` helper (Uint8Array, no Buffer) in both files; replaced `Buffer.from(titlekek, 'hex')`, `Buffer.from(tikData.subarray(...))`, `Buffer.from(keys.header_key, 'hex')`. Now works in browser HTML UI and Node CLI.

2. **Doc: clarify yanu/hac2l pipeline vs our implementation** — `DOC-REPACK.md`. Added detailed section "What exactly is a yanu-style update?" explaining that yanu is purely an orchestrator calling external tools: hac2l with `--basenca` (for BKTR merge via Stratosphere's StorageOnNca::CreateWithPatchWithContext), hacpack for NCA/NSP packing. Documented that our manual BKTR implementation (`fs/bktr-merge.js`, `fs/bktr.js`) diverges from yanu's Stratosphere-based BKTR merge (our RomFS ~1.26 MB larger on Stardew Valley), though both produce valid installable NCAs. Updated source code references table with direct links to yanu/hac2l/hacpack/Stratosphere source files. Added current difference metrics table (merged NCA size, RomFS size, ExeFS size, CNMT hash).

1. **Fix: `--update` hung silently (exit 0, no output) on scene "multi-section" NSZs** — two interacting bugs:
   - **RangeError in BKTR-check `writeChunk`** — `fs/update.js`. The update Program NCZ's decompressed stream emits chunks at offsets `>= 0xC00` (decompOffset starts at `0x4000`), so `rawHeader.set(chunk.subarray(0, end - offset), offset)` computed `end - offset < 0` → empty subarray → `.set(∅, offset)` out-of-bounds throw on the very first chunk.
   - **Silent-deadlock propagation** — `crypto/zstd.js` `decompressNodeStream`. When the consumer threw, the async-generator's `finally { await feed }` ran while `feed` was blocked on `'drain'` (nobody consumed the readable side anymore) → deadlock; with `main().catch(...)` (no top-level `await`) the event loop drained and the process exited **0 silently** with no error.
   - Fixes: guard `writeChunk` with `if (offset >= headerSize) return;` (capture only the header region); `decompressNodeStream` now makes the `'drain'` wait resolve on stream `'close'`/`'error'`, aborts the feed and destroys the decompressor when the consumer exits early, and propagates feed errors. Consumer errors now surface loudly instead of hanging.
   - Root cause of the hang verified on the real **Stardew Valley v1310720 update NSZ**: its program NCZ has `NCZSECTN` table with **633 sections but a single giant zstd frame** (~570 MB compressed → 700,338,688 B decompressed, exactly `ncaSize - 0x4000`). Node's `createZstdDecompress` emits output incrementally for partial frames (verified), so the streaming path handles it — it was only ever the writeChunk crash + finally-deadlock that killed it.
   - Result: `--update base.nsz update.nsz` now completes end-to-end on the real files: BKTR check decompresses the 633-section NCZ, RomFS merged (607,663,616 B, 373 reloc entries, 631 subsection entries), ExeFS 91,409,120 B, merged Program NCA 699,174,112 B (`43587665…`), rebuilt CNMT NCA `5fea1424…`, output 701,825,632 B / 8 members — identical output via CLI and `test_update_e2e.mjs`. Output CNMT parses (base TID, v1310720, 3 contents matching shipped NCAs), merged program NCA header decrypts with sections ExeFS 87.2 MB / RomFS 579.5 MB (cryptoType 0 per BKTR design). All tests pass: `test_vector.mjs`, `test_aesctr.mjs`, `test_merge_ncz.mjs`, `test_update_e2e.mjs`.
   - New persisted verifier: `verify_updated_output.mjs <output.nsp> [yanu.nsp]` — member-wise compare vs a reference NSP plus merged-program-NCA header/CNMT validation.

 ## ✅ Recent Changes (2026-08-10)

0. **Fix: `--update` BKTR output was NOT emulator-installable (CNMT/program mismatch) — now yanu-consistent** — `fs/update.js`. The BKTR path packed a merged Program NCA but rebuilt the CNMT FIRST, so the CNMT's program content entry still referenced the update Program NCA (`d11817ae…`, 700 MB) while the NSP shipped the merged NCA (638 MB) under the base program's filename. No file matched the CNMT program entry → emulators would report missing/corrupt program content. Fix (matches hacpack/yanu): build the merged Program NCA **before** the CNMT; the rebuilt CNMT's program content entry now references the merged NCA's **own** sha256/contentId/size, and the shipped file is named `<contentId>.nca` (`4bfacc59…nca` for Stardew Valley). `rebuildCnmtNca` gained a `mergedProgram` override param for the type-1 entry; tik/cert collection was hoisted into a pre-pass (titlekeys needed by the merge before member assembly). Verified on Stardew Valley v0+v1310720: **both** modes are hash-consistent — `ALL CNMT ENTRIES MATCH SHIPPED NCAs`: BKTR (611.2 MB / 8 members: program `4bfacc59…` 638,285,294 B, manual, publicdata, cnmt, base/update tik/cert) and standard (703,006,592 B / 8 members, rebuilt CNMT sha256 `e0211867…` byte-identical to the previous verified output).

1. **Feature: `--update` in browser UI** — `index.html`, `main.js`, `converter.js`. New Update pill (exactly 2 files, keys required) wired to `updateNSPs(files)`. Output name `<base>_updated.nsp`, same flow as merge (FSA/SW/Blob). Memory-mode blob path validated via `update(readers, { memory: true })` returning `Blob` in Node with real fixtures (703,006,592 bytes, 8 members).

2. **Refactor: remove `rebuild` option entirely** — `main.js`, `converter.js`, `fs/merge.js`, `nsz-cli.js`, `index.html`. Rationale: rebuild (CNMT-based orphan filtering) is not present in any reference tool (julesontheroad/NSC_BUILDER, cxfcxf/nscb_rust, ReiKatari/STORM_SWITCH_BOX), and for real dumps rebuild and nodelta produce identical output since every NCA is CNMT-referenced. Removed CLI `-r/--rebuild`, browser "Rebuild" pill, `mergeNSP` `{ rebuild }` option, `rebuildNcaMap`/`rebuildTitleIds`/`rebuildAllCnmts` logic; only `nodelta` remains. `fs/update.js` retains its internal `rebuildCnmtNca()` function (unrelated).

3. **Fix: `--update` output installable in emulators — include the update ticket/cert and copy the base CNMT extended header verbatim** — `fs/update.js`. Two root causes for Ryujinx reporting «нет приложений» (no application found) on the updated NSP:
   - **Wrong ticket**: the output kept the update's Program NCA, whose header rightsId is the **update's** titlekey rightsId (`0100e65002bb8800…0003`, masterKey 2, titlekey-protected), but only the base `.tik`/`.cert` (`0100e65002bb8000…0003`) were packaged — no ticket matched the Program NCA, so the emulator couldn't decrypt it. Fix: include the `.tik`/`.cert` from **both** containers (dedup by filename), so `0100e65002bb8800…0003.tik`/`.cert` ship alongside the update Program NCA. The scene "fake" tickets (sigType `0x10004`, all-0xFF signature, zeroed titlekey block, rightsId at 0x2A0) decrypt the NCA via the commonKey-derived zero-block titlekey, exactly as they do for the base/update NSZs.
   - **Garbled CNMT extended header**: `rebuildCnmtNca` synthesized the ext header by reading the base CNMT's PatchId/RequiredSystemVersion bytes and *reversing* them (`0088bb020000010c0000000000000000` instead of the base's `0088bb0250e600010000010c00000000`), producing a bogus PatchId. Fix: copy the base Application CNMT's extended header bytes (0x10 at offset 0x20) verbatim; only the version field changes.
    - Result: **8 members** (base tik/cert + update tik/cert + rebuilt CNMT NCA + decompressed update Program/Control/Manual NCAs), 703,006,592 bytes. Verified: output PFS0 re-parses; rebuilt CNMT v1310720 with 3 entries and ext header byte-identical to base; update `.tik` rightsId at 0x2A0 == `0100e65002bb88000000000000000003` matches the Program NCA; sha256 of each output NCA matches its CNMT entry; `verify_update.mjs` ALL ORIGINAL FORMULAS MATCH.

4. **Feature: `--update` — physically apply an update to a base game into a single NSP** — new `fs/update.js`, wired as `nsz-cli.js --update <base> <update>`. Instead of merging base + update as two NCAs (877 MB + 667 MB), update rebuilds the base's `.cnmt.nca` so its Application CNMT (base titleId, update version) references the update's content NCAs as full replacements, then packages: rebuilt CNMT NCA + decompressed update program/manual/publicdata NCAs + base ticket/cert. Output for Stardew Valley v0+v1310720: **670.44 MB**, one patched program NCA (700 MB). Verified end-to-end: output PFS0 re-parses; CNMT re-decrypts (Application 0x80, base TID, version 1310720, 3 entries); sha256 of each output NCA exactly matches its CNMT content-entry hash; the rebuilt CNMT NCA passes a full decrypt→parse→re-encrypt round trip.

5. **NCA hash-formula research (recipe for rebuilding a CNMT NCA byte-exact)** — reverse-engineered against real NCAs and validated in the repo verifier `verify_update.mjs <base.nsz> <update.nsz> [keys.txt]` (all formula checks + a full rebuild round trip; produces the same rebuilt-NCA sha256 as the CLI, e.g. `4f6e7da8…` for Stardew Valley):
   - `sectionHash`/`hblock` @0x280 = `sha256(decrypted header[0x400:0x600])` — MATCH on base CNMT, update CNMT and program NCAs (formula matches NSC_BUILDER `Nca.py:273 calculate_hblock_hash`).
   - `htable_hash` @0x408 = `sha256(decrypted media[0 : htableSize])`, where htable is the leading region of the media section holding the per-block hashes (NSC_BUILDER `Nca.py:442 calc_htable_hash`).
   - Per-block `htable[i]` = `sha256(decrypted media[pfs0Offset + i*0x1000 : min(pfs0Offset + (i+1)*0x1000, pfs0Offset + pfs0Size)])` — **truncated at the pfs0Size end, NO zero padding** (this was the last open piece; earlier assumption of padding to a 0x1000 block was wrong). Confirmed on both the base (1 block) and update (2 blocks) CNMT NCAs.
    - `0x000`/`0x100` are RSA-2048 signatures (`rsa_sig_1`/`rsa_sig_2`, per pyNCA3.py), not hashes — kept as-is when rebuilding.
    - CNMT trailing 0x20 = dev-only `ContentMetaDigest` (sha256 of the CNMT minus its digest); Switch doesn't validate it.

6. **Crypto: `AesXts.encrypt` added** — `crypto/aes128.js` (pure-JS, mirror of `decrypt` with `_encData` in place of `_decData`) and `crypto/aes-ops.mjs` `createAesXts` (Node fast path adds an `aes-128-ecb` encrypt cipher). Required to re-encrypt the NCA header after patching the hblock/htable hashes.

7. **Feature: BKTR RomFS merge (yanu-style update) — `fs/bktr-merge.js`, `fs/nca-pack.js`** — Full hac2l-style pipeline implemented per `SciresM/hactool` (`nca.c`, `bktr.h`):
    - **BKTR tables**: parse/decrypt relocation + subsection tables from update NCA FsHeader extension (offsets 0x100/0x120, magic "BKTR") using AES-CTR(titlekey, section_ctr reversed + file_offset/16 BE)
    - **AesCtrEx**: patch region decrypt with counter[0:4]=section_ctr[0:4], counter[4:8]=ctrVal BE, counter[8:16]=block_index BE per `nca_update_bktr_ctr`; handles subsection entry boundaries within patches
    - **Full NSP output**: extract ExeFS PFS0 from update NCA (PFS0 at sectionStart after IVFC), merge RomFS via BKTR, pack plaintext Program NCA (AesXts header, cryptoType=0), wrap in NSP PFS0 with tik
    - **Titlekey fix**: extract from tik via AES-ECB(titlekek_02, tik[0x180:0x190]) — `decryptNcaHeader` returns wrong key for rightsId-protected NCAs with zeroed keyBlock
    - Verified on Stardew Valley v0+v1310720: NSP 699.1 MB (699,076,640 bytes), ExeFS PFS0 parses correctly (main: 85.2 MB, main.npdm: 1.6 KB, rtld: 10 KB, sdk: 6.2 MB), RomFS contains XNBS/MonoGame/Stardew patterns matching yanu offsets within IVFC hash table offset. `extractExefs(ncaData, keys, tikData)` now accepts tik for titlekey-protected NCAs. Note: yanu's merged NCA uses dummy cryptoKey 0x04 for sections (not functionally valid), so our properly decrypted output is more correct; pattern offsets differ by IVFC header size (~224 bytes).

## ✅ Recent Changes (2026-08-09)

1. **Fix: `rebuild` must keep ALL CNMT-referenced NCAs (base + update + DLC programs)** — `fs/merge.js`. Previous logic picked only the "latest CNMT" (PATCH > BASE) per base title and used only its ncaIds, which DROPPED the base program NCA. On emulator that yields a broken NSP ("нет приложения" / no application found) — the base program IS the application. Matched the actual NSC_BUILDER `rebuild()` (py/ztools/Fs/Nsp.py:5863): it iterates every META NCA and keeps every content entry whose ncaId exists in the input, excluding only delta fragments (type 6). New logic: collect ncaIds referenced by ANY CNMT across all inputs (deduped), exclude type-6 fragments into the same delta set, keep all `.cnmt.nca` files, and keep `.tik`/`.cert` only when their 16-hex titleId prefix matches a CNMT's titleId (this also prevents keeping duplicate/cross-title tickets). `.cnmt.xml` files remain excluded. Tested on Stardew Valley base (v0) + update (v1310720) NSZs: output now 1.51 GB / 12 members — base program 877.63 MB, base manual/publicdata/CNMT/tik/cert, update program 667.91 MB, update manual/publicdata/CNMT/tik/cert — matching NSC_BUILDER multi-content rebuild output. The 627 MB result of the old logic is confirmed broken (missing application).

2. **Feature: `nodelta` — exclude delta-fragment NCAs on merge (opt-in, like nscb_rust)** — `fs/merge.js`, `nsz-cli.js`, `converter.js`, `index.html`, `main.js`. `mergeNSP` takes new option `{ nodelta = false }`; when enabled + keys present, each input's `.cnmt.nca` files are parsed and members whose ncaId appears as a `DeltaFragment` (ContentInfo `type === 6`) are dropped from the merged output with an `[nodelta]` log line. Default is OFF — matching cxfcxf/nscb_rust (`cli.rs:115` clap bool, no default; there it's also currently a no-op since `is_delta` is hardcoded `false`, unlike ours which really detects via CNMT type 6). Detection requires keys (the CNMT is key-encrypted), so `--nodelta` without keys is a hard error like `--latest` (`mergeNSP: nodelta requires keys` / CLI `Error: --nodelta requires a keys file`, exit 1). Implementation: per-input CNMT scan in the merge loop, delta ncaIds collected into a Set, then filtered before member addition. CLI: `-n, --nodelta`; plain `--merge` needs no keys (name dedup, NCZ decompression) as before. Browser: new "No Deltas" pill in Merge mode, off by default, threaded through `converter.mergeNSPs` → `mergeNSP`. Tests: `buildCnmt` accepts entries as strings or `{ id, type }`; new cases — update NSP whose CNMT references a type-6 fragment and ships the file: kept by default, dropped with `nodelta:true` + keys, and `nodelta:true` without keys throws. Note (from survey): scene releases strip the fragment files, so on them this is a no-op; it matters for un-stripped eShop delta updates.

## ✅ Recent Changes (2026-08-08)

1. **Refactor: move AES-CTR backend selection into `crypto/aes-ops.mjs`** — new `crypto/platform.js` is the single source of truth for `isNode`. `crypto/aes-ops.mjs` now defines `aesBackend()` (`NSZ_AES_CTR_BACKEND` env override, Node only) and imports `isNode` from `platform.js` instead of re-detecting `process`; `fs/ncz.js` imports `aesBackend()` from `aes-ops.mjs` instead of defining its own copy (it keeps its local `isNode` until the follow-up zstd refactor removes it). No behavior change; `test_merge_ncz.mjs` passes.

2. **Perf: cache the `node:zlib` import** — `fs/ncz.js`. Node zstd decompression previously did `await import('node:zlib')` on every call — per-chunk during streaming, per-block in NCZBLOCK. A module-scope `nodeZlibPromise = import('node:zlib')` is now resolved once and reused inline in the NCZBLOCK block path. New `bench_nczblock.mjs`: in-memory NCZBLOCK pipeline benchmark (output discarded, best-of-5). `bench_nczblock.mjs` (best-of-5): ~1597 → ~2375 MB/s. Behavior identical; `test_merge_ncz.mjs` passes.

3. **Perf + refactor: zstd platform dispatch, flat NCZBLOCK schedule** — `crypto/zstd.js` now hosts all zstd seams: `decompressStream(readChunk)` async-generator for streaming (node:zlib `createZstdDecompress` push/write + concurrent drain, or WASM `zstddec-stream-wrapper`) and `decompressBlock(data)` for single NCZBLOCK blocks (Node: cached `node:zlib.zstdDecompressSync`, browser: `ZstdDecompressor` WASM). `fs/ncz.js` no longer imports `node:zlib`/`zstddec-stream-wrapper.js` nor branches on `isNode` — both `decompressStream` and `decompressBlock` imported statically; local `isNode`/`nodeZlibPromise` removed. `parseBlockSchedule` returns flat parallel arrays (`sizes`, `relOffsets` — plain JS numbers, no 4 GiB truncation) plus `blockSize`/`remainder`; `AsyncBlockDecompressorReader.nextBlock` iterates by index, keeping the raw/incompressible decision (`compressedSize < decompressedSize`) as a synchronous inline check (no per-block microtask). Behavior identical; `test_merge_ncz.mjs` (streaming + NCZBLOCK) passes; `bench_nczblock.mjs` ~2300–2400 MB/s.

## ✅ Recent Changes (2026-08-06)

1. **Feature: compressed file support on merge (.nsz/.xcz inputs)** — `fs/merge.js`, `nsz-cli.js`, `converter.js`, `main.js`, `index.html`. `mergeNSP` now accepts compressed containers: PFS0 with `.ncz` members (NSZ) and XCIs with `.ncz` members (XCZ). `.ncz` members are decompressed to `.nca` on the fly during the copy phase (`NCZDecompressor` with `AdapterNCZReader`, both streaming-zstd and NCZBLOCK modes) — section AES keys are read from the NCZ headers, so no keys file is required (still accepted via `--keys`). Dedup is now by output filename (`foo.ncz` ↔ `foo.nca` collide, first input wins). Non-compressed `.ncz` (plain NCA with wrong extension) falls back to raw copy with a `warn`. CLI `--merge` accepts `.nsz`/`.xcz` extensions and passes keys through; browser merge mode accepts `.nsz`/`.xcz` files and output-name regex extended. New test `test_merge_ncz.mjs` (synthetic NSZ, streaming + NCZBLOCK, dedup-across-extension).

2. **Perf: single NCZ header parse per `.ncz` file** — `fs/merge.js`, `fs/nsz-convert.js`, `fs/xcz-convert.js`, `fs/ncz.js`. `parseNczSections` is now called once during member/file-meta collection and its result is passed to `NCZDecompressor.decompress()` via a new third `parsed` argument, skipping the redundant second parse that previously ran inside `decompress()`. Applied to all three consumers (merge, NSZ→NSP, XCZ→XCI) — previously every `.ncz` was parsed twice. `test_merge_ncz.mjs` (10 assertions) and CLI convert still pass.

3. **Perf: in-process zstd decompression on Node, no CLI subprocess per .ncz** — `fs/ncz.js`. The Node streaming path previously spawned a `zstd -d` CLI subprocess per `.ncz` member (reported as `[ZSTD] Using zstd CLI`); it now uses `zlib.createZstdDecompress()` from `node:zlib` (in-process, streaming, any window size, verified on Node v26.6.0). Browser path still uses `zstddec` WASM — untouched. Verified: 200MB synthetic NCZ decompresses byte-identical in ~144ms with no `zstd` child process; CLI convert and merge pass.

4. **Fix: AES-CTR section decrypt corrupted at unaligned chunk boundaries in streaming decompression** — `fs/ncz.js`. In `_decompressStream`, `lastAesCtr`/`lastDecryptEnd` were reset to null at the start of every `processChunk` call, forcing `AesCtr.seek(ncaPos)` on every zstd output chunk. When a chunk boundary landed at a non-16-aligned position, the freshly re-seeded Node CTR cipher restarted its keystream from the block start instead of continuing mid-block, corrupting decrypted output. Hoisted both variables into the enclosing scope so the stateful cipher continues seamlessly across chunk boundaries (seek only happens on section switch / discontinuity). Verified on the real Trackline Express NSZ (largest `.ncz` 107.5 MB → 221.8 MB NCA, 3 sections incl. two AES-CTR): before the fix output had 12883 wrong bytes vs a `zstdDecompressSync` + one-shot AES-CTR reference; after the fix it is byte-identical. Browser webcrypto path shares `processChunk`; it still starts keystream at block starts for mid-block chunk boundaries (pre-existing latent issue, unchanged).

5. **Tests: high-entropy streaming + AES-CTR section in `test_merge_ncz.mjs`** — added a streaming NCZ whose payload is 12.5 MB of random bytes (exercises the write-backpressure path on incompressible data; regresses against any re-entrant `drain` writer) and a two-section NCZ with a `cryptoType=3` AES-CTR section (verifies section decrypt through the full `mergeNSP` path). Also gave the fixture-compression `execFileSync` calls a `maxBuffer` (default 1 MB was killing `zstd` with SIGTERM on the large random payload). Test count 10 → 15, all pass; `test_vector.mjs` PASS; build OK.

6. **Tests: drop the `zstd` CLI dependency from `test_merge_ncz.mjs`** — test fixtures are now compressed in-process with `zlib.zstdCompressSync` instead of spawning the `zstd` CLI; the `hasZstd` skip block and all `execFileSync`/`spawnSync` calls are removed. The whole test suite now runs with only Node ≥ 22.11 (no system zstd binary required anywhere). Note: Node's `zstdCompressSync` ignores the `level` option (always ~level-3 ratio, verified 363 B output for levels 1–22) — fine for decompression fixtures. Benchmark (50 MB real data): level 3 — CLI 73–82 ms vs node:zlib 121–125 ms; level 19 — CLI 5997–6498 ms → 12.7 MB vs node:zlib 120 ms → 15.7 MB (level ignored).

7. **Tests: make the AES-CTR continuity regression test actually catch the bug** — `test_merge_ncz.mjs`. The previous `cryptoType=3` section (32 KB patterned bytes) compressed to a single zstd chunk, so no chunk boundary ever landed inside the section and the pre-fix code passed. The section is now ~16 MB (`0x1000001`) of random bytes, deliberately not a multiple of 16: with the 16 MB input-feeding pattern, node's streaming zstd emits at least one output chunk starting at a non-16-aligned position inside the section, forcing the old `seek()`-at-every-chunk cipher to produce a shifted keystream. Verified on the pre-fix commit `a7fd4a5`: 788 wrong bytes, test FAILS; on the fix: byte-identical, PASSES. Test count 15 → 16.

8. **Refactor: remove dead `keys` parameter from NSZ/merge decompression paths** — `fs/ncz.js`, `fs/merge.js`, `fs/nsz-convert.js`, `fs/xcz-convert.js`, `nsz-cli.js`, `converter.js`, `test-ncz.mjs`, `test_merge_ncz.mjs`. `NCZDecompressor` stored `this.keys` but never read it — section AES keys come from the NCZ headers, so a keys file was never needed for `.ncz` decryption. Dropped the parameter from `NCZDecompressor`, from `convertNSZ`/`convertNSZStreaming`/`collectOutputMeta` (NSZ→NSP path), and from `mergeNSP` options (the CLI no longer loads keys for `--merge`). `keys` stays in the XCZ path (`buildPartitionMetas`) and in `split` (CNMT/XTS). CLI help/warning text updated to drop the misleading "encrypted NCZ decryption" claim.

9. **Refactor: drop remaining dead `keys` from the XCZ→XCI pipeline** — `fs/xcz-convert.js`, `nsz-cli.js`, `converter.js`. `keys` was threaded through `convertXCZ` → `convertXCZStreaming` → `buildPartitionMetas` → `writePartitions` but never dereferenced anywhere in the pipeline (the real consumer is the CLI's `extractCnmtHashMap` closure, which captures `keys` itself). Removed it from all four signatures and their call sites. The CLI `convertXCZ` wrapper keeps `keys` (used by `makeExtractCnmtHashMap` for `--verify`), as does `split`. Help/warning text refined: keys are required only for `--split`; for `convert --verify` they enable CNMT hash checks and are otherwise unused.

10. **Fix: AES-CTR keystream misalignment on mid-block chunk boundaries in browser (webcrypto / JS-fallback) paths** — `crypto/aes-ops.mjs`. The stateless decrypt paths (webcrypto and JS-fallback) generated keystream in whole 16-byte blocks and advanced the counter by `ceil(len/16)` blocks per call. When a decompressed zstd chunk boundary fell at a non-16-aligned position inside an AES-CTR section, the next chunk's keystream started at a block boundary while the data began mid-block, producing a shifted keystream and corrupted output (the same class of boundary that the Node path fix in #4 addressed). Now tracks absolute byte position (`_pos`) and, on a mid-block chunk start, pre-generates the full keystream block for the current counter and uses only the `[pos%16..15]` tail for the head, then block-aligned continuation. The Node stateful cipher path is unaffected (already correct). Added `backend` constructor override for testing. Regression coverage added in `test_merge_ncz.mjs`: (a) an AES-CTR section decrypted in `1000`-byte chunks (not a multiple of 16) on forced `js` and `webcrypto` backends must match a node reference; (b) a single cipher re-`seek()`ed to nonlocal offsets — forward jump, unaligned rewind, and a tail run into the next block — must reproduce byte-for-byte the keystream an independent node cipher yields for those absolute positions. All pass on Node (the pre-fix code corrupts data here); old code corrupts 16.7 MB of 16.8 MB with the first error at chunk boundary 1000. Test count 16 → 26. Aligned decrypts (the common browser case) now take a fast path in `encrypt()` that returns the cipher output directly without an intermediate `out` copy.

11. **Correction: `AesCtr.seek()` counter truncation note** — `crypto/aes-ops.mjs`. The earlier review note claimed truncation at >64 GB; verified empirically that the counter field is 8 bytes (64-bit, written bytes 15–8), supporting offsets up to 2^64 blocks ≈ 295 EiB (not 64 GB). JS number precision (`Math.floor(offset/16)`) is exact up to 2^53 bytes (~9 PB). No code change needed.

12. **Perf: allocation-free block ops in `crypto/aes128.js`** — `encryptBlock`/`decryptBlock` now take an optional `out` buffer and write in place (callers pass a reusable subarray, removing a `new Uint8Array(16)` per block). `AesCtrJS` writes the keystream directly into its merged output; `AesXts.decrypt` reuses one `xored` scratch buffer and performs in-place `gf128MulIn(tweak)` (was `gf128Mul(tweak) → new buffer`); the now-dead `xor`/`xorInto` helpers are removed. Verified byte-identical (`verify_clean.mjs` pattern: ECB, CtrJS, XTS across sizes/sectors, AesCtr integration) and via new `test_aes128.mjs` fixed vectors. Micro-bench (64 MiB, best-of-5): AES-XTS 69.5 → 102.3 MB/s (~+47%), software AES-CTR keystream 119.8 → 144.6 MB/s (~+21%).

13. **Perf: aligned fast path in `crypto/aes-ops.mjs` `encrypt()`** — when the chunk starts at a 16-aligned position, return the cipher output directly instead of copying into an intermediate `out` buffer + `set`. Advances `_pos` by the chunk length so mid-block bookkeeping stays correct. Functionally identical (byte-identical verify), removes the only remaining per-call copy on the aligned path (the common browser case).

14. **Docs+tooling: benchmark rule in `AGENTS.md` + persistent bench/verify scripts** — AGENTS.md now mandates: real-pipeline benchmarks on the real `.nsz` with output **discarded** (`/dev/null` writeChunk), micro-benchmarks in-memory (64 MiB, no disk), best-of-N ≥3 + MB/s (not single wall time), verify byte-identical before measuring, and persisting useful scripts (`bench_*.mjs`/`test_*.mjs`). New files: `test_aes128.mjs` (regression vectors + XTS streaming invariant), `bench_aes128.mjs` (in-memory micro-bench), `bench_real_nsz.mjs` (real `.nsz` decompress with dev-null output). Also added `NSZ_AES_CTR_BACKEND` env seam in `fs/ncz.js` (auto|node|webcrypto|js, default auto — no behavior change) to force the AES-CTR backend for benchmarking. Real-pipeline runs on Little Nightmares II (5.02 GiB NCZ, output discarded): Node/WebCrypto path ~684 MB/s (unaffected); **software js-fallback path ~101.6 → ~119.5 MB/s (≈+18% end-to-end)** — the real-file gain of the alloc-free AES-CTR rewrite (#12), close to the +21% micro-benchmark.

## ✅ Recent Changes (2026-08-05)

1. **Fix: split lost `.tik`/`.cert` for titles with `rightsId=0` (e.g. DLC)** — `fs/split.js`. Ticket lookup used only `rightsId` from NCA headers; DLC whose NCAs are unencrypted (PUBLICDATA, `rightsId=0`) still ship with a ticket/cert, but split silently dropped them. `collectTicketsByRightsId` → `collectTickets` now builds two indexes (`byRightsId`, `byTitleId`); attachment falls back to matching a ticket whose `titleId` (first 16 hex chars of `rightsId`) equals the CNMT title id. Protected titles with no matching ticket now emit a `warn` instead of silently omitting the ticket. Verified on Little Nightmares II merged NSP: DLC outputs went from 2 files (no ticket) to 4 files (`cnmt.nca`, `nca`, `.tik`, `.cert`). Matches nscb_rust's filename-prefix ticket matching; certs stay stem-matched (tighter than nscb_rust's all-certs-everywhere).

## ✅ Recent Changes (2026-08-02)

1. **Fix: CNMT `ContentEntry.type` offset** — `fs/cnmt.js`. Read at byte `54`/`0x36` per spec (was `53`); fixes meta/deltaFragment title filtering.

2. **Feature: full XCI (no-intro) support — read + write** — `fs/xci.js`, `fs/xcz-convert.js`. Read: root HFS0 located at `hfs0Offset + headOffset - 0x100` (0x10000 for full, 0xF000 for normal; matches nsz PR #148). Write: when input is full XCI (`headOffset=0x1100`), CardKeyArea is preserved — prefix `[0, 0x10000)` (InitialData + TitleKeyArea + CardHeader + CertArea) is copied verbatim, patched header written at `baseOffset=0x1000` (HEAD stays at `0x1100`), root HFS0 at `0x10000`. Round-trip full XCI ↔ XCZ keeps reversible layout; output NSP via merge is unaffected (CardKeyArea never read, offsets absolute from `0x10000`).

3. **UI: mode-specific options** — `main.js`. Fix Padding/Verify are shown only in Convert mode, Overwrite only in FSA download mode.

## ✅ Recent Changes (2026-08-01)

1. **Feature: NSP merge + split, XCI inputs** — new `fs/merge.js`, `fs/split.js`, CLI `--merge`/`--split`, browser mode switcher (Convert/Merge/Split). Merge: unions members of 2+ NSPs (base/update/DLC) with first-wins dedup by filename, also accepts `.xci` inputs — secure partition HFS0 read header-only via `XCIReader.getSecureFiles()`, `HEAD` probed at `0x100` with fallback to the backup header at `0x1000` (magic `0x1100`) for raw/full dumps. Split: parses CNMT per meta-NCA (XTS header + AES-CTR section decrypt + inner PFS0), groups NCAs by title, writes one `{titleId}_{base|update|dlc}_v{version}.nsp` per title with matching `.tik`/`.cert`. Fixed: ticket parse on pooled buffers (`.slice()`).

2. **Refactor: shared NCA decrypt + CNMT parse helpers** — `fs/nca.js`: `decryptNcaHeader`, `decryptNcaSection`, `parseCnmtFromDecryptedSection`, `readCnmtFromMeta` (+`isPfs0`). Inner PFS0 is located at the spec field `section.sectionStart` (FsHeader+`0x40`). `copyRange`/`COPY_CHUNK` moved to `fs/adapter.js`. `fs/ticket.js` now holds only the pure `Ticket` parser (throws on unknown `signatureType` instead of silently defaulting).

3. **CLI: mode hints in help** — `nsz-cli.js`: mode-specific options tagged `[convert]`/`[convert, split]` in `printUsage()`.

## ✅ Recent Changes (2026-07-29)

1. **Fix: PFS0Writer `fixPadding=true` double-padding bug** — `fs/pfs0.js`. `buildHeader()` had two bugs in the `fixPadding` branch: `namesLen` used `headerSize` (included dataOffset, should be total header minus dataOffset), and `headerSize` padded itself `inner + (0x20 - inner%0x20)` which would produce a self-inconsistent PFS0 where `totalHeaderSize != stringTableSize + dataOffset`. Fixed `namesLen` to use `this.metaSize + stringsLen` and `headerSize` to use `inner` unpadded. Verified: 3 test NSPs now byte-identical to Python nsz `--fix-padding` output.

## ✅ Recent Changes (2026-07-23)

1. **Fix: SW stream error detection + smarter registration** — `main.js:SWDownloader`, `download-worker.js`. SW потеря stream (iframe не загрузился, cancel, error) — данные терялись молча. **Фикс**: SW шлёт `{type: 'error', url, message}` при write без stream. `SWDownloader.#onSWMsg` ловит, ставит `#streamError`, `write()` кидает ошибку. Причины: `not-registered`, `cancelled`, `closed`, `error`. Баг с `.bind(this)` блокировал event loop — замена на arrow function. **Registration**: Старый подход — `register()` + `ready()` при каждом convert. Проблема: `register()` может зависнуть если SW в bad state (обновление в процессе, stale registration). Браузер блокируется на install/activate цикле. **Новый подход**: `getRegistration()` → если registration active — используем сразу (0ms), если installing/waiting — `unregister()` + `register()` заново, если нет registration — `register()` с нуля. Это устраняет зависания на Ctrl+R когда старый SW ещё活着. **Logging**: "Starting SW..." (getRegistration) → "SW active" (registration ready) → "Connecting to SW..." (dl.start() ждёт ready ответ) → "Stream ready" (iframe загрузился, stream активен).

## ✅ Recent Changes (2026-07-20)

1. **Refactor: Hexagonal/Layered architecture — `fs/*` = core, `converter.js` = browser facade only** — `converter.js`, `fs/nsz-convert.js`, `fs/xcz-convert.js`, `fs/cnmt-hashes.js`, `nsz-cli.js`. Moved high-level `convertNSZ`/`convertXCZ` (with `buildAdapter`/`collectBlob`, CNMT extraction, orchestration) into `fs/nsz-convert.js` and `fs/xcz-convert.js` respectively, next to their streaming cores. `converter.js` now holds only `NSZConverter` (browser facade) + `FileSliceReader` and imports `convertNSZ`/`convertXCZ` from `fs/*`. `nsz-cli.js` imports `convertNSZ`/`convertXCZ` directly from `fs/*` (no longer needs `converter.js`). No more "call-then-return to same lib": facade calls one core function, which does `buildPartitionMetas` → streaming locally. Mirrors nsz: `nsz/Fs/*` + `NszDecompressor` (now `fs/*`), `__init__.py`/`__main__` call core directly. Dependency Injection: core receives `adapter`/`extractCnmtHashMap`/`keys` as params (no hard import of CNMT logic). Trackline `.nsz`→`.nsp` still 223285520 bytes (byte-identical to nsz).

2. **Verify: strict per-file CNMT hash match (`Map<ncaId,hash>`)** — `fs/nsz-convert.js`, `fs/xcz-convert.js`, `fs/cnmt-hashes.js`. Added `extractContentHashMap(ncaData, keys)` returning `Map<ncaId, hash>` (previously `extractContentHashes` returned a `Set`). Both `convertNSZ` and `convertXCZ` now build a `Map` and verify via `verifyHashByNcaId(hash, ncaId, cnmtHashMap)` — the concrete `.nca` file's `ncaId` must map to exactly its expected hash, not just be present in a set (stricter than nsz's `in fileHashes` membership check). `verifyFileNameHash` remains the fallback when no CNMT is available. `extractContentHashes` (Set) kept for backward compatibility.

## ✅ Recent Changes (2026-07-19)

1. **Perf: module-level `fs` import + sync read in FileDescriptorReader** — `nsz-cli.js`. `FileDescriptorReader.read()` previously called `await import('fs')` on every invocation — 100K+ times on block-mode NCZ. Replaced with a top-level `import fs from 'fs'` and sync `fs.readSync()`, eliminating the dynamic import + Promise + microtask yield per read.

2. **Perf: `Buffer.alloc()` → `Buffer.allocUnsafe()`** — `nsz-cli.js:135,196`, `fs/ncz.js:137`. `Buffer.alloc()` zero-fills then `fs.readSync` immediately overwrites. `allocUnsafe()` skips zero-fill — saves ~1-2µs per 16KB block × 100K+ blocks = ~100-200ms on large files.

3. **Perf: PFS0Writer string table** — `fs/pfs0.js`. Earlier versions rebuilt `join('\0')` on every access and created `new TextEncoder()` multiple times (`_stringTable` getter + `_paddedStringTableSize` + 3× in `buildHeader()`). The `7f4bdb6` refactor consolidated all of this into a single inline computation in `buildHeader()` — `stringTable` built once via `map().join('\0')`, encoded once via `new TextEncoder().encode(padded)`. No cached getters remain; layout is computed once per `buildHeader()` call.

4. **Perf: HFS0Writer string table** — `fs/hfs0.js`. Earlier versions had `_buildStringTable()` creating `new TextEncoder()` every call plus another inside the loop in `_writeHeader()`. The `7f4bdb6` refactor removed these: `_stringTableBytes()` encodes once, `_buildLayout()` computes the layout a single time, and `_writeHeader()` no longer creates a `TextEncoder` per entry (uses `e.name.length` for the offset). Eliminated the N+1 `TextEncoder` creations.

5. **Fix: PFS0Writer `fixPadding=false` (default) padding** — `fs/pfs0.js`. The old `else` branch added 16-byte alignment `(16 - rawSize%16) % 16` to the string table, which does NOT match Python nsz. In nsz `BlockCompressor.blockCompressNsp`, the `!fixPadding` path uses `container.getFirstFileOffset()` / `container.getStringTableSize()` — i.e. it adds **no padding** (data starts right after the unpadded header). Changed `paddedSize` to `namesLen` (no padding) for the default branch.

6. **Refactor: unify XCI XCZ→XCI into single `convertXCZStreaming`** — `fs/xcz-convert.js`, `fs/xci.js`, `converter.js`. Removed `XCIWriter` class from `fs/xci.js` and `convertXCZMemory` from `fs/xcz-convert.js` (the in-memory XCI builder that duplicated `computeLayout`/`writeXciHeaders`/`writePartitions`). Both browser (memory) and CLI/FileSystemAccess (streaming) paths now go through the single writer-driven `convertXCZStreaming`. Memory fallback uses a chunks-adapter (`{ offset, data }` collected, sorted, `new Blob(...)`) — exactly like the already-unified NSZ path (`convertNSZStreaming`). Root HFS0 reserves 0x8000 via `new HFS0Writer(ROOT_HFS0_PADDED_SIZE)` (matching nsz `Hfs0Stream.headerSize = 0x8000`), same as the streaming `computeLayout`. No behavioral change vs the previous memory path.

## ✅ Recent Changes (2026-07-15)

1. **Perf: T-tables for AES-ECB decrypt** — `crypto/aes128.js`. Added T1inv/T2inv/T3inv tables computed directly per InvMixColumns column (not via rotation from T0inv — InvMixColumns matrix is NOT circulant). Added `_invMixColumnsWord()` helper. Pre-computed `decKeys` (rounds 1–9 InvMixColumns'd) in `AesEcb` constructor. Rewrote `decryptBlock()` to use T-tables (symmetric performance with encrypt). Also removed 3× duplicated `rconTable` entries (180→40 entries). Decrypt ~8.6M blocks/s (symmetric with encrypt ~8.2M blocks/s).

2. **Perf: Replace BigInt gf128Mul with byte-level implementation** — `crypto/aes128.js`. GF(2^128) doubling now uses pure byte ops, no BigInt. Byte order matches BigInt reference (tweak[15] = MSB, tweak[0] = LSB). 17.6x faster on gf128Mul alone (4.5ms vs 71.5ms per 100K calls), 4.5x faster on real XTS decrypt (569ms vs 2573ms per 50MB). All 1000 test vectors match BigInt reference.

3. **Fix: gf128Mul byte order bug** — `crypto/aesxts.mjs`. Byte-level GF(2^128) doubling had wrong carry direction (carried from byte 15→0 instead of 0→15). Broke XTS decryption for files with cryptoType=XTS (e.g. Trackline Express). Root cause: BigInt representation treats tweak[15] as MSB, tweak[0] as LSB — carry propagates LSB→MSB (byte 0→15). Confirmed against Python nsz reference (`aes128.py:144-148`). All 1005 test vectors pass.

4. **Refactor: consolidate crypto layer** — Deleted `crypto/aesctr.mjs` and `crypto/aesxts.mjs`. Moved `AesXts` class, `xor`, `xorInto`, `getTweakBytes`, `gf128Mul` into `crypto/aes128.js`. Renamed `aesCtr` → `AesCtrJS` in `aes128.js`. Added `crypto/aes-ops.mjs`: `AesCtr` class with Node.js (`crypto.createCipheriv`), WebCrypto (`crypto.subtle.encrypt`), and pure-JS fallback. Added `createAesXts()` factory that overrides pure JS with native AES-ECB on Node.js. Updated all imports. Fix: `test_ticket_keys.mjs` `AESCTR` → `AesCtr` naming.

## ✅ Recent Changes (2026-07-14)

1. **Perf: T-tables for AES-ECB encrypt + decrypt** — `crypto/aes128.js`. Added T0–T3 and T0inv–T3inv lookup tables combining SubBytes/ShiftRows/MixColumns into single 32-bit lookups. Rewrote `encryptBlock()` and `decryptBlock()` to use T-tables. Pre-computed `decKeys` (rounds 1–9 InvMixColumns) in constructor. Added `_gmul` and `_invMixColumnsWord` helpers. Removed old step-by-step methods (subBytes, shiftRows, mixColumns, etc.). Trimmed rconTable 180→40 entries. Encrypt: ~7.4x faster (728K → 5.4M ops/s). Decrypt: ~34x faster (163K → 5.5M ops/s).

## ✅ Recent Changes (2026-07-09)

1. **Perf: replace string conversion in `getTweakBytes` with direct byte writes** — `crypto/aesxts.mjs:26`. Removed `Number → hex string → parseInt` roundtrip. Now writes sector bytes directly into `Uint8Array` from MSB to LSB. Same big-endian output, no intermediate string allocation.

## ✅ Recent Changes (2026-07-08)

1. **Build: copy runtime assets to `out/`, key files only** — `build.js`. Copies `favicon.svg`, `download-worker.js`, `static/prod.keys` to `out/`. No longer copies `static/zstddec.mjs` — it's bundled into `app.mjs` now. Graceful skip if `prod.keys` missing. Extracted `ENTRY`/`OUT`/`ASSETS` constants. Assumes `netlify.toml` with `publish = "out"`.

2. **ZstdDecoder: replace dynamic `import()` with static `import`** — `crypto/zstd.js`. Changed `await import('../static/zstddec.mjs')` to `import { ZSTDDecoder } from '../static/zstddec.mjs'`. esbuild bundles it into `app.mjs`, eliminating one HTTP request at startup.

## ✅ Recent Changes (2026-07-05)

1. **NCAHeader: sections/sectionFilesystems split** — `fs/nca.js`. Added `SectionHeader` class parsing 0x200-byte section headers at offset 0x400. `NCAHeader.parse()` now returns parallel `sections[]` and `sectionFilesystems[]` arrays (matching Python nsz `Nca.open()` pattern). `sections[i]` has: `offset`, `endOffset`, `size`, `fsType`, `cryptoType`, `cryptoKey` (= `titleKeyDec`), `sectionStart`, `sectionSize`, `cryptoCounter`, BKTR buffers. `sectionFilesystems[i]` has: `fsType`, `cryptoType`, `sectionStart`, `size`, `cryptoCounter`, BKTR buffers. Only sections with `fsType !== 0` included. Added `FsType` constants. `NCAHeader.parse(buffer, keys)` now accepts optional `keys` parameter for key block decryption (AES-ECB with `key_area_key_application[masterKey]`, bytes 32-48 = `titleKeyDec`).

2. **Simplified extractCnmtHashes** — `converter.js`. Removed manual key block decryption (25 lines). Now uses `header.sections[0].cryptoKey` and `header.sections[0].cryptoCounter` directly. Removed unused `AesEcb` import and `nodeCrypto` dynamic import.

## ✅ Recent Changes (2026-07-04)

1. **CLI: added `-o, --output`** — `nsz-cli.js`. Output directory for converted files. Matches Python nsz `-o, --output`.

2. **CLI: added `-w, --overwrite`** — `nsz-cli.js`. Skips conversion if output exists unless `-w` is passed. `convertNSZ`/`convertXCZ` check `fs.existsSync(outPath)` before opening output fd. Matches Python nsz `-w, --overwrite`.

3. **CLI: added `--rm-source`** — `nsz-cli.js`. Deletes input file after successful conversion. `convertNSZ`/`convertXCZ` call `fs.unlinkSync(inputPath)` after `=== DONE ===`. Matches Python nsz `--rm-source`.

2. **Perf: skip redundant `slice(0)` in SWDownloader for standalone buffers** — `main.js`, `crypto/zstd.js`. Added `ZstdDecompressor.wasmBuffer` getter. `SWDownloader.write()` now checks `view.buffer === wasmMem`: WASM views still `slice(0)`, standalone buffers (WebCrypto output, ~90%+ of data) transferred directly — no copy. Eliminates one allocation + memcpy per chunk for encrypted sections.

1. **Perf: skip redundant `slice(0)` in SWDownloader for standalone buffers** — `main.js`, `crypto/zstd.js`. Added `ZstdDecompressor.wasmBuffer` getter. `SWDownloader.write()` now checks `view.buffer === wasmMem`: WASM views still `slice(0)`, standalone buffers (WebCrypto output, ~90%+ of data) transferred directly — no copy. Eliminates one allocation + memcpy per chunk for encrypted sections.

2. **Fix: dropzone empty height — show space for 3 files, no jump on load** — `main.js`. Removed `Math.min(200, ...)` cap, set `height = minSlotHeight` (= 3×itemHeight + border) instead of CSS `clamp(120px, ...)`. `snapFileListHeight()` called synchronously during init before first paint — no jump from 120px to file height.

3. **UX: replace pill CSS tooltips with ⓘ info popovers** — `index.html`. Removed `.pill[title]::after` CSS tooltip (per-pill `:focus` popup on mobile). Added ⓘ buttons next to "Download mode" and "Options" labels that open a native `popover` with grouped descriptions of all modes/options. `title` attributes kept on individual pills for desktop hover. Uses Popover API — no JS. Popover anchored to label via CSS `position-area: bottom; justify-self: anchor-center` — appears below the label button, not centered on screen.

## ✅ Recent Changes (2026-07-02)

1. **Fix: remove double CNMT hash extraction in NSZ path** — `converter.js`, `nsz-convert.js`, `nsz-cli.js`. `decompressNSZtoNSP` collected `cnmtHashes` once (lines 85-96), then passed `extractCnmtHashes` callback to `convertNSZStreaming`, which called `collectCnmtHashes` that iterated files and decrypted CNMT again. Now `convertNZStreaming`/`convertNSZMemory` accept `cnmtHashes` Set directly (like Python's `ExtractHashes` → `Set` pattern). `collectCnmtHashes` removed. `nsz-cli.js` collects hashes once before calling `convertNZStreaming`. XCZ path unchanged (no duplication there).

2. **Refactor: replace dynamic `import('crypto')` with `isNode` guard** — `converter.js`. Same pattern as `aesctr.mjs`/`aesxts.mjs`. Module-level detection, runs once. Browser uses pure-JS `AesEcb` (was always the fallback), Node.js uses native `crypto.createDecipheriv` (AES-NI). No performance change in browser path.

## ✅ Recent Changes (2026-06-30)

1. **Perf: simplify `AsyncBlockDecompressorReader.read()` to single block lookup, remove dead `concatBytes`** — `fs/ncz.js`. Replaced while-loop + `concatBytes(...)` pattern with direct single-block lookup. Each `read(n)` call now returns at most one block (subarray), eliminating the temporary buffer array and concat allocation. Function `concatBytes` removed as dead code. All existing tests pass.

2. **Refactor: split decompress back to streaming/block paths, add FakeSection** — `fs/ncz.js`. Removed `ZstdStreamReader` buffered-reader abstraction, reverted to two independent paths: `_decompressStream` (for `decodeStream`/CLI stdout — processes chunks immediately via `for await`) and `_decompressBlocks` (for `AsyncBlockDecompressorReader` sections loop). Added `FakeSection` when `sections[0].offset > 0x4000` (matches Python nsz behavior). Fixed CLI exit handler race — register `close` listener immediately after `spawn`. Benchmarked copy overhead: ~10ms on 221MB (~0.03%) — negligible, but correctness fix for WASM. WASM `decodeStream` yields views into mutable WASM memory that must be consumed synchronously; `ZstdStreamReader` deferred consumption, forcing an unnecessary `Uint8Array(chunk)` copy. Immediate consumption eliminates the copy. All existing tests pass.

## ✅ Recent Changes (2026-06-29)

1. **Refactor: extract converters into shared modules** — `fs/xcz-convert.js`, `fs/nsz-convert.js` (new).
   - `fs/xcz-convert.js`: `convertXCZStreaming` + `convertXCZMemory` with adapter interface `{ read, write, createHash, log, progress }`. XCI layout computed via `buildPartitionMetas`+`computeLayout`, written by `writeXciHeaders`+`writePartitions`. Shared with `converter.js` (browser) and `nsz-cli.js` (Node).
    - `fs/nsz-convert.js`: `convertNSZStreaming` + `convertNSZMemory` with same adapter pattern. `collectOutputMeta` helper reused in both paths. `buildPfs0Blob` shared. (Note: `collectCnmtHashes` removed 2026-07-02 — now receives `cnmtHashes` Set directly.)
   - `converter.js`: 496→280 lines, delegates to shared modules. `nsz-cli.js`: ~170→~30 lines per function.
   - `fs/ncz.js`: `AdapterNCZReader` (colocated with `DataReader` base class), reused by both converter modules.
   - `verifyHash`/`verifyFileNameHash`: local functions in `fs/nsz-convert.js` + `fs/xcz-convert.js` (not a shared module — inline per consumer matches pre-refactoring pattern). Non-NCZ files are not hashed (matches Python nsz behavior).
   - **Regression benchmark** (commit `64fed88` vs `4e6330d`, 7 runs each, 109MB NSZ, `--no-verify`):
     - OLD: 0.320–0.424s (avg 0.386s). NEW: 0.315–0.339s (avg 0.325s).
     - **−15.6% faster**.

## ✅ Recent Changes (2026-06-28)

10. **Optimize SHA256 internal buffer: plain Array → Uint8Array** — `crypto/sha256.js:67`. Replaced `this.buf = []` (plain JS Array with byte-by-byte `.push()` → boxed Number heap allocations) with `this.buf = new Uint8Array(256)` + offset pointer `this.bufLen`. Hot path `.update()` now uses `buf.set(subarray, offset)` — zero boxing, zero GC. Padding/finalization in `hexdigest()` uses direct index assignment + `fill()` + `copyWithin()`. Single allocation at construction, no resizing. Microbenchmark: −4.5% on SHA256 alone.

9. **Remove sha256 verification for non-NCZ files, skip CNMT when verify=off, add `--no-verify` CLI flag** — `converter.js`, `nsz-cli.js`. Python nsz doesn't hash non-NCZ files (.tik, .cert, etc.); they're just copied. Removed 4 redundant `sha256(data)` calls. Also skip CNMT extraction entirely when verify=off (both NSZ and XCZ paths). CLI gains `--no-verify`/`-nv` flag — skips CNMT, SHA256 hashing, and hash verification. Benchmark: 0.535s vs 0.65s = 17% faster on 109MB NSZ.

8. **Fix Uint8Array counter increment overflow bug** — `crypto/aes128.js:264`, `crypto/aesctr.mjs:84-87`. `++counter[j]` on a `Uint8Array` returns the **full integer** (e.g. `256`) before truncation to `0x00`. The check `if (++counter[j]) break` was **always truthy on overflow**, breaking carry propagation past byte 0xFF → counter wrapped at 256 blocks (4096 bytes). Pure JS AES-CTR produced garbage for any data >64KB after block 256. Fix: separate `counter[j]++; if (counter[j]) break;` — the stored value is the correct truncated Uint8, and `0x00` is falsy so carry propagates correctly.

7. **Re-instate async WebCrypto path** — `crypto/aesctr.mjs`: `encrypt()`/`decrypt()` are `async`. Browser uses WebCrypto `crypto.subtle.encrypt('AES-CTR')` (hardware-accelerated), Node.js uses sync `crypto.createCipheriv()` (wrapped in async Promise — ~2ms overhead for 500MB, negligible). Pure JS `AesEcb` fallback only when WebCrypto unavailable. All callers in `fs/ncz.js`, `converter.js` use `await`.

## ✅ Recent Changes (2026-06-27)

1. **Decision: keep `%`/`Math.floor` in aes128.js for readability** — V8 TurboFan strength-reduces power-of-2 `%` to `&` automatically (< 1 ns difference per op). Manual `%`→`&` gave < 6% on full AES block encrypt/decrypt — not worth the readability loss. Refactor commit `c071523` already uses `%`/`Math.floor` directly.

2. **Cleanup: remove redundant `Number(remainder)` in ncz.js**, fixup'd revert into Refactor AES commit.

4. **Fix CNMT field offsets matching Python nsz** — `fs/cnmt.js`: `headerOffset`, `contentEntryCount`, `metaEntryCount` were at wrong offsets (18/20/22 instead of Python's 14/16/18). Caused `contentEntryCount=0` on all valid CNMT files → `Found 0 expected NCA hashes from CNMT`. Also: `converter.js`: `NSZConverter` constructor now accepts `keys` parameter (`constructor(keys = null)`). `nsz-cli.js`: passes `keys` when constructing `NSZConverter` for CNMT extraction.
5. **AES-XTS + AES-CTR NCA header decryption in `extractCnmtHashes`** — `converter.js`: XTS-decrypts NCA header (0xC00 bytes) with `header_key`, unwraps key block with `key_area_key_application`, AES-CTR decrypts section data, skips hash tree, extracts CNMT XML from PFS0. Verified: Trackline Express NSZ extraction matches Python nsz — all 3 NCA hashes `[VERIFIED]`.
6. **Browser-compatible AES-ECB in `extractCnmtHashes`** — `converter.js`: `import('crypto')` guarded with `isNode` check (same pattern as `aesctr.mjs`/`aesxts.mjs`). Module-level detection, runs once. Browser uses pure-JS `AesEcb`, Node.js uses native `crypto.createDecipheriv` (AES-NI). No performance change in browser (~31µs saved one-time, pure-JS AES-ECB 64 bytes is ~23µs).
7. **Fix sync/async mismatch in `AesCtr` for browser WebCrypto path** — `crypto/aesctr.mjs`: `_webTransform()` was async but `encrypt()`/`decrypt()` didn't `await` it, returning a Promise instead of Uint8Array when WebCrypto was active. Made `encrypt()`/`decrypt()` async. Updated all callers in `fs/ncz.js`, `converter.js` to `await` the result.

## ✅ Recent Changes (2026-06-26)

10. **Perf: slice→subarray, remove redundant await/Buffer.from** — `fs/ncz.js`: `slice`→`subarray`, removed `await` from sync calls, dropped `Buffer.from` wrapper. Benchmarked: −7.7% user CPU on 109MB NSZ.

11. **Fix NCAHeader/BKTR to handle both ArrayBuffer and Uint8Array** — `fs/nca.js`. Use `arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)` — zero excess allocations for Uint8Array input, one for ArrayBuffer.

## ✅ Recent Changes (2026-06-23)

10. **Fix pure JS AESECB in `aes128.js`** — Three bugs fixed:
    - `keySchedule()`: rcon lookup was off-by-one (`rcon_table[1]` used for round 1, should be `rcon_table[0]`). Fix: `rcon_table[Math.floor(i / constNk) - 1]`
    - `rotateOp()`: used arithmetic `>> 24` which sign-extends when MSB ≥ 0x80, corrupting key schedule for keys with bit 31 set in any word. Fix: `>>> 24`
    - `shiftRows()`/`invShiftRows()`: swapped rows 1&3 instead of rotating within each row. Fix: transpose then rotate via `state[j*4 + i] = tmp[i*4 + (j+i)%4]` (aes-js style)
    Verified against NIST vectors and 100 random roundtrips match Node.js native AES.

## ✅ Recent Changes (2026-06-25)

5. **Remove dead ArrayBuffer branch from PFS0 constructor** — `fs/pfs0.js:2-9`. Constructor had 3 branches: `Uint8Array` (no copy), `ArrayBuffer` (wrap), else (`new Uint8Array`). `ArrayBuffer` branch never called — all callers pass `Uint8Array` or `Buffer`. Simplified to `this._data = new Uint8Array(data)`.

6. **Remove dead `hfs0Data` field from nsz-cli partitionMetas** — `nsz-cli.js:129,139`. `hfs0Data: null` was set in partition metadata objects but never read. Left over from pre-HFS0Writer refactoring when CLI built HFS0 in memory. Still alive in `converter.js` (local variable, used for XCI build).

7. **Add CNMT verification to CLI NSZ path** — `nsz-cli.js:278-291,335-337,345-347`. `convertNSZ` was missing CNMT hash collection and `verifyHash` calls. Added: same pattern as `convertXCZ` — collect CNMT hashes from `.cnmt.nca` files via `NSZConverter.extractCnmtHashes`, then verify each NCA hash against the expected set. `[VERIFIED]`/`[CORRUPTED]` logs now appear for NSZ→NSP conversion too.

8. **Fix `extractCnmtHashes` returning 0 hashes** — `converter.js`. CNMT NCA section data is wrapped in a PFS0 filesystem, but `extractCnmtHashes` passed it directly to `Cnmt.parse`. Added PFS0 unwrapping: check for `PFS0\0` magic, parse as PFS0, extract first file, then pass to `Cnmt.parse`. This caused `Found 0 expected NCA hashes from CNMT` and no `[VERIFIED]`/`[CORRUPTED]` output even with Verify enabled.

9. **Remove dead `decompressNCZtoNCA`, add `verifyFileNameHash` fallback** — `converter.js`, `nsz-cli.js`. Standalone NCZ conversion (`decompressNCZtoNCA`) was dead code — never called from anywhere. Removed. Added `verifyFileNameHash(hash, nczName, ncaName, onLog)` — extracts first 32 chars from NCZ filename stem, compares against `hash[:32]`. Used as fallback in all verification paths when `cnmtHashes` is empty (no CNMT available). Follows Python nsz `NszDecompressor.py:28-32`.

## ✅ Recent Changes (2026-06-24)

1. **Extract `verifyHash` to standalone function** — `verifyHash` was defined inside `decompressNSZtoNSP` (line 92-101) but not in `decompressXCZtoXCI` (line 277). When `verify=true` was passed to XCZ conversion, all 4 call sites threw `ReferenceError: verifyHash is not defined`, crashing the conversion. Also: dead top-level `verifyHash` referenced undefined `onLog`. Fixed: single standalone `verifyHash(hash, name, fileHashes, onLog)` at module level. Follows ESLint `class-methods-use-this`.

2. **titlekek_source fallback in keys.js** — `keys.js:35` required `titlekek_source` key to be present; missing key caused silent failure (empty Uint8Array → wrong derived keys). Added fallback to `keys.titlekek` if `titlekek_source` is absent, with explicit error if neither is found.

3. **PFS0.open(reader) static factory** — `fs/pfs0.js`. Added `PFS0.open(reader)` static method that probes 16 bytes, reads exact header size, and creates PFS0 instance. Updated `converter.js` and `nsz-cli.js` to use `PFS0.open(reader)` instead of 1MB buffer reads. Matches Python nsz `Pfs0.open()` — reader-based, no fixed buffer size.

4. **AESCTR async→sync in Node.js** — `crypto/aesctr.mjs`. `encrypt()`/`decrypt()` were `async` even though `_nodeTransform()` is sync. Hot loop (`ncz.js:333,436`) created 2 microtask ticks per call. Fixed: sync in Node.js + pure JS fallback, async only for WebCrypto. ~2ms saved on 212MB file (within noise, not bottleneck).

### Performance Benchmarks (Trackline Express, 212MB NCA, 10 runs)
| Test | Result |
|---|---|
| AESCTR async→sync (b5701fe vs HEAD) | 447.6ms vs 445.5ms — ~2ms, within noise |
| PFS0: old 1MB readSync vs new PFS0.open | 0.20ms vs 0.26ms — negligible |
| ZSTD: CLI vs WASM in Node.js | 417.8ms vs 590.6ms — CLI 41% faster (native C++) |

## ✅ Recent Changes (2026-06-22)

9. **Fix AESECB decrypt() PKCS7 unpadding bug** — `crypto/aes128.js:128-144` — `decrypt()` stripped PKCS7 padding from last block, but key derivation (`keys.js:65,68,71`) passes raw 16-byte blocks with no padding. If `decrypted[15]` fell in [1,16], the key was truncated. ~18% chance of wrong key per derivation. Fixed: removed PKCS7 unpadding (matches Python nsz `AESECB.decrypt()` which does raw AES-ECB). Added block alignment check (`data.length % 16 !== 0` throws). Also fixed `encrypt()` to use PKCS7 padding for partial blocks (matches Python nsz `_pad_partial_block()`).
8. **Fix XCZ→XCI partition overlap** — Root HFS0 entry size was `pm.hfs0BufferSize` (header only), not `pm.hfs0BufferSize + pm.totalSize` (header + data). This caused partition N+1 header to overlap with partition N data when multiple non-empty partitions exist. Fixed in both `converter.js` streaming path and `nsz-cli.js` CLI path. Refactored to use `partSizes[]` array computed once, matching Python nsz pattern where `f['size']` stores full partition size. Added documentation to `HFS0-OFFSET-CONVENTION.md` explaining why JS uses pre-calculate (browser `FileSystemWritableFileStream` can't use Python's streaming `add()`+`resize()` approach).
7. **Full codebase bug review** — Found 11 bugs. Critical: XCZ partition overlap (converter.js:355-365, nsz-cli.js:166-178). Significant: AES-ECB PKCS7 padding in key derivation (aes128.js:128-139 → keys.js:65,68,71). Moderate: accumulatedBytes not updated on error, blockIndex uninitialized, DataView fragility, dead padding code. Low: iframe DOM leak, Content-Disposition injection, unchecked readSync. Awaiting user decision on which to fix.
1. **Fix `offsetInSection` → `offset` bug in CLI** — `nsz-cli.js:177` — `po.offset` was `undefined` (`offsetInSection: currentDataPos`), causing all `fs.writeSync` to write at cursor instead of absolute position. Fixed to `offset: ROOT_DATA_SECTION + currentDataPos`.
2. **Remove dead `hfs0Data` reference** — `converter.js:343` — `hfs0Data,` in `partitionMetas.push()` referenced undefined variable, left over from refactor. Removed (field was never consumed).
3. **Folded both fixes into original commits** — `hfs0Data` and `pHeaderSize` fixed in the refactor commit itself, no separate fix commits.
4. **Fix error cleanup: close writable and removeEntry on conversion failure** — `outputName` moved outside `try` block. On conversion failure, closes the writable stream and removes the partial output file from the filesystem.
5. **Fix `writable` ReferenceError in catch block** — `let writable = null;` was declared inside `try` with `let`, making it inaccessible in `catch` (block-scoped). Moved it alongside `outputName` before the `try` block. Without this, any error path would throw `ReferenceError: writable is not defined`, silently skipping error status and file list update.
6. **Load keys once at startup, not on every convert** — Moved `loadDefaultKeys()` from the convert button handler to after `converter.init()`. Keys file is static, no reason to re-fetch it on each conversion.

## ✅ Recent Changes (2026-06-21)

1. **iOS 27 segmented control for download mode** — Mode pills now use `.pills.segmented`: connected with shared border (`gap: 0`, `border-left: none` on siblings), first/last rounded corners, active pill uses accent fill (`var(--accent-glow)`). Options pills remain separate with `gap: 4px`.
2. **Compact mobile setting rows** — `.setting` padding reduced from `10px 14px` to `6px 14px`, eliminating scroll before drop. Desktop padding also reduced: `14px 16px` → `10px 16px`. Pills centered. Removed `flex-shrink: 0` (unused).
3. **12px pills on desktop** — `@media (min-width: 900px)` now sets `.pill { font-size: 12px }`.
4. **Label: "Download mode"** (not "Save mode").
5. **Removed `min-width: 0`** from `@media (max-width: 380px)` `.pill` rule.
6. **Removed `0%` default from progress percent** — stays empty until conversion starts.

## ✅ Recent Changes (2026-06-21) (Previous)

## ✅ Recent Changes (2026-06-19)

1. **esbuild bundle** — All JS modules bundled into single `out/app.mjs` (178KB) via esbuild. 1 HTTP request instead of 15+ separate module imports. Solves `ERR_HTTP2_PING_FAILED` on Netlify CDN caused by too many parallel HTTP/2 streams. Build: `npm run build`. Netlify needs build command set to `npm run build`.

## ✅ Recent Changes (2026-06-18)

0. **Zstd init with fallback UI** — `main.js` calls `converter.init()` at startup. On failure (e.g. network down), shows `#jsFallback` with Retry button (`location.reload()`). Added `window.addLog` in `index.html` so errors log before main.js loads. Initially added retries for both `index.html` (import) and `main.js` (init), but removed them — retrying dynamic imports doesn't help when the page itself needs a full reload. Errors seen: `ERR_HTTP2_PING_FAILED` (Netlify CDN drops HTTP/2 connections). Removed unnecessary `DOMContentLoaded` wrapper (import() is already deferred).

1. **Fixed "Ready" false state before JS loads** — Static HTML showed "Ready" in progressTitle (`index.html:672`) before any JS ran. If main.js (ES module with import chain) loaded slowly, user saw "Ready" but no log entries. Changed HTML default to empty, added spinner, JS sets "Ready" only after `converter.init()` completes (`main.js:462`). Also reset to "Ready" when file list becomes empty.

## ✅ Recent Changes (2026-06-18) (Previous)

1. **Simplified progress calculation — removed fixed offsets, byte-weighted overall** — Replaced `pct = (bytes) => 0.02 + 0.93 * (bytes / totalDataSize)` with `bytes / totalDataSize` in all 4 places in converter.js. Removed `onProgress(0.02, 'Reading container...')` call. Removed all `0.95` building-phase progress calls. Removed NSZ remapping `(p - 0.02) / 0.98` in main.js. Changed overall progress from file-count-weighted `(i + p) / totalFiles` to byte-weighted `(accumulatedBytes + file.size * p) / totalBytes`.

2. **Hidden Overwrite toggle for non-FSA modes** — Overwrite only works in FSA mode; now hidden when Stream or Blob is selected. Added `.pill.hidden` CSS class (index.html:383), toggle logic in download mode switch handler (main.js:259) and init (main.js:98).

3. **Fixed layout elongation after conversion** — Root cause: grid items (`.main-left`, `.main-right`) with default `min-height: auto` grow the grid row to fit all content, pushing past viewport. Fixed by `min-height: 0` on both grid column flex containers in desktop media query. Also: `height: auto` on `.drop-zone` desktop override to avoid conflict with mobile `height: clamp(...)`. Changes in `index.html` lines 549-568.

## ✅ Recent Changes (2026-06-17)

1. **Added Verify toggle to browser UI** — New `Verify` button in Options (`index.html`) defaults to OFF, skipping SHA-256 hash computation. Gives ~6x speedup in browser streaming path (pure JS SHA-256 is the dominant bottleneck). Guarded by `verify` option in all 3 converter methods (`decompressNSZtoNSP`, `decompressNCZtoNCA`, `decompressXCZtoXCI`). Default `verify=false` — no change for CLI (uses native `crypto.createHash` independently).

## ✅ Recent Changes (2026-06-14)

1. **Deleted `_decompressBuffered`** — Memory path now uses `_decompressStream` with `collectChunk` wrapper (`fs/ncz.js:220`). Reads input as stream, collects output into buffer. Removed ~80 lines of duplicated decompression logic.

2. **Aligned hash verification with Python nsz** — Extracted `verifyHash` method, removed dead `hash in cnmtHashes` bug, split NCZ/NCA verification, moved `.nca` check to call sites, added `[VERIFIED]`/`[CORRUPTED]` with hash, `[EXISTS]` logging, `[MISSMATCH]` for standalone NCZ.

3. **Per-partition XCZ hash verification** — Python nsz extracts CNMT hashes from each XCI partition independently. Now both NCZ and non-NCZ .nca files verified against partition-specific CNMT hashes.

4. **blockSizeExponent validation** — Added range check (14-32) matching Python nsz `BlockDecompressorReader`.

5. **Delete partial output on error** — CLI now deletes incomplete output files on conversion failure.

6. **Removed CLI Buffer.from(chunk) copies** — `fs.writeSync` accepts Uint8Array directly.

7. **Updated IMPROVEMENTS.md** — All items resolved, added speed/memory optimization attempts.

8. **Updated README** — Added Python nsz compatibility section, verification behavior, architecture notes.

## ✅ Recent Changes (2026-06-12)

1. **Added "Overwrite" toggle option** — New toggle in browser UI settings panel (`index.html`) allows controlling FSA file creation behavior. Defaults to on (overwrite existing files). Added as a `.toggle-group` alongside the existing "Fix Padding" toggle in the Options setting group. JavaScript handler not yet wired in `main.js`.

2. **Fixed ES modules CORS issue** — Browser `file://` protocol blocks ES module script loading. Fixed by using `python3 -m http.server 8080` to serve files via HTTP.

## ✅ Recent Changes (2026-05-30)

1. **HFS0 offset convention changed to match hactool** — All HFS0 writers (`HFS0Writer`, `XCIWriter`, `_buildPartitionHfs0*` in converter.js, `nsz-cli.js` root/partition entries) now store `absolutePos - actualHeaderSize` instead of `absolutePos`. The `HFS0Reader` reconstructs the absolute offset as `baseOffset + actualHeaderSize + storedOffset`. This matches Python nsz commit `b445f666` and hactool's `absolute = base + header_size + cur_file->offset`. 7 sites updated across 3 files.

2. **XCZ→XCI: proper nested XCI output** — `fs/xci.js`, `converter.js`, `nsz-cli.js` rewritten to produce full XCI with root HFS0 at `0xF000` containing partition entries (`secure`, `normal`, `update`, `logo`). Each partition is a nested HFS0 with `0x8000` header padding containing the decompressed NCA files. Matches Python nsz output structure. Previously produced a flat HFS0 at `0x200` which treated partition names as filenames.

3. **nsz-cli.js root HFS0 padded to 0x8000** — Root HFS0 now written as 0x8000 bytes (std. convention: partition offsets relative to HFS0 base at 0xF000, so first partition stored as 0x8000 - actualHeader). Partition HFS0 uses dynamic `pHeaderSize` for actual padding. Fix: `writePos` and file entry offsets now use `pHeaderSize` instead of hardcoded `PARTITION_HEADER_SIZE`.

4. **Removed dead code in converter.js** — Cleaned up unused `inputFile`/`origFiles` variables in streaming path (lines 411-412) and unused `hfs0`/`hfs0Data` variables in memory path (lines 461-463).

5. **Fixed `nsz-cli.js` unused HFS0Writer import** — Removed unused HFS0Writer import from nsz-cli.js.

## ✅ Recent Changes (2026-05-17)

1. **SW download: hidden iframes pre-created upfront, one per file** — All hidden `<iframe>` elements are created before the conversion loop (`main.js:265-270`). Each file in the loop uses its pre-allocated iframe, navigating it to the SW stream URL only after the stream is registered. No `window.open` calls, no new tabs. (`main.js:36-39`, `main.js:265-270`)

## ✅ Recent Changes (2026-05-15)

1. **Shared ZSTDDecoder instance in `crypto/zstd.js`** — WASM `ZSTDDecoder` is instantiated once and reused across all `decompressBuffer` calls. Eliminates repeated WASM module import + decoder init + memory allocation per decompress call. The WASM instance is captured for raw API access via `ZstdDecompressor.instance`. Removed unused `decompressStreaming` static method.

2. **Eliminated `compressedChunks` pre-buffering in `fs/ncz.js`** — `_decompressStream` no longer reads all compressed data into an array before decompressing. Node.js path reads chunks lazily and writes to zstd stdin; browser path uses new `crypto/zstddec-stream-wrapper.js` which wraps zstddec's raw WASM exports (`ZSTD_createDCtx`/`ZSTD_decompressStream`) as an async generator with lazy `readChunk`. Peak RAM drops from file-size to 16 MB chunks.

3. **Replaced hash-wasm with Web Crypto API SHA-256** — hash-wasm WASM was 1 min slower than pure JS (WASM init overhead, SHA-256 not the bottleneck). Now uses `crypto.subtle.digest('SHA-256')` (browser) and `crypto.createHash('sha256')` (Node.js) — native, hardware-accelerated, zero init overhead. Falls back to pure JS.
4. **Updated `TEST_RESULTS.md` with speed comparison** — hash-wasm was 2m53s vs pure JS 1m51s for 5 GB NSZ conversion.
5. **Fixed SHA256 class bit-length encoding** — `>>> 32` in JS is a no-op (shifts mask to 5 bits). Split into hi/lo 32-bit words. Also fixed padding math (was padding to 64 instead of 56 bytes, leaving the 8-byte length field untransformed). Both bugs caused incorrect SHA-256 for all non-empty inputs.

## ✅ Recent Changes (2026-05-13)

1. **SW streaming: fixed `<a download>` not intercepted by SW** — Chrome's download manager bypasses the Service Worker for `<a download>` fetches (no `[SW] fetch` log seen). Replaced with `window.open(streamUrl)` — navigation fetches are always routed through the SW. The SW responds with `Content-Disposition: attachment` which triggers the download.

2. **Blob parts instead of giant Uint8Array** — `buildPFS0Memory` now passes file data as individual Blob parts instead of allocating a contiguous `new Uint8Array(totalSize)` and copying. Eliminates peak 2× memory overhead during PFS0 container building.

3. **NCZ→NCA streaming write support** — Added `writable` path to `decompressNCZtoNCA`. Uses NCZ decompressor's `writeChunk` callback with correct absolute positions for random-access `createWritable` writes. Memory path unchanged (NCZ needs random-access, not sequential).

4. **Mobile: SW streaming download instead of Blob** — On mobile (broken `createWritable`), registers a Service Worker at `sw.js` that creates a `ReadableStream`. Data chunks are sent to the SW via `postMessage` with zero-copy `Transferable` buffers and enqueued into the stream. The browser download manager consumes the stream immediately — peak memory drops from file-size to chunk-size. Falls back to Blob download if SW unavailable.

5. **Download mode switch** — UI radio buttons in `index.html` let the user pick: Auto (FSA→SW→Blob), File System (force FSA), Stream (force SW), Blob (force memory download). Mode state in `downloadMode` variable in `main.js`.

## ✅ Recent Changes (2026-05-10)

1. **Consolidated PFS0 writing into `pfs0.js`** — All PFS0 header building logic moved into `PFS0Writer` class. Removed duplicated inline header builders from `converter.js`, `nsz-cli.js`, `node/decompressor.js`.

2. **PFS0 alignment: two modes matching Python nsz** — Default uses 16-byte alignment `(16 - n%16) % 16` (Python nsz default); `--fix-padding` uses 0x20 alignment via `0x20 - n%0x20` (Python's `align0x20`). Verified: JS default output is byte-identical to Python nsz output.

3. **Fixed absolute offset bug in `node/decompressor.js:writeNSP`** — Was writing absolute file positions instead of offsets relative to header end. Fixed by `PFS0Writer` which correctly tracks relative offsets from 0.

4. **Fixed `FileDescriptorReader.read` for Node v25** — `fs/promises` dropped the `read` export; switched to callback-based `fs.read` wrapped in Promise.

5. **Verified JS output vs Python nsz** — Both default and `--fix-padding` modes produce byte-identical file data to Python nsz. Default mode output is 100% byte-identical. `--fix-padding` provides 0x20-aligned headers.

6. **Moved modules to `fs/` directory** — `pfs0.js`, `ncz.js`, `xci.js`, `ticket.js` moved from root to `fs/` matching Python nsz's `Fs/` layout. Removed unused `node/fs/` directory. All imports updated.

7. **Cleanup: removed dead code** — Removed `crypto/aesxts.js` (never imported), `node/nsz.js` + `node/decompressor.js` + `node/fileExistingChecks.js` (broken CLI chain referencing deleted `node/fs/`), `node/pathTools.js` + `node/parseArguments.js` (both never imported). Removed dead `sha256` import/export from `fs/ticket.js`. Updated `package.json` — `main` → `nsz-cli.js`, scripts use `nsz-cli.js`.

8. **Added `--help`/`-h` flag to CLI** — `nsz-cli.js` now handles `--help` and `-h` flags to display usage. Previously fell through to `stat()` call and crashed with ENOENT.

9. **Renamed `nsz-convert.js` → `nsz-cli.js`** — Clearer name for the Node.js CLI entry point. Updated all references in `package.json`, `README.md`, `CHANGELOG.md`, `BROWSER-ZSTD-LIMITATION.md`, `FIXES_PLAN.md`, and usage string.

10. **Removed `node/keys.js`** — Dead code; nothing imported it. Functionality superseded by `keys.js` (KeysParser) and `crypto/` modules.

## ✅ Recent Changes (2026-05-09)

1. **Node.js CLI rewritten for large files** — No more `fs.readFileSync`. Uses `FileDescriptorReader` for random access reads from file descriptor. Output written via `fs.writeSync` with positional writes. Works for files of any size (limited only by disk space). Handles NCZ, XCZ, and NSZ formats.

2. **XCZ browser path: streaming write support** — Stream-decompresses with `writeChunk` in pass 2. Uses File System Access API for large XCZ→XCI conversion. Memory path preserved as fallback.

3. **NSZ→NSP streaming decompression for large files** — Replaced the >1.5 GB guard with `zstddec.decodeStreaming()`. Reads compressed data in sub-2GB chunks, per-section AES-CTR decryption during streaming.

4. **XCZ input refactored** — `XCIReader` now uses `DataReader`, only reads 0x200-byte header + HFS0 header. `HFS0Reader` handles sliced `Uint8Array` correctly.

5. **DataReader abstraction** — `BufferReader`, `ChunkedBufferReader`, `FileSliceReader`, `FileDescriptorReader` for pluggable random-access reading.

6. **Native AES-CTR acceleration** — Node.js uses `crypto.createCipheriv('aes-128-ctr')` (OpenSSL/AES-NI), browser uses `crypto.subtle.encrypt('AES-CTR')` (Web Crypto API). ~2.3x speedup in browser (3min → 1m17s for 5GB NSZ). Dropped `aes-js` dependency entirely — no more pure-JS AES. Removed `AESCTR_BKTR` (dead code) and stale `node/crypto/` directory. Removed static `aes-js.js` from HTML.

7. **Removed compressed NCZ memory cache** — No longer caches 2GB+ compressed NCZ data in RAM. Pass 2 reads directly from the dropped File via `FileSliceReader`. Zero speed impact, eliminates peak memory bottleneck.

## ✅ Working Components

1. **PFS0 Container Parsing**
   - Reads uint32 at offset 4 (fileCount) and offset 8 (strTableSize)
   - Correctly parses 7 files from NSZ container

2. **PFS0 Writer**
   - Writes proper header structure with file entries and string table

3. **NCZ Discovery**
   - Finds NCZSECTION magic at offset 0x41D0 (16848)
   - Correctly parses 3 sections from section table

4. **zstd Decompression**
   - Uses zstddec WASM library for all decompression (browser and Node.js block)
   - Node.js streaming uses system `zstd` CLI via spawn piping
   - Successfully decompresses files of any size

5. **Section Handling**
   - Correctly calculates NCA size (0x4000 + sections)
   - Handles cryptoType: 1 (none), 3 (CTR), 4 (BKTR)

6. **AES-CTR Encryption**
   - Counter block: nonce[0:8] + BE64(blockIndex) matching PyCryptodome
   - Node.js: `crypto.createCipheriv('aes-128-ctr')` (OpenSSL/AES-NI)
   - Browser: `crypto.subtle.encrypt('AES-CTR')` (Web Crypto API)
   - Hardware-accelerated, ~2.3x faster than pure-JS aes-js

## ✅ Recent Fixes (2026-04-29)

1. **Fixed AESCTR class**
   - Was XORing data directly with key/nonce (wrong)
   - Now properly encrypts counter block with AES-ECB using aes-js
   - Counter format: nonce[0:8] + BE64(blockIndex) - matches Python PyCryptodome

2. **Fixed AESCTR_BKTR class** (since removed — dead code, BKTR uses AESCTR)

3. **Fixed decryptSection in ncz.js**
   - Removed double addition of UNCOMPRESSABLE_HEADER_SIZE
   - Removed `&& this.keys` condition that was blocking decryption
   - Now properly calls AESCTR/AESCTR_BKTR with correct offset

4. **Added aes-js library** (since removed — replaced by native crypto)

## ✅ Recent Fixes (2026-05-08)

5. **Fixed streaming decompression HACK in ncz.js**
   - Removed wrong pre-decryption of compressed data before zstd decompression
   - Correct order is now: zstd decompress → AES-CTR decrypt per section (matching Python nsz)
   - Fixed `ncaSize` scope bug (was undefined in sub-methods, would cause ReferenceError in progress callback)

6. **Improved zstd error handling in crypto/zstd.js**
   - Throws errors instead of silently returning empty Uint8Array
   - Uses console.error for error logging
   - Checks for empty decompressor output

7. **Rewrote nsz-cli.js (Node.js CLI)**
   - Now uses proper project modules (NCZDecompressor, PFS0Reader, KeysParser, sha256)
   - Supports optional keys file as third argument
   - No longer downloads fzstd from CDN at runtime
   - Proper PFS0 writing with correct 64-bit offsets

8. **Added NCA file type detection in ncz.js**
   - Detects NCA files (no NCZSECTN magic) and returns them as-is

9. **Fixed test-ncz.mjs test**
   - Was passing entire NSZ file to NCZDecompressor instead of sliced NCZ data

## ✅ Recent Fixes (2026-05-08, continued)

10. **Fixed fzstd decompression bug — 6-byte NCA SHA256 mismatch**
     - Root cause: fzstd (pure JS) produces 6 incorrect bytes at one location when decompressing large zstd streams (~600MB compressed, 1.6GB decompressed)
     - Fix: Node.js streaming decompression uses `zstd` CLI via `child_process`; browser uses zstddec WASM
     - Verification: Output NCA SHA256 matches working NSP reference byte-for-byte

11. **Node.js zstd CLI improvement: temp files → stdin/stdout piping**
     - Replaced `execSync` with temp files → `spawn('zstd', ['-d', '--no-check'])` with stdin/stdout pipes

12. **ncz.js code cleanup**
     - Removed dead classes and unused utility functions
     - Unified section decryption loop for both Node.js and browser paths

## ✅ Recent Changes (2026-05-08, continued)

15. **Dropped fzstd dependency entirely**
     - Replaced fzstd with zstddec WASM in all decompression paths (crypto/zstd.js, node/crypto/zstd.js, node/fs/ncz.js)
     - Removed `static/fzstd.mjs` and fzstd from `package.json`
     - All zstd decompression now uses a single library: zstddec (WASM-based, handles any window size)
     - Node.js streaming still uses system `zstd` CLI via spawn for performance
     - See `BROWSER-ZSTD-LIMITATION.md` for rationale


16. **Added standalone .ncz file support**
     - Browser: drop .ncz files → decompressed to .nca
      - CLI: `node nsz-cli.js game.ncz` → outputs game.nca
     - NCZDecompressor already detected standalone NCZ (NCZSECTN at offset 0); just needed UI/CLI routing

17. **Added XCZ decompression**
     - New `HFS0Writer` class in `xci.js` for building HFS0 partitions
     - Browser: drop .xcz files → decompressed to .xci
      - CLI: `node nsz-cli.js game.xcz` → outputs game.xci
     - Parses XCI secure partition, decompresses NCZ files inside, rebuilds HFS0

18. **Removed dead code**
     - Removed `getZstdWindowSize()` from `ncz.js` (no longer needed with zstddec)
     - Removed orphaned `decompressor.js` (not imported anywhere)

19. **Cleaned up test files**
     - Replaced hardcoded paths in `test_ticket_keys.mjs` and `test_decompress.mjs` with CLI args

## ⚠️ Known Limitations

1. **Memory download path (no File System Access API)**: Falls back to `Blob` download — builds full output in memory, fails for games >2 GB. Use browser with File System Access API (Chrome/Edge) for large files.

## ✅ Verified

- **Full end-to-end NSZ→NSP conversion** tested with `Little Nightmares II` (1.56 GB update NSZ)
- **All NCA data byte-identical** to Python nsz reference output
- **AES-CTR implementation** verified against Node.js native `crypto.createCipheriv('aes-128-ctr')` — both are correct
- **zstd CLI piping + Node.js native AES-CTR** confirmed to produce byte-identical output to the reference
- **PFS0 header padding**: Default uses 16-byte alignment (matching Python nsz). `--fix-padding` uses Python's `align0x20` (32-byte alignment, minimum 0x20 padding). All file data is identical between modes. Default mode output is byte-identical to Python nsz.
- **XCZ output is a proper nested XCI** — root HFS0 at `0xF000` with partition entries, each partition a nested HFS0 with `0x8000` header padding. Structure matches Python nsz output.

