# Program NCA Repack Documentation

## External Tools Overview

### hac2l (Atmosphere-NX/hac2l) — extraction only, NOT repacking

hac2l is a modern rewrite of hactool by Atmosphere-NX. It runs on Switch hardware and desktop, built from Atmosphere's source tree.

**What it does:**
- View info about NCA/NSP/XCI/PFS0/HFS0 files
- Decrypt headers (AesXts) and sections (AesCtr/AesCtrEx/BKTR)
- Extract sections to disk as plaintext files
- **Merge BKTR patch NCAs with base NCAs** (via `--basenca`)

**What it does NOT do:**
- Repack NCAs
- Create new containers
- Compress data
- Build hash trees

**BKTR merge algorithm** (`source/hactool_processor.nca.cpp:178`):
1. Opens base NCA and patch NCA via `StorageOnNca` (Atmosphere's Stratosphere filesystem)
2. Calls `CreateWithPatchWithContext(base_reader, patch_reader, section_index)` 
3. Stratosphere's `nca_storage_on_nca.cpp` internally:
   - Reads BKTR header (relocation table + subsection metadata)
   - Decrypts patch subsections via AesCtrEx (patch-key derived from titlekey, ctrVal big-endian)
   - Applies relocation table entries: each entry says "take X bytes from patch subsection Y and write them to offset Z in the base RomFS"
   - Streams the merged plaintext RomFS output
4. Extractor writes the result as `romfs/` directory

**Key insight:** hac2l does NOT re-implement BKTR. It delegates entirely to Stratosphere's `StorageOnNca::CreateWithPatchWithContext()`, which is the same code that the Switch OS itself uses for patching.

### hacPack (XITRIX/hacPack) — actual repacking tool

hacPack is the C tool that **creates** NCA/NSP/XCI from extracted files. Yanu calls it to pack merged data into new NCAs.

**Repacking algorithm** (Program NCA with `--plaintext`, from `nca.c:195`):

**Step 1: Build ExeFS PFS0** (`nca.c:221-235`)
```
exefs_dir/ → pfs0_build() → exefs_pfs0.bin + exefs_hashtable.bin
```
- Reads all files from `exefs_dir/`
- Creates PFS0 header (magic + file entries: name_offset/size/offset per file)
- Appends file data
- Computes hierarchical SHA-256 hash table (`hash_block_size=0x10000` for ExeFS)
- Hash table is padded to 0x200 boundary

**Step 2: Build RomFS IVFC tree** (`nca.c:41-76`)
```
romfs_dir/ → romfs_build() → level5_data.bin → ivfc_create_level() × 5 → level0_hashes.bin
```
- Reads all files from `romfs_dir/`, builds RomFS image (IVFC Level 5 = raw data)
- Creates 6 IVFC levels (5 hash levels + 1 data level):
  - Level 5: RomFS data (raw)
  - Level 4: SHA-256 of each 64KB block of level 5 → padded to 0x4000
  - Level 3: SHA-256 of each 64KB block of level 4 → padded to 0x4000
  - ...
  - Level 0: top hash level → padded to 0x4000
- IVFC header (0xE0 bytes): magic + level headers (logical_offset/hash_data_size/block_size) + master_hash
- Master hash = SHA-256(entire level-0 file, including padding)

**Step 3: Assemble NCA file** (`nca.c:238-471`)
```
NCA header placeholder (0xC00 zeros)
  + Section data (exefs_hashtable + exefs_pfs0 + ivfc_levels_concatenated)
    each section padded to 0x200 boundary
```
- Write NCA header placeholder (0xC00 bytes of zeros)
- Write ExeFS hash table
- Write ExeFS PFS0
- Pad to 0x200
- Write RomFS IVFC levels concatenated (level0 + level1 + ... + level5)
- Pad to 0x200
- Set `media_end_offset` = current file position / 0x200

**Step 4: Build FsHeaders** (`nca.c:260-268`)
For each section:
- `version = 2`
- `fs_type = 1` (PFS0) or `0` (RomFS)
- `hash_type = 2` (PFS0) or `3` (RomFS/IVFC)
- `crypt_type = 0x01` (CRYPT_NONE) with `--plaintext`, or `0x03` (CRYPT_CTR) without
- Superblock: master_hash, block_size, hash_table_size, offsets
- Section hash: `SHA-256(FsHeader[0:0x200])`

**Step 5: Build NCA header** (`nca.c:44-98`)
- `magic = "NCA3"`
- `content_type = 0x00` (Program)
- `distribution = 0` (not gamecard) or `1` (gamecard)
- `crypto_type = 0` (keygen 1) or `2` (keygen 2+)
- `title_id` = big-endian, but stored reversed (little-endian in file)
- `sdk_version = 0x000C1100`
- `section_entries[i]`: `media_start_offset` and `media_end_offset` (in 0x200 blocks)
- `section_hashes[i]` = SHA-256(FsHeader[i])
- `encrypted_keys[4]`: slot 2 = keyareakey (`0x04 * 16`), ECB-encrypted with `key_area_key_application_XX`

**Step 6: Encrypt sections** (`nca.c:788-843`)
- WITHOUT `--plaintext`: encrypt each section with AES-CTR(titlekey, counter=media_offset >> 4)
- WITH `--plaintext`: skip encryption (FsHeader still says CRYPT_CTR/BKTR so emulators know how to read)

**Step 7: Sign + encrypt header** (`nca.c:834-471`)
- `fixed_key_sig`: random/zero/static signature (default: zeros)
- `npdm_key_sig`: RSA-2048-PSS-SHA256 over header[0:0x200] with ACID private key
- Encrypt header with AesXts(header_key, tweak=0, sector_size=0x200)
- Write final header at file offset 0

**Step 8: Final hash** (`nca.c:856-891`)
- Compute SHA-256 of entire NCA file
- Rename: `Program.nca` → `<sha256[0:32]>.nca`

**Source:** `sources/hacPack/nca.c` — see `nca_create_program()`, `nca_write_padding()`, `nca_calculate_section_hash()`, `nca_encrypt_section()`.

### Titlekey flow: `.tik` → `title.keys` → NCA decryption

The titlekey lifecycle spans three tools. The **key point**: `title.keys` stores the **encrypted** titlekey (exactly as found in the `.tik`), and the reader (hac2l/hactool) decrypts it at read time with a **titlekek**. Yanu never decrypts it.

**1. yanu reads the `.tik` raw** (`crates/hac/src/vfs/ticket.rs`):
- `rights_id` = bytes at tik offset `0x2A0`
- `title_key` = bytes at tik offset `0x180`
- **No decryption, no validation** — pure offset reads into the ticket file.
- `Display` for it is `hex(rights_id)=hex(title_key)`.

**2. yanu stores it to `title.keys`** (`crates/hac/src/utils/mod.rs`):
- `clear_titlekeys()` deletes the file first.
- `store_titlekeys()` writes `DEFAULT_TITLEKEYS_PATH` = `~/.switch/title.keys` (SWITCH_DIR + `title.keys`), one `hex=hex` line per key, joined with `"\n"` plus a trailing `"\n"`.
- In `update_nsp()` (`crates/hac/src/utils/update.rs`) both base and update tickets are written before the reader runs: `store_titlekeys([&base.title_key, &update.title_key].filter_map(...))`.

**3. The reader decrypts it with a titlekek**:

- **hac2l** (`hactool_processor.nca.cpp:79-110`): when an NCA has a non-zero `rights_id`, it looks up the encrypted titlekey in the titlekeys file, then calls `spl::PrepareCommonEsTitleKey(access_key, encrypted_titlekey, key_generation)` and passes the resulting key to `NcaReader::SetExternalDecryptionKey()`.
- **Atmosphere SPL** (`spl_secure_monitor_api.os.generic.cpp`): `PrepareCommonEsTitleKey` computes `pkg1_gen = max(KeyGeneration_1_0_0, generation - 1)` and does `DecryptWithEsCommonKey(..., EsCommonKeyType_TitleKey)` — i.e. **AES-ECB-decrypt of the titlekey with the titlekek** for that key generation.
- **NcaReader::GetKeyGeneration()** = `NcaHeader::GetProperKeyGeneration()` = `max(key_generation, key_generation_2)` (`fssystem_nca_header.cpp:20-22`).
- **hactool** (`nca.c:424-429`, `nca.c:459-465`) does the same with different indexing:
  - `crypto_type = max(crypto_type1, crypto_type2)`, then `crypto_type--` (so NCA generations 0/1 → titlekek index 0, generation 2 → index 1, ...).
  - `dec_titlekey = AES-ECB-decrypt(titlekeks[crypto_type], titlekeys[rights_id])`.

**4. hacPack creates the `.tik`** (`sources/hacPack/ticket.c:26-62`): the ticket body is a 704-byte template (`ticket_files.h` `TICKETTIKSIZE=704`). It:
- AES-ECB-**encrypts** the titlekey with `titlekeks[keygeneration - 1]` and writes it at offset `0x180`;
- writes the keygeneration byte at offset `0x285`;
- writes `rights_id` at offset `0x2A0`.

These are exactly the offsets yanu reads (0x180/0x2A0), so the pipeline round-trips: hacPack encrypts with a titlekek → yanu copies the ciphertext into `title.keys` → hac2l/hactool decrypt it with the same titlekek.

**Stardew Valley update NCA concrete numbers** (for the test fixture):
- Header `crypto_type[0x206] = 2`, `crypto_type2[0x220] = 3` → hactool `crypto_type = max(2,3) - 1 = 2` → `titlekek_02`.
- Ticket: encrypted titlekey @`0x180` = `208d250942dac283a5e5d6985bbf5fd4`, keygeneration @`0x285` = 3, rights_id @`0x2A0` = `0100e65002bb88000000000000000003`.
- `titlekek_02`-decrypted titlekey = `c58252a27a72b38cd03c35b583aa1743`. Note this key still failed to decrypt the BKTR tables to valid data in our tests (see BKTR divergence section).

### yanu update orchestration (`crates/hac/src/utils/update.rs`)

Yanu is an **orchestrator only** — it contains no crypto/BKTR logic. `update_nsp()`:
1. Creates `readers = [Hactoolnet, Hac2l]` and `packer = Hacpack` backends.
2. `clear_titlekeys()`, unpacks both NSPs with `nsp_extractor` (`unpack()`), derives titlekeys from both `.tik`s (`derive_title_key`), `store_titlekeys()`.
3. Finds base Program NCA and update Program/Control NCAs using the readers.
4. Unpacks Control NCA RomFS → reads NACP for the application name/version.
5. Calls `base_nca.unpack_all(&update_nca, romfs_dir, exefs_dir)` → **the error is deliberately ignored** (`_ = ... // !Ignoring err`). This runs `hac2l --basenca base.nca update.nca --romfsdir ... --exefsdir ...`.
6. `Nca::pack_program()` → `hacpack --keyset prod.keys --type nca --ncatype program --plaintext --exefsdir --romfsdir --titleid --outdir`.
7. `Nca::create_meta()` → `hacpack --type nca --ncatype meta` (Application CNMT).
8. `Nsp::pack()` → `hacpack --type nsp` on the NCA directory.

---

## Overview

The `--update` feature applies a title update to a base game and produces a single installable NSP where the update's Program NCA is physically merged with the base RomFS (a "yanu-style update"). This mirrors the hacpack/yanu pipeline.

## What exactly is a "yanu-style update"?

Yanu (`nozwock/yanu`) is a CLI tool written in Rust that orchestrates **external tools** (hac2l, hacpack, hactool/hactoolnet). It does **NOT** implement any BKTR/crypto/NCA logic itself. Yanu is purely an orchestrator.

When yanu processes `base.nsp` + `update.nsp` → `updated.nsp`, it does:

1. **Unpack both NSPs** (using hactool or hactoolnet) into temp directories
2. **Derive titlekeys** from both `.tik` files, write them into a temp keys file
3. **Call hac2l with `--basenca`**:
   - Command: `hac2l base_program.nca update_program.nca --romfsdir <tmp/romfs> --exefsdir <tmp/exefs>`
   - Hac2l internally: opens both NCAs via Stratosphere's filesystem stack, detects that the update NCA has a BKTR RomFS (cryptoType=4), then uses `StorageOnNca::CreateWithPatchWithContext(base_reader, update_reader, section_index)` to stream-merge the BKTR delta into the base RomFS
   - Output: `romfs/` directory = merged plaintext RomFS; `exefs/` directory = update ExeFS files (plaintext)
4. **Call hacpack to pack the merged data into a new Program NCA**:
   - Command: `hacpack --type nca --ncatype program --plaintext --exefsdir <tmp/exefs> --romfsdir <tmp/romfs> --titleid <base_tid> --outdir <tmp/nca_dir>`
   - Hacpack: reads all files from `exefs/` and `romfs/` directories → builds ExeFS PFS0 + RomFS IVFC tree → packs into a Program NCA with `--plaintext` (cryptoType=1, no AES encryption on section data)
5. **Call hacpack to create a meta/CNMT NCA**:
   - Command: `hacpack --type nca --ncatype meta --titletype application --programnca <merged.nca> --controlnca <control.nca> --titleid <base_tid> --outdir <tmp/nca_dir>`
6. **Copy remaining files**: manual/publicdata NCAs from the update, base tik/cert, update tik/cert
7. **Call hacpack to pack everything into NSP** (PFS0): `hacpack --type nsp --outdir <final> <tmp/nca_dir>`

### Key insight

**The BKTR merge is done by hac2l**, which delegates to **Atmosphere/Stratosphere's** `StorageOnNca::CreateWithPatchWithContext()`. Yanu never touches BKTR tables directly. Hac2l is compiled from Atmosphere's source tree and uses the exact same BKTR implementation that the Switch OS itself uses.

### What we are reproducing

Our `--update` implementation in `fs/update.js` attempts to reproduce the **same pipeline** without external tools:

1. ✅ **Parse NSP containers** (PFS0) — matches yanu's unpack step
2. ✅ **Decrypt CNMT metadata** — matches yanu's titlekey/tik reading
3. ⚠️ **BKTR merge** — we re-implemented BKTR table parsing/decryption in `fs/bktr-merge.js` and `fs/bktr.js` **from scratch**, instead of calling hac2l. This is where our output diverges from yanu's.
4. ✅ **Pack plaintext Program NCA** — `packPlaintextProgramNca()` mimics hacpack's `--plaintext` output
5. ✅ **Rebuild CNMT NCA** — matches hacpack's meta NCA creation
6. ✅ **Assemble output NSP** — PFS0 with all members

### Current difference vs reference output (STORM SWITCH BOX, Stardew Valley v0+v1310720)

| Metric | Reference | Our | Note |
|--------|------|-----|------|
| Merged Program NCA size | 699,123,712 B | 699,123,712 B | identical (RomFS data level padded to 0x4000) |
| Merged RomFS (IVFC Level 5) | 606,401,860 B | 606,401,864 B | +4 B (re-pack artifact, see below) |
| ExeFS PFS0 size | 91,409,104 B | 91,409,120 B | +16 B (PFS0 string-table alignment; absorbed by 0x200 section padding → 0 B to total) |
| Top-level NSP PFS0 | 272 B | 288 B | +16 B (PFS0 string-table alignment; the **only** total-size difference) |
| main.npdm ACID | zeroed (`0x80..0x280`) | original (update NCA) | ACID key pair variants (see below; no size/functional impact) |
| CNMT NCA | `ee048d85...` | `931aec3a...` | Different hash |

**PFS0 string-table alignment (one root cause, two instances):** our `PFS0Writer` (fs/pfs0.js) aligns the **whole** PFS0 header to 0x20, while hacpack aligns only the **string table** (`pfs0.c:121`, `(stringtable_offset + 0x1f) & ~0x1f`). It manifests in two PFS0s: the **top-level NSP** PFS0 (container header, not 0x200-rounded → the +16 B shows up in the total) and the **ExeFS** PFS0 (inside the Program NCA, whose section is 0x200-rounded → the +16 B is absorbed, 0 B to total). Both match Python nsz and Nintendo's original update NCA (`sts=0x30`); we keep our variant.

**main.npdm ACID key pair (three variants — no size or functional impact):** the `main.npdm` in the Program NCA ExeFS embeds the **ACID** (Application ID) at `acid_offset=0x80` (confirmed by `scripts/analyze_npdm.mjs`): `signature[0x100]` (`0x80..0x180`) + `modulus[0x100]` (`0x180..0x280`) — the ACID's RSA-2048 key pair, i.e. the title's **cryptographic authorization block** (for eShop titles, signed with Nintendo's ACID private key). All variants are the same 0x200 bytes (no size impact), and the ACID is **not enforced** for plaintext/dev NCAs — integrity comes from the IVFC hash trees, not the ACID — so there is no functional impact either. Only the 0x200 bytes of content differ:

| Variant | signature (`0x80..0x180`) | modulus (`0x180..0x280`) | Pair |
|---|---|---|---|
| Reference (STORM SWITCH BOX) | zeroed | zeroed | invalid |
| yanu/hacpack (documented invocation above: no `--nosignncasig2`, no `--acidsigprivatekey`) | original | replaced with the selfgen key (`rsa_keys.h`, `0xbd 0x54 0x73…`) by `npdm_process()` (`npdm.c`) | invalid (signature does not match the modulus) |
| **Ours** | original | original (`main.npdm` copied verbatim from the update NCA) | **valid** (signature matches the modulus — the title's real ACID) |

Why repacks invalidate or replace the ACID: a repack has no ACID private key (can't re-sign), and the original ACID is tied to the source title's titlekey — meaningless for the new **plaintext** NCA. We keep the original: it matches the source NCA byte-for-byte, is the only *valid* variant, and the update shares the base's titleId (no foreign title data). No reason to corrupt a valid block.

Both are valid, installable NCAs with correct structure (IVFC tree, FsHeaders, section hashes). Our merged RomFS is the exact level-5 data region of the update NCA (byte-identical to the update's declared IVFC data, verified via hash chain level4→level5, a full RomFS table walk, and `scripts/analyze_romfs.mjs`/`scripts/diff_romfs.mjs`). The +4 B vs the reference is a **padding/alignment artifact**, not a content difference: all 3,554 file entries, every blob size, and all table sizes are identical. The gap between the blob area and `dir_hash_table_ofs` holds real data (a ~512-byte tail of `manifest.txt` — its blob is truncated and the file list continues there) followed by zero padding; Nintendo aligns `dir_hash_table_ofs` to 8 (0x2421f048 → 7 pad bytes) while hacPack `romfs_build()` aligns to 4 (0x2421f044 → 3 pad bytes). Removing our 4 pad bytes reproduces the reference byte-for-byte.

Our implementation does all four steps in a single `update()` function in `fs/update.js`.

---

## Yanu/hacpack Pipeline (reference)

```
base.nsp          update.nsp
    │                  │
    ├─ nsp_extractor   ├─ nsp_extractor
    │   (hactoolnet)   │   (hactoolnet)
    ▼                  ▼
base_nca_dir     update_nca_dir
    │                  │
    │    ┌─────────────┤
    │    │ hac2l --basenca base.nca update.nca \
    │    │        --romfsdir <dir> --exefsdir <dir>
    │    │
    │    ├─ extracts merged RomFS → romfs/
    │    └─ extracts update ExeFS → exefs/
    │
    │    ┌─────────────────────────────────────┐
    │    │ hacpack --keyset prod.keys           │
    │    │   --type nca --ncatype program        │
    │    │   --plaintext --exefsdir exefs/       │
    │    │   --romfsdir romfs/ --titleid <tid>   │
    │    │   --outdir <dir>                      │
    │    │                                       │
    │    │ Creates: patched.nca                  │
    │    │   - plaintext section data (no AES)   │
    │    │   - IVFC header + hash tree per sec   │
    │    │   - cryptoType=3/4 in FsHeader        │
    │    └─────────────────────────────────────┘
    │
    │    ┌─────────────────────────────────────┐
    │    │ hacpack --keyset prod.keys           │
    │    │   --type nca --ncatype meta           │
    │    │   --titletype application             │
    │    │   --programnca patched.nca            │
    │    │   --controlnca control.nca            │
    │    │   --titleid <tid> --outdir <dir>      │
    │    │                                       │
    │    │ Creates: <sha256>.cnmt.nca            │
    │    │   - Application CNMT v{update_ver}    │
    │    │   - content entries reference patched  │
    │    └─────────────────────────────────────┘
    │
    │    ┌─────────────────────────────────────┐
    │    │ hacpack --keyset prod.keys           │
    │    │   --outdir <out> <nca_dir>           │
    │    │                                       │
    │    │ Creates: final.nsp                    │
    │    │   - CNMT NCA + tik/cert               │
    │    │   - patched.nca (Program)             │
    │    │   - manual/data/publicdata NCAs       │
    │    │   - update tik/cert                   │
    │    └─────────────────────────────────────┘
    ▼
final.nsp (single installable NSP)
```

### Key details about each hacpack command

**`--plaintext`** — tells hacpack: "the files in exefs_dir/romfs_dir are already plaintext. Don't encrypt them with AES-CTR/BKTR, just pack them into the NCA with the FsHeader cryptoType set to 3/4 so the emulator knows how to read them." Without `--plaintext`, hacpack would encrypt every byte of the section data with the titlekey.

### Source code references

Never reverse-engineer from packed output when the reference source is public — read it directly (`XITRIX/hacPack` is the maintained fork of `hexkyz/hacpack`):

| Area | Source |
|------|--------|
| **yanu pipeline orchestrator** — `update_nsp()` calls hac2l + hacpack + hactool | `crates/hac/src/utils/update.rs` — https://github.com/nozwock/yanu/blob/main/crates/hac/src/utils/update.rs |
| **yanu hac2l integration** — `--basenca base.nca update.nca --romfsdir --exefsdir` | `crates/hac/src/vfs/nca.rs` — https://github.com/nozwock/yanu/blob/main/crates/hac/src/vfs/nca.rs (`unpack_all()`) |
| **yanu hacpack integration** — `Nca::pack_program()` calls hacpack `--type nca --ncatype program --plaintext` | `crates/hac/src/vfs/nca.rs:178` — https://github.com/nozwock/yanu/blob/main/crates/hac/src/vfs/nca.rs#L178 |
| **yanu meta NCA** — `Nca::create_meta()` calls hacpack `--type nca --ncatype meta` | `crates/hac/src/vfs/nca.rs:230` |
| **yanu backend selection** — hacpack/hac2l/hactool binaries are built from source | `crates/hac/src/backend.rs` — https://github.com/nozwock/yanu/blob/main/crates/hac/src/backend.rs |
| **hac2l BKTR merge** — `ProcessAsNca()` → `StorageOnNca::CreateWithPatchWithContext()` | `source/hactool_processor.nca.cpp:178` — https://github.com/Atmosphere-NX/hac2l/blob/master/source/hactool_processor.nca.cpp#L178 |
| **Stratosphere BKTR** (used by hac2l) — `CreateWithPatchWithContext()` does the actual BKTR patching | Atmosphere repo `stratosphere/kernel/loader/nca/nca_storage_on_nca.cpp` — https://github.com/Atmosphere-NX/Atmosphere |
| **hacpack Program NCA packing** — `nca_create_program()`: ExeFS PFS0 + hash table, RomFS IVFC tree, section order by media offset | `nca.c` — https://github.com/XITRIX/hacPack/blob/master/nca.c |
| **hacpack Meta/CNMT NCA** — `nca_create_meta()`: PFS0 section, sectionStart/PFS0 offset, cryptoType | `nca.c:495` |
| **hacpack section encryption** — `nca_encrypt_section()` + counter (`start_offset >> 4`) | `nca.c:788`, `nca.c:846` (`nca_update_ctr`) |
| **hacpack XTS header encryption** — `aes_xts_encrypt(..., 0xC00, 0, 0x200)` | `nca.c:781` (`nca_encrypt_header`) |
| **hacpack section hash** — `sha256(FsHeader[0:0x200])` | `nca.c:765` (`nca_calculate_section_hash`) |
| **hacpack key area encryption** — `key_area_key_application` slot 2, AES-ECB | `nca.c:774` (`nca_encrypt_key_area`) |
| **hacpack IVFC hash-tree** — 6 levels, 0x4000 block size, padded to 0x4000 | `ivfc.c` — https://github.com/XITRIX/hacPack/blob/master/ivfc.c |
| **hacpack PFS0 build** — `pfs0_create_hashtable()`, block size 0x1000 for ExeFS | `pfs0.c` — https://github.com/XITRIX/hacPack/blob/master/pfs0.c |
| **hactool BKTR reference** — `bktr.h` structs, `nca_update_bktr_ctr()` | https://github.com/SciresM/hactool |

---

## Our Implementation

### Single `update()` function

`fs/update.js:199` — one async function that does everything:

```
update(baseReader, updateReader, outputWriter, { keys, log, progress })
```

**Phases:**

1. **Parse both containers** — read PFS0/XCI headers, find `.cnmt.nca` entries, decrypt/parse CNMT metadata
2. **Identify base vs update** — exactly one must have `titleType=0x80` (Application CNMT); the other is the patch
3. **Extract titlekeys** — from both base and update `.tik` files via `AES-ECB(titlekek_02, tik[0x180:0x190])`
4. **Determine merge strategy** — check if update Program NCA has BKTR section (cryptoType=4)
5. **Merge Program NCA** — BKTR RomFS merge or ExeFS-only merge → `packPlaintextProgramNca()`
6. **Rebuild CNMT NCA** — `rebuildCnmtNca()` — points at merged Program NCA
7. **Assemble output NSP** — collect all NCAs, tickets, certs → PFS0 → write to output

### Merge strategies

Two update Program NCA patterns are handled:

**BKTR RomFS merge** (most updates):
- Update Program NCA has a RomFS section with `fsType=3, cryptoType=4` (BKTR)
- Our approach: we parse the BKTR relocation/subsection tables **manually** in `fs/bktr.js`, then apply them in `fs/bktr-merge.js`. We re-implemented BKTR decryption (AesCtrEx with patch-key + ctrVal big-endian) from scratch, based on hactool/SciresM/hactool source.
- Result: full merged RomFS + update ExeFS → new Program NCA
- ⚠️ This manual BKTR implementation previously produced a RomFS **~1.26 MB larger** than yanu's (which uses Stratosphere's BKTR implementation via hac2l); fixed in `fs/bktr-merge.js` by slicing only the IVFC level-5 data region instead of the whole virtual section — the remaining difference vs yanu is +4 B (a padding/alignment artifact, see the table above). Both NCAs are valid and installable, but hashes differ.

**ExeFS-only merge** (scene updates, patches with full RomFS):
- Update Program NCA has no RomFS section, only ExeFS
- Use base RomFS as-is + update ExeFS → new Program NCA

### Merged Program NCA layout

`packPlaintextProgramNca()` in `fs/nca-pack.js` produces a Program NCA matching yanu/hacpack:

```
NCA Header (0xC00 bytes, encrypted with AesXts, cryptoType=2)
  Magic: NCA3
  ContentType: 0x00 (Program)
  CryptoType: 0x02 (AesXts header encryption)
  KeyIndex: 0x01 (header_key_01, masterKey=1)
  TitleId: base titleId (reversed)
  KeyArea: key_area_key_application_0a (slot 2)
  Section table:
    [0] ExeFS: mediaOffset=0x243cca00, mediaEndOffset=...
    [1] RomFS: mediaOffset=0x00004000, mediaEndOffset=...

Section 1 (RomFS) — at NCA offset 0xC00
  IVFC header (0xE0 bytes) + hash tree (6 levels, 64KB blocks)
  RomFS data (merged, plaintext)
  FsHeader at 0x400+0xE0:
    partitionType=0x00 (RomFS)
    fsType=0x03 (RomFS)
    cryptoType=0x04 (BKTR/IVFC)
    sectionStart = IVFC tree size
    sectionSize = RomFS data size

Section 0 (ExeFS) — at NCA offset after RomFS
  IVFC header (0xE0 bytes) + hash tree (6 levels, 64KB blocks)
  PFS0 data (ExeFS, plaintext)
  FsHeader at 0x400+0xE0:
    partitionType=0x01 (PFS0)
    fsType=0x02 (ExeFS)
    cryptoType=0x03 (AesCtr)
    sectionStart = IVFC tree size
    sectionSize = ExeFS data size

Section hashes: sha256(FsHeader) at 0x280 and 0x2A0
```

### Section order

Sections are ordered by **lowest media offset first**:
- **Section [1] = RomFS** at `mediaOffset=0x4000` (lowest)
- **Section [0] = ExeFS** at `mediaOffset=0x243cca00` (higher)

The section table indices [0]/[1] are independent of media offsets. This matches both the base game layout and yanu's output.

### IVFC hash tree

`buildIvfcHashTree(data)` builds a 6-level hierarchical SHA-256 hash tree per section:

```
Level 6 (bottom): hash each 64KB block of the data → N * 32 bytes
Level 5:        hash each 64KB block of level 6 hashes
...
Level 1:        hash each 64KB block of level 2 hashes
Level 0:        hash each 64KB block of level 1 hashes (used for master hash)

IVFC header (0xE0 bytes):
  [0..3]   Magic: "IVFC" (0x43465649 LE)
  [4..7]   ID: 0x20000
  [7]      Master hash size: 0x20
  [8..9]   Num levels: 7 (1 header + 6 IVFC levels)
  [0x10..] Level headers (each 0x18 bytes):
    block_size (4 bytes) = 0x4000 (16KB)
    logical_offset (8 bytes LE)
    hash_data_size (4 bytes)
  [0xA0..] Master hash: SHA-256(level 0 data)
```

### Header encryption

The header is double-encrypted:

1. Build header → write section hashes at 0x280/0x2A0
2. Encrypt with AesXts(header_key, tweak=0)
3. Write encrypted header into NCA buffer
4. Update NCA size field (0x208-0x20F) — now that everything is assembled
5. Re-encrypt with AesXts(header_key, tweak=0) — overwrites header

This ensures the header's own hash table (which hashes all decrypted header bytes) is consistent with the final header content including the NCA size.

### CNMT rebuild

`rebuildCnmtNca()` modifies the base CNMT:

1. Copy all content entries from the update CNMT (type=6 DeltaFragment entries dropped)
2. If a merged Program NCA exists, replace the type=1 Program entry with the merged NCA's sha256/contentId/size
3. Copy the base Application CNMT's extended header (PatchId, RequiredSystemVersion) verbatim
4. Set version to the update version
5. Build PFS0 wrapping the CNMT binary
6. Build hierarchical SHA-256 hash table (htable) for the PFS0
7. Patch: htable_hash (0x408), section_hash (0x280) into decrypted header
8. Re-encrypt header and section

### Output NSP assembly

The output NSP contains:
- Rebuilt CNMT NCA (named by its own sha256)
- Merged Program NCA (named by its own sha256, when BKTR/ExeFS-only merge)
- Update Manual/PublicData NCAs (decompressed from NSZ/NCZ if needed)
- Base `.tik` + `.cert` (for the Application)
- Update `.tik` + `.cert` (for the update Program NCA, if present)

> **Member names are NOT replaceable.** Theory: replace the hash in the PFS0 member name with a
> fixed name ("program.nca"). Tested on emulator installs — disproven: emulators match the filename
> against the CNMT's content hash, so members MUST keep their real `<contentId>.nca` /
> `<contentId>.cnmt.nca` names. Hence the merged Program NCA's sha256 is computed in advance
> (`preparePlaintextProgramNca()` — deterministic, depends only on exefs/romfs/keys) so the PFS0
> header is built once with real names and written at offset 0, no seek-back.

### Member order (yanu NSP sorting)

**yanu does not sort the NSP members.** It has no ordering logic — it passes a directory of
NCAs to hacpack, and hacpack's `pfs0_build()` (`pfs0.c:65`) enumerates the directory with
`readdir()` **without any sorting**. So the PFS0 member order is whatever order the filesystem
returns the directory entries in — in practice, **the order the NCAs were written into the
`nca_dir`** (filesystem creation order). "How yanu sorts files" = **the processing order of its
pipeline, not an explicit sort**.

yanu's processing order is fixed by `update_nsp()` (`crates/hac/src/utils/update.rs`):
1. Control NCA is moved into `nca_dir` first (`fs::rename`)
2. `pack_program()` writes the merged Program NCA
3. `create_meta()` writes the CNMT NCA
4. All other NCAs (Manual/PublicData) are copied in via `Nsp::pack()`'s `ncadir` — the manual NCA
   lands directly after the Program NCA, "attached" to it (there is no separate step that places it).

**Observed reference (yanu via StormX), Stardew Valley v0+v1310720:**

| # | Member | contentId | Type |
|---|--------|-----------|------|
| 1 | Program | `8dc3f778…` | Program |
| 2 | Manual | `99636bbd…` | Manual (attached after Program) |
| 3 | Control | `af613c75…` | Control |
| 4 | CNMT | `ee048d85…` | Meta |

**Our output matches this exactly** (verified member-by-member with
`scripts/inspect_entries.mjs`):

| # | Member | contentId | Type |
|---|--------|-----------|------|
| 1 | Program | `7c3bbb53…` | Program |
| 2 | Manual | `99636bbd…` | Manual (attached after Program) |
| 3 | Control | `af613c75…` | Control |
| 4 | CNMT | `931aec3a…` | Meta |

The Manual/Control members are **the same physical NCAs** as in the update (identical
contentIds/hashes) — we do not rebuild them. The order is produced in `fs/update.js` by:
1. Program NCA first (it is the merged/repacked one)
2. Remaining non-meta NCAs from the update's CNMT content entries, **sorted by name**
   (Manual `99636bbd…` < Control `af613c75…` — this is why the manual lands right after Program)
3. CNMT NCA last

This ordering is byte-independent: any ordering is valid for install (members are located via
their `<contentId>.nca` names matched against the CNMT), but keeping yanu's processing order
gives output that matches the reference layout.

---

## Key files

| File | Role |
|------|------|
| `fs/update.js` | Main `update()` function, orchestrates the pipeline |
| `fs/nca-pack.js` | `packPlaintextProgramNca()` — Program NCA repacking |
| `fs/nca-pack.js` | `extractExefs()` / `extractRomfs()` — section extraction |
| `fs/bktr-merge.js` | `mergeRomFS()` — BKTR relocation table application |
| `fs/bktr.js` | Low-level BKTR: table parsing, AesCtrEx decryption |
| `fs/ncz.js` | NCZ decompressor for compressed inputs |
| `crypto/sha256.js` | SHA-256 for hash tree, section hashes, CNMT |

## Comparison: hacPack vs nsz-js

### NCA header construction

| Field | hacPack (`nca.c`) | nsz-js (`nca-pack.js`) | Match |
|-------|-------------------|------------------------|-------|
| `magic` | `"NCA3"` | `"NCA3"` | ✅ |
| `distribution` | 0 or 1 (gamecard) | 0 (not gamecard) | ✅ (we don't support gamecard yet) |
| `content_type` | from `settings->nca_type` | 0x00 (Program) | ✅ |
| `crypto_type` | 0 (kg1) or 2+ | 0 (kg1) | ✅ |
| `title_id` | reversed (LE) | reversed (LE) | ✅ |
| `sdk_version` | `settings->sdk_version` (default 0x000C1100) | 0x000C1100 | ✅ |
| `section_entries[i].media_offset` | file_pos / 0x200 | offset / 0x200 | ✅ |
| `section_entries[i]._0x8[0]` | always 0x01 | always 0x01 | ✅ |
| `rights_id` | all zeros (no-titlekey) | all zeros | ✅ |
| `fixed_key_sig` | zeros (default) | zeros | ✅ |
| `npdm_key_sig` | RSA-signed with ACID key | zeros | ❌ we skip ACID signature |

### Section ordering

| Tool | Approach |
|------|----------|
| hacPack | Writes ExeFS first, then RomFS. Section indices match write order: sec0=ExeFS, sec1=RomFS. Media offsets follow: ExeFS at `0x6 * 0x200 = 0xC00`, RomFS after ExeFS. |
| nsz-js | Writes ExeFS first at `sec0Start=0xC00`, RomFS after. Same media layout. |

✅ Media offsets match. However:

| Metric (Stardew Valley v0+v1310720) | hacPack/yanu | nsz-js | Note |
|-----------------------------------|--------------|--------|------|
| ExeFS media_start_offset | `0x6` (0xC00) | `0x6` (0xC00) | ✅ |
| RomFS media_start_offset | after ExeFS | after ExeFS | ✅ |
| ExeFS PFS0 size | 91,409,104 B | 91,409,120 B | +16 B |
| RomFS (IVFC Level 5) | 606,401,860 B | 606,401,864 B | +4 B (re-pack artifact) |

### IVFC hash tree

| Aspect | hacPack (`ivfc.c`) | nsz-js (`nca-pack.js`) | Match |
|--------|-------------------|------------------------|-------|
| Block size | 0x4000 | 0x4000 | ✅ |
| Num hash levels | 5 (plus data = 6 total) | 5 (plus data = 6 total) | ✅ |
| Hash algorithm | SHA-256 per block | SHA-256 per block | ✅ |
| Level padding | to 0x4000 | to 0x4000 | ✅ |
| Master hash | SHA-256(entire level-0 file) | SHA-256(entire level-0 file) | ✅ |
| IVFC header | 0xE0 bytes, magic/id/levels/master_hash | 0xE0 bytes, same structure | ✅ |
| IVFC num_levels | 7 (header + 6 levels) | 7 | ✅ |

✅ IVFC structure matches exactly. Difference in RomFS size is due to BKTR merge divergence, not IVFC.

### PFS0 hash table

| Aspect | hacPack (`pfs0.c`) | nsz-js (`nca-pack.js`) | Match |
|--------|-------------------|------------------------|-------|
| Block size (ExeFS) | 0x10000 | 0x10000 | ✅ |
| Block size (Meta CNMT) | 0x1000 | 0x1000 | ✅ |
| Hash algo | SHA-256 per block | SHA-256 per block | ✅ |
| Padding | to 0x200 | to 0x200 | ✅ |
| Master hash | SHA-256(raw hash table, no padding) | SHA-256(raw hash table, no padding) | ✅ |

✅ PFS0 hash tables match.

### Key area encryption

| Aspect | hacPack (`nca.c:774`) | nsz-js (`nca-pack.js`) | Match |
|--------|-----------------------|------------------------|-------|
| Key block layout | [0, 0, keyareakey, 0] × 0x10 | [0, 0, keyareakey, 0] × 0x10 | ✅ |
| Encryption | AES-ECB(key_area_key_application_XX) | AES-ECB(key_area_key_application_00) | ✅ |
| Slot used | slot 2 (keyareakey) | slot 2 | ✅ |

### Header encryption

| Aspect | hacPack (`nca.c:781`) | nsz-js (`nca-pack.js`) | Match |
|--------|-----------------------|------------------------|-------|
| Algorithm | AesXts(header_key) | AesXts(header_key) | ✅ |
| Sector size | 0x200 | 0x200 | ✅ |
| Tweak | 0 | 0 | ✅ |
| Range | first 0xC00 bytes | first 0xC00 bytes | ✅ |

### Section encryption (plaintext mode)

| Aspect | hacPack (`--plaintext`) | nsz-js | Match |
|--------|------------------------|--------|-------|
| Data encrypted? | No (plaintext) | No (plaintext) | ✅ |
| FsHeader.crypt_type | 0x01 (CRYPT_NONE) | 0x01 (CRYPT_NONE) | ✅ |
| FsHeader.fs_type | 1 (PFS0) / 0 (RomFS) | 1 / 0 | ✅ |

### Padding

| Context | hacPack | nsz-js | Match |
|---------|---------|--------|-------|
| Section data padding | to 0x200 | to 0x200 | ✅ |
| IVFC level padding | to 0x4000 | to 0x4000 | ✅ |
| PFS0 htable padding | to 0x200 | to 0x200 | ✅ |
| NCA total size | natural (header + sections) | natural | ✅ |

### Key differences / missing features

| Feature | hacPack | nsz-js | Status |
|---------|---------|--------|--------|
| ACID signature (`npdm_key_sig`) | RSA-signed with ACID private key | zeros | ❌ skipped (Atmosphere ignores anyway) |
| Gamecard NCA (`distribution=1`) | Supported | Not supported | ⚠️ not needed for digital NSPs |
| Titlekey-based encryption | Supported (encrypted NCAs) | Not used (--plaintext only) | ✅ correct for yanu pipeline |
| Multiple section types | Program (ExeFS+RomFS), Meta (PFS0), RomFS-only | Program, Meta | ✅ covers yanu use cases |
| BKTR merge | Delegated to hac2l/Stratosphere | Manual re-implementation | ✅ output matches (RomFS +4 B padding only) |

### BKTR divergence root cause

Our BKTR implementation (`fs/bktr.js`, `fs/bktr-merge.js`) is written from scratch, based on hactool source. Yanu uses Stratosphere's BKTR via hac2l, which is the same code the Switch OS uses.

**Investigation (2026-08-13):**

1. **Counter construction**: Changed `decryptPatchRegion` to use Stratosphere-style counter (secure_value BE + ctrVal BE + fileOffset/16 BE) instead of reversed section_ctr. However, FsHeader.aes_ctr_upper_iv is ALL ZEROS for Stardew Valley update NCA, so both counters produce the same result (zeros). Counter fix changed nothing.

2. **FsHeader decryption**: Our XTS decrypt with sector=0 correctly decrypts:
   - Magic (NCA3), version (2), fsType, IVFC magic, IVFC num_levels (7)
   - BUT NcaPatchInfo area (FsHeader[0x100-0x13F]) is ALL ZEROS
   - AND IVFC level headers have wrong hash_data_size values (64 bytes instead of ~16KB)
   - This suggests our XTS implementation partially matches but has subtle differences vs mbedtls XTS used by hacPack

3. **Size discrepancy resolved (2026-08-14)**: Our merged RomFS = 606,401,864 bytes = exactly the update NCA's IVFC level-5 `hash_data_size` (0x2424f548); yanu's rebuilt RomFS = 606,401,860 bytes (0x2424f544, 4 bytes smaller). The original bug was outputting the whole virtual BKTR section (`relocBlock.totalSize` = 607,663,616 B: IVFC header + hash levels 0-4 + data + 184-byte tail) instead of only the level-5 data region. hactool/hac2l use the same slice: `romfs_offset = ivfc_levels[IVFC_MAX_LEVEL-1].data_offset` (hactool nca.c:1240). The remaining 4-byte gap vs yanu was **fully localized** with `scripts/analyze_romfs.mjs`/`scripts/diff_romfs.mjs`: all 3,554 entries, all blob sizes and table sizes are identical; the gap between blob area end (0x2421ee41) and `dir_hash_table_ofs` contains a ~512-byte tail of `manifest.txt` (blob truncated at 118,257 B, list continues in the gap) followed by zero padding. Nintendo aligns `dir_hash_table_ofs` to 8 (0x2421f048, 7 pad bytes), hacPack `romfs_build()` to 4 (0x2421f044, 3 pad bytes). Deleting our 4 pad bytes `[0x2421f044, 0x2421f048)` and subtracting 4 from the header offsets reproduces yanu byte-for-byte. Our level-5 slice byte-identically matches the update's declared data.

4. **Root cause (resolved)**: Output size used `relocBlock.totalSize` (whole virtual section) instead of the level-5 data region. Fixed in `fs/bktr-merge.js` — `merged` is built at full virtual size (level-4's last hash block covers the trailing virtual-image tail, so this is required for the hash chain to verify), and `mergedData = merged.subarray(dataLevelOffset, dataLevelOffset + dataLevelSize)` is the actual RomFS blob passed to `packPlaintextProgramNca`.

**To match yanu exactly:** remove the 4 zero-pad bytes before `dir_hash_table_ofs` and decrement the header's table offsets by 4 (Nintendo aligns tables to 8, hacPack to 4). Not worth doing — our slice is the more faithful reproduction of Nintendo's original RomFS.

### Known RomFS anomaly: truncated `manifest.txt`

In the Stardew Valley update's RomFS the last file table entry `manifest.txt` (name_size=12) declares blob size **118,257 B**, but the file list **continues past the blob end** into the gap that precedes the tables. Bytes right after blob end (`0x2421ee41`) read ` \r\nTileSheets\joja_furnitureFront.xnb \r\nTileSheets\junimo_furniture.xnb …` — an uninterrupted continuation of the manifest file list. The ~512-byte remainder lives in the region `[blob_end, dir_hash_table_ofs)` that a reader treats as padding:

```
blob area    ...manifest.txt blob (118,257 B)     manifest-list tail (512 B)  pad  tables
              [0x24202050, 0x2421ee41)            [0x2421ee41, 0x2421f040)    [0x2421f040, dir_hash)
```

This anomaly is present **identically in both** the original update and yanu's rebuilt RomFS (same 512 non-zero bytes, same `0x0a` terminator position), so it is a Nintendo quirk of this update, not a bug in our merge. The gap region is inherited from the **base RomFS**: BKTR relocation entry covering the gap is marked `isPatch=true` but the subsection table has no patch for that offset, so BKTR merge preserves the base's gap as-is. The remaining 4-byte size difference vs yanu is unrelated to it — that is purely the table-alignment padding (8 vs 4) described above: hacPack `romfs_build()` computes `dir_hash_table_ofs = align64(file_partition_size + ROMFS_FILEPARTITION_OFS, **4**)` (sources/hacPack/romfs.c:410), while Nintendo's original builder aligned to **8**. The RomFS header structure itself (`romfs_header_t`: header_size, dir_hash_table_ofs/size, dir_table_ofs/size, file_hash_table_ofs/size, file_table_ofs/size, file_partition_ofs) is identical across all sources: hactool (ivfc.h:52-63), hacPack (romfs.h:42-53), libnx/switchbrew (romfs_dev.h). The manifest blob being truncated has no functional impact: the RomFS is valid, installs, and boots in emulators.

---

## Testing

- `test_update_e2e.mjs` — full E2E test on Stardew Valley v0+v1310720
- `verify_updated_output.mjs` — compare output NSP vs yanu reference (member-wise hash match)
- `bktr_verify_merged.mjs` — verify merged RomFS against yanu's output

## Verification on Stardew Valley v0+v1310720

```
Input:  base.nsp (877 MB) + update.nsz (667 MB compressed)
Output: 701,770,528 B / 4 members (Δ +16 B vs yanu = top-level PFS0 string-table alignment)
  - Merged Program NCA: 699,123,712 B (contentId=7c3bbb53…)
  - CNMT NCA: 931aec3a… (type 0x80, v1310720, 3 contents)
  - Control NCA: 2,476,032 B (af613c75…)
  - Manual NCA: 166,400 B (99636bbd…)

CNMT entries:
  type=1 ncaId=7c3bbb53… size=699123712 (merged Program)
  type=3 ncaId=af613c75… size=2476032 (Control)
  type=5 ncaId=99636bbd… size=166400 (PublicData)

Merged Program NCA structure:
  Header: cryptoType=0 (plaintext), keyIndex=0
  Section [0] ExeFS: cryptoType=0 (plaintext), 87.2 MiB
  Section [1] RomFS: cryptoType=0 (plaintext), 606,401,864 B (~579 MiB)
  IVFC: 6-level hash tree, 64KB blocks
```
