# Rules for AI Agents

## Start Checklist

- [ ] Read all `.md` files in the project root
- [ ] Check `IMPROVEMENTS.md` for completed tasks and planned improvements
- [ ] Check `CHANGELOG.md` for recent changes and remaining issues
- [ ] Check `TESTS.md` for test suite documentation and test vectors

### MD Files Reference

| File | Description |
|---|---|
| `AGENTS.md` | This file — rules, static files, workarounds |
| `NSZ-FORMAT-ANALYSIS.md` | NCZ/XCZ/NCA format specs, crypto types, Python nsz comparison, known bugs and fixes |
| `PLAN.md` | Action plan, completed steps, success criteria |
| `CHANGELOG.md` | Working components, recent fixes, remaining issues |
| `TESTS.md` | Test suite documentation, test vectors, how to run tests |
| `IMPROVEMENTS.md` | Improvement opportunities, planned fixes, and completed tasks |

## Update CHANGELOG.md After Changes

**Always update CHANGELOG.md after making functional changes.** Add entries under the appropriate section:
- New features or fixes → add to "Recent Changes" with date and description
- When sections grow long, move older entries to a collapsed `<details>` block

CHANGELOG.md is the single source of truth for what works and what doesn't.

### CHANGELOG numbering follows the new commit order

When rewriting/splitting history (e.g., splitting one commit into several, or reordering commits), the numbering and ordering of entries in `CHANGELOG.md` must follow the **order of the rewritten commits**, NOT be copied from the original commit(s). Each commit adds its entry with the next sequential number (its position in the new history). Do not preserve the original numbering if it conflicts with the new commit order.

### History rewrite verification

When rewriting/splitting history, always verify after the rewrite:
- `git diff <old tip> <new tip>` must be empty — the final tree must contain exactly the same content as the original, nothing lost or added.
- Each intermediate commit must be self-sufficient: its imports/dependencies resolve using only files present at that commit (nothing depending on changes from future commits).

### Force-push only on explicit request

Never force-push to a shared branch without asking the user first. When asking, state the divergence (e.g. `ahead X / behind Y`) and explain what the force-push will change.

## Static Files

**DO NOT manually edit files in the `static/` folder.**

The `static/` folder contains downloaded/copied dependencies for browser use:
- `static/zstddec.mjs` - Copied from `node_modules/zstddec/dist/zstddec-stream.modern.js` (ES Module, imports directly). WASM-based native zstd decoder. Used for streaming decompression in browser. Handles any window size.
- `static/prod.keys` - User-provided Nintendo Switch keys file

### How to update static files:

1. Update the npm packages:
   ```bash
   npm install zstddec@x.x.x
   ```

2. Copy the files to `static/` **WITHOUT ANY MODIFICATIONS**:
   ```bash
   cp node_modules/zstddec/dist/zstddec-stream.modern.js static/zstddec.mjs
   ```

3. **NO manual editing of static files** - If the original files don't work as-is:
   - Do workarounds in the **consuming code** (e.g., `crypto/zstd.js`), not in the static files
   - Document any workarounds in `AGENTS.md` under "Workarounds" section

### Source-first research

When reverse-engineering or implementing behavior from an external tool/library:
- **If the source is publicly available (GitHub, etc.) — read the source directly.** Don't guess, probe, or reverse-engineer from output files when the implementation is open source.
- Example: to understand how `hacpack --plaintext` packs NCAs, read `nca.c` in the hacpack repo instead of trying to reconstruct the structure from a packed NCA.

### Workarounds

When original files from npm don't work directly in the target environment:

- **Problem**: `DecompressionStream` API doesn't support `'zstd'` format in any browser — constructor throws `"Failed to construct 'DecompressionStream': Unsupported compression format: 'zstd'"`.
  **Solution**: Use `zstddec` (WASM-based native zstd) for all decompression in browser via `static/zstddec.mjs`. Imported in `crypto/zstd.js` and `fs/ncz.js`.

- **Problem**: `zstddec` streaming ESM build has a bug in `decode()` when passing explicit `uncompressedSize` — produces truncated/all-zeros output for large streams (>1GB).
  **Solution**: In `ncz.js` (around line 310), call `decoder.decode(compressedData, 0)` (auto-detect size). This works correctly: calls `ZSTD_findDecompressedSize` internally, falls back to streaming API if size is unknown.

- **Problem**: When `writePlaintextProgramNca` writes a Uint8Array via the SW adapter (`postMessage` with `transfer`), the buffer is detached. Subsequent reads of `.length` return 0 (spec: detached ArrayBuffer has byteLength 0). This caused the romPos calculation to omit the hash table size (0xB000), placing IVFC levels and RomFS data 0xB000 bytes too early — a backward write that corrupted the output.
  **Solution**: Snapshot all buffer lengths (`htableLen`, `exefsLen`, `levelLengths`) into local variables **before** any writes in `writePlaintextProgramNca` (`fs/nca-pack.js`). Same pattern applied defensively in `packProgramNcaStream`.

Browser HTML files load dependencies:
```html
<!-- zstddec.mjs is imported via ES module in crypto/zstd.js and fs/ncz.js -->
```

`zstddec.mjs` is imported directly as ES module (WASM binary is base64-embedded in the JS).

**DO NOT use import maps or CDN URLs** - the whole point of the `static/` folder is to enable offline use.

## Benchmarking

**Never write benchmark output to real disk repeatedly** — it wears the SSD. Benchmark rules:

- **Real-pipeline benchmarks**: run on the real `.nsz`/`.ncz` file with output **discarded** (stream to `/dev/null`, i.e. `writeChunk` that drops data). Do NOT write full decompressed output to disk just to measure throughput.
- **Micro-benchmarks** (e.g. AES primitives): use in-memory buffers (64 MiB), no disk I/O at all.
- Report **best-of-N** (≥3 runs) and **MB/s**, not wall time of a single run. Warm up before measuring.
- When comparing an optimization, verify **byte-identical output** vs. the reference implementation first (e.g. `verify_clean.mjs` pattern), then measure.
- Persist useful bench/verify scripts in the repo (`bench_*.mjs`, `test_*.mjs`) instead of throwing them away.

## Package Versions

Current versions (update this when upgrading):
- `zstddec`: 0.2.0 (use streaming ESM version: `zstddec/dist/zstddec-stream.modern.js`)


