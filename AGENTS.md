# Rules for AI Agents

## Read All MD Files on Start

**Always read all `*.md` files in the project root before starting work.** These contain critical context about the project:

- `AGENTS.md` — This file (rules, static files, workarounds)
- `NSZ-FORMAT-ANALYSIS.md` — NCZ/XCZ/NCA format specs, crypto types, Python nsz comparison, known bugs and fixes
- `PLAN.md` — Action plan, completed steps, success criteria
- `PROGRESS.md` — Working components, recent fixes, remaining issues
- `TESTS.md` — Test suite documentation, test vectors, how to run tests
- `FIXES_PLAN.md` — Planned fixes with file/line references
- `fix_converter.md` — Quick fix reference

These docs contain format specifications, crypto implementation details, and known issues that are essential for correct development.

## Static Files

**DO NOT manually edit files in the `static/` folder.**

The `static/` folder contains downloaded/copied dependencies for browser use:
- `static/aes-js.js` - Copied from `node_modules/aes-js/index.js` (UMD format, sets `window.aesjs` when loaded via `<script>` tag)
- `static/zstddec.mjs` - Copied from `node_modules/zstddec/dist/zstddec-stream.modern.js` (ES Module, imports directly). WASM-based native zstd decoder. Used for streaming decompression in browser. Handles any window size.
- `static/prod.keys` - User-provided Nintendo Switch keys file

### How to update static files:

1. Update the npm packages:
   ```bash
    npm install aes-js@x.x.x zstddec@x.x.x
   ```

2. Copy the files to `static/` **WITHOUT ANY MODIFICATIONS**:
   ```bash
   cp node_modules/aes-js/index.js static/aes-js.js
    cp node_modules/zstddec/dist/zstddec-stream.modern.js static/zstddec.mjs
   ```

3. **NO manual editing of static files** - If the original files don't work as-is:
   - Do workarounds in the **consuming code** (e.g., `crypto/zstd.js`), not in the static files
   - Document any workarounds in `AGENTS.md` under "Workarounds" section

### Workarounds

When original files from npm don't work directly in the target environment:

- **Problem**: `aes-js` (UMD) sets `window.aesjs` global in browsers
  **Solution**: In `crypto/aesctr.mjs`, access via `globalThis.aesjs` for browser, `import from 'aes-js'` for Node.js

- **Problem**: `DecompressionStream` API doesn't support `'zstd'` format in any browser — constructor throws `"Failed to construct 'DecompressionStream': Unsupported compression format: 'zstd'"`.
  **Solution**: Use `zstddec` (WASM-based native zstd) for all decompression in browser via `static/zstddec.mjs`. Imported in `crypto/zstd.js` and `ncz.js`.

- **Problem**: `zstddec` streaming ESM build has a bug in `decode()` when passing explicit `uncompressedSize` — produces truncated/all-zeros output for large streams (>1GB).
  **Solution**: In `ncz.js:203-207`, call `decoder.decode(compressedData, 0)` (auto-detect size). This works correctly: calls `ZSTD_findDecompressedSize` internally, falls back to streaming API if size is unknown.

### Browser Usage

Browser HTML files load dependencies:
```html
<script src="./static/aes-js.js"></script>
<!-- zstddec.mjs is imported via ES module in crypto/zstd.js and ncz.js -->
```

`aes-js.js` sets global variable `window.aesjs` accessed via `globalThis` in ES modules.
`zstddec.mjs` is imported directly as ES module (WASM binary is base64-embedded in the JS).

**DO NOT use import maps or CDN URLs** - the whole point of the `static/` folder is to enable offline use.

## Package Versions

Current versions (update this when upgrading):
- `aes-js`: 3.1.2
- `zstddec`: 0.2.0 (use streaming ESM version: `zstddec/dist/zstddec-stream.modern.js`)


