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
- `static/fzstd.mjs` - Copied from `node_modules/fzstd/esm/index.mjs` (ES Module, import directly)
- `static/prod.keys` - User-provided Nintendo Switch keys file

### How to update static files:

1. Update the npm packages:
   ```bash
   npm install aes-js@x.x.x fzstd@x.x.x
   ```

2. Copy the files to `static/` **WITHOUT ANY MODIFICATIONS**:
   ```bash
   cp node_modules/aes-js/index.js static/aes-js.js
   cp node_modules/fzstd/esm/index.mjs static/fzstd.mjs
   ```

3. **NO manual editing of static files** - If the original files don't work as-is:
   - Do workarounds in the **consuming code** (e.g., `crypto/zstd.js`), not in the static files
   - Document any workarounds in `AGENTS.md` under "Workarounds" section

### Workarounds

When original files from npm don't work directly in the target environment:

- **Problem**: `aes-js` (UMD) sets `window.aesjs` global in browsers
  **Solution**: In `crypto/aesctr.mjs`, access via `globalThis.aesjs` for browser, `import from 'aes-js'` for Node.js

- **Problem**: `fzstd` (CommonJS) uses `exports` which isn't defined in browsers
  **Solution**: Use ESM version `fzstd/esm/index.mjs` instead, copy to `static/fzstd.mjs`, import directly in `crypto/zstd.js`

- **Problem**: `fzstd` ESM exports `Decompress` class (not `decompress` function)
  **Solution**: In `crypto/zstd.js`, use `new fzstdLib.Decompress(callback)` with streaming API (`push()` method)

- **Problem**: Node.js `zstd-codec` package doesn't export `ZstdDecompressor` as constructor
  **Solution**: Use `fzstd` instead (same as browser version) - works in both Node.js and browser

- **Problem**: `DecompressionStream` API doesn't support `'zstd'` format in any browser — constructor throws `"Failed to construct 'DecompressionStream': Unsupported compression format: 'zstd'"`. Also fzstd (pure JS zstd) has a hard 32MB backreference window limit — large NSZ files use 128MB windows, producing 6 corrupted bytes at NCA offset 0x68793b7.
  **Solution**: `getZstdWindowSize()` in `ncz.js:50-59` parses the zstd frame header to detect window size. Browser path checks this before decompression and throws immediately if >32MB. Small files (window ≤32MB) work in browser via chunked fzstd. Large files show a clear error telling the user to use `nsz-convert.js` (Node.js CLI with native `zstd` tool).

### Browser Usage

Browser HTML files load dependencies:
```html
<script src="./static/aes-js.js"></script>
<!-- fzstd.mjs is imported via ES module in crypto/zstd.js -->
```

`aes-js.js` sets global variable `window.aesjs` accessed via `globalThis` in ES modules.
`fzstd.mjs` is imported directly as ES module (no script tag needed).

**DO NOT use import maps or CDN URLs** - the whole point of the `static/` folder is to enable offline use.

## Package Versions

Current versions (update this when upgrading):
- `aes-js`: 3.1.2
- `fzstd`: 0.1.1 (use ESM version: `fzstd/esm/index.mjs`)
- `zstd-codec`: ^0.1.5 (not recommended - use `fzstd` instead)

## Recent Fixes ( streaming decompression)

The NCZ streaming decompression was producing incorrect output (SHA256 mismatch).
Root cause: `crypto/zstd.js` was using non-existent `fzstd.decompress()` instead of `fzstd.Decompress` class.
Fix: Use `new fzstdLib.Decompress(callback)` with streaming API (`push()` method).

See commit `334c017` for details.
