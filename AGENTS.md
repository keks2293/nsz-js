# Rules for AI Agents

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
