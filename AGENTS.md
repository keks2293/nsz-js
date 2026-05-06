# Rules for AI Agents

## Static Files

**DO NOT manually edit files in the `static/` folder.**

The `static/` folder contains downloaded/copied dependencies for browser use:
- `static/aes-js.js` - Copied from `node_modules/aes-js/index.js` (UMD format, sets `window.aesjs` when loaded via `<script>` tag)
- `static/fzstd.js` - Copied from `node_modules/fzstd/lib/index.js`
- `static/prod.keys` - User-provided Nintendo Switch keys file

### How to update static files:

1. Update the npm packages:
   ```bash
   npm install aes-js@x.x.x fzstd@x.x.x
   ```

2. Copy the files to `static/` **WITHOUT ANY MODIFICATIONS**:
   ```bash
   cp node_modules/aes-js/index.js static/aes-js.js
   cp node_modules/fzstd/lib/index.js static/fzstd.js
   ```

3. **NO manual editing of static files** - If the original files don't work as-is:
   - Do workarounds in the **consuming code** (e.g., `crypto/aesctr.mjs`), not in the static files
   - Example: If `aes-js` sets `window.aesjs` global, access it via `globalThis.aesjs` in your code
   - Example: If you need ES module syntax, import from `'aes-js'` in Node.js and use the global in browsers
   - Document any workarounds in `AGENTS.md` under "Workarounds" section

### Workarounds

When original files from npm don't work directly in the target environment:

- **Problem**: `aes-js` (UMD) sets `window.aesjs` global in browsers
  **Solution**: In `crypto/aesctr.mjs`, access via `globalThis.aesjs` for browser, `import from 'aes-js'` for Node.js

- **Problem**: `fzstd` needs to be loaded as a script
  **Solution**: Load via `<script src="./static/fzstd.js"></script>` in HTML, access via `window.fzstd` in code

### Browser Usage

Browser HTML files load dependencies via `<script>` tags (not import maps):
```html
<script src="./static/aes-js.js"></script>
<script src="./static/fzstd.js"></script>
```

These set global variables (`window.aesjs`, `window.fzstd`) that are accessed in the ES module code via `globalThis`.

**DO NOT use import maps or CDN URLs** - the whole point of the `static/` folder is to enable offline use.

## Package Versions

Current versions (update this when upgrading):
- `aes-js`: 3.1.2
- `fzstd`: 0.1.1
- `zstd-codec`: ^0.1.5
