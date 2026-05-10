# Browser Zstd Decompression

## The Problem

NSZ files can use zstd compression with any window size. The browser has no native zstd decompression API (`DecompressionStream('zstd')` throws `Unsupported compression format` in all browsers), so we use a WASM-based library.

## Solution: zstddec WASM

[zstddec](https://github.com/StadiA/zstddec) wraps the real zstd C library compiled to WebAssembly:

```javascript
import { ZSTDDecoder } from './static/zstddec.mjs';
const decoder = new ZSTDDecoder();
await decoder.init();
const decompressed = decoder.decode(compressed, 0);
```

- **Native zstd** — handles any window size
- **~28 KB WASM** binary base64-embedded in the JS (no extra `.wasm` file)
- **Fast** — near-native performance

## Why fzstd Was Removed

Previously, the project used `fzstd` (pure-JS zstd) for block decompression (NCZBLOCK small blocks). It had two bugs with large zstd windows (>32 MB):

1. **Streaming API**: 6 bytes corrupted at offset 109 MB in the output
2. **Standalone decompress()**: Throws "invalid zstd data"

Since `zstddec` handles all cases correctly (both streaming and block decompression), `fzstd` was removed entirely. Now `zstddec` is the single zstd library for all browser decompression.

## The Node.js Path

Node.js CLI (`nsz-convert.js`) uses the system `zstd` binary via `spawn` for streaming decompression (faster, no WASM overhead):
```javascript
const proc = spawn('zstd', ['-d', '--no-check'], { stdio: ['pipe', 'pipe', 'pipe'] });
```

For NCZBLOCK block decompression, Node.js also uses `zstddec` via `crypto/zstd.js`.

## Current Implementation

- `ncz.js` — Browser streaming path imports `zstddec` directly
- `crypto/zstd.js` — Block decompression for both Node.js and browser uses `zstddec`

## Known zstddec Bug

zstddec's `decode()` has a bug when passing explicit `uncompressedSize` for large streams (>1 GB) — produces truncated/all-zeros output.

**Fix**: Always pass `0` to auto-detect: `decoder.decode(compressedData, 0)`. This calls `ZSTD_findDecompressedSize` internally and falls back to streaming API if size is unknown.

## Files

- `static/zstddec.mjs` — Copied from `node_modules/zstddec/dist/zstddec-stream.modern.js` (ES Module)
- `crypto/zstd.js` — ZstdDecompressor class using zstddec
- `ncz.js` — Browser streaming path using zstddec directly
