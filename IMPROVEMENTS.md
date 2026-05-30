# Improvement Opportunities

Prioritized areas for improvement identified 2026-05-30.

## High Impact

- [ ] **HFS0 header building duplicated 6x** — `converter.js:339-375,504-570`, `nsz-cli.js:184-274`, `fs/xci.js:76-141`. `HFS0Writer` class exists but is unused by converter/CLI. Any HFS0 bug needs fixing in 6 places. Refactor to use `HFS0Writer` consistently.

- [ ] **Verification logic duplicated** — `converter.js:132-162` vs `192-221`. Identical hash verification code in streaming and memory branches. Extract to shared method.

- [ ] **Ad script in HTML blocks page load** — `index.html:4`. External ad `<script>` injected before `<title>`. Slows rendering if CDN is slow/down.

- [ ] **`aes128.js` rcon_table oversized** — `crypto/aes128.js:6-26`. AES-128 only needs 10 rcon entries; table has ~100+ entries (repeating every 255).

## Medium Impact

- [ ] **No `npm test` script** — `package.json:8-10`. Tests exist but require manual discovery. Prevents automated CI.

- [ ] **zstd CLI: reads all compressed data before piping** — `fs/ncz.js:292`. `_decompressWithStreaming` feeds entire data to zstd stdin before decompression begins. Defeats streaming. `_decompressWithStreamingStream` does this correctly.

- [ ] **`HFS0Writer.getHeaderSize()` computes differently from reader** — `fs/xci.js:131-141`. Uses running sum of encoded names; reader uses raw string table slice. Potential mismatch.

- [ ] **Missing NACP parser** — `fs/ticket.js` has NCA/CNMT/Ticket but no NACP. Python nsz has one; needed for game metadata extraction.

- [ ] **File detection by extension only, not magic bytes** — `main.js:93-103`. Python nsz checks content magic for robust format detection.

## Polish

- [ ] No CI setup (GitHub Actions or similar)
- [ ] SW `writable.close()` error handling could be more robust
- [ ] `site-v2.md` suggests a UI redesign may be planned
