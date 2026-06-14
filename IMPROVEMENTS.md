# Improvement Opportunities

Prioritized areas for improvement identified 2026-05-30.

## High Impact

1. ✅ **HFS0 header building duplicated 6x** — `converter.js:339-375,504-570`, `nsz-cli.js:184-274`, `fs/xci.js:76-141`. `HFS0Writer` class exists but is unused by converter/CLI. Any HFS0 bug needs fixing in 6 places. Refactor to use `HFS0Writer` consistently.

2. ✅ **Verification logic duplicated** — `converter.js:132-162` vs `192-221`. Extracted to shared `verifyHash` method. Aligned with Python nsz verification behavior.

3. ❌ **Ad script in HTML blocks page load** — `index.html:4`. External ad `<script>` injected before `<title>`. Slows rendering if CDN is slow/down. **Not a problem.**

4. ❌ **`aes128.js` rcon_table oversized** — `crypto/aes128.js:6-26`. AES-128 only needs 10 rcon entries; table has ~100+ entries (repeating every 255). **Keeping as-is to match Python nsz.**

## Medium Impact

5. ❌ **No `npm test` script** — `package.json:8-10`. Tests exist but require manual discovery. Prevents automated CI. **Not needed for this project.**

6. ✅ **Deleted `_decompressBuffered`** — Memory path now uses `_decompressStream` with `collectChunk` wrapper. Reads input as stream, collects output into buffer. `_decompressBuffered` (entire file in memory before decompression) removed.

7. ❌ **Missing NACP parser** — `fs/ticket.js` has NCA/CNMT/Ticket but no NACP. Python nsz has one; needed for game metadata extraction. **Not needed for NSZ→NSP conversion** — NACP stays inside NCA and is preserved in output NSP. Only useful for `--info` style features.

## Polish

8. ❌ **No CI setup** — Not needed for this project.

9. ❌ **SW `writable.close()` error handling** — Not needed. Browser handles failed downloads gracefully. No way to determine appropriate timeout value without profiling.

10. ✅ **UI redesign** — `site-v2.md` suggests a redesign may be planned.
