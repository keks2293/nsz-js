# Speed Comparison

Tested with Little Nightmares II NSZ (2.09 GB compressed, 4.99 GB decompressed).

| SHA-256 | Total Time | Peak RAM | Notes |
|---------|-----------|----------|-------|
| Pure JS | 1m51s | ~2.5 GB | Well-optimized 32-bit integer implementation |
| hash-wasm WASM | 2m53s | ~2.5 GB | +1 min from WASM init overhead; SHA-256 wasn't the bottleneck |
| Web Crypto / Node crypto | 1m17s | ~2.5 GB | Native, hardware-accelerated, zero overhead. Same test at ~1 GB/s AES-CTR (Web Crypto) + zstddec WASM decompression |
