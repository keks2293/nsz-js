# Speed Comparison

Tested with Little Nightmares II NSZ (2.09 GB compressed, 4.99 GB decompressed).

| SHA-256 | Total Time | Peak RAM | Notes |
|---------|------------|----------|-------|
| Pure JS | 1m15s†     | ~2.5 GB† | Well-optimized |
| hash-wasm WASM | 2m53s†     | ~2.5 GB† | +1 min from WASM init overhead; SHA-256 wasn't the bottleneck |
| Web Crypto / Node crypto | 1m17s      | ~2.5 GB | Native, hardware-accelerated, correct SHA-256. FSA streaming path |
