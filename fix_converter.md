# Fix Plan for NSZ to NSP Converter

## Problem
The NSZ to NSP converter produces broken output files because:
1. The zstd decompression is failing with "invalid zstd data"
2. The AES-CTR decryption might not be working correctly

## Root Cause
The `fzstd` JavaScript library might not support the zstd frame format used in NCZ files, or the decryption is not being applied correctly.

## Solution
1. Use the working `nsz` Python tool for decompression
2. Or fix the JavaScript implementation

## Working Command
```bash
nsz -D -o /output/dir "input.nsz"
```

This produces a valid NSP file.
