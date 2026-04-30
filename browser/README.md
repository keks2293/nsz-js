# NSZ to NSP Browser Converter

A fully ported JavaScript implementation of the [nicoboss/nsz](https://github.com/nicoboss/nsz) project for converting Nintendo Switch NSZ (compressed NSP) files to NSP format, running entirely in the browser.

## Features

- **Pure JavaScript**: No server-side processing required
- **Browser-based**: Works entirely in the browser with Web Crypto API
- **Zstandard decompression**: Full support for both streaming and block compression
- **NCA encryption**: Supports decryption with title keys
- **Integrity restoration**: Validates and restores NCA file integrity
- **Large file support**: Streaming decompression for files up to 8GB+
- **Multiple files**: Process multiple NSZ files in batch
- **Default keys**: Option to load default prod.keys from GitHub

## Usage

### Browser Version

1. Open `index.html` in a modern web browser
2. Drag and drop NSZ files or click to select
3. (Optional) Load default keys or paste your own prod.keys
4. Click "Convert to NSP" to decompress

### Node.js Version

```bash
cd browser/node
npm install
node nsz.js -d "path/to/file.nsz" -o "output/directory"
```

## Requirements

- Modern browser with ES6+ module support
- Web Crypto API (available in all modern browsers)
- Zstandard codec (loaded from CDN)

## File Format Support

- **Input**: `.nsz` (compressed NSP container)
- **Output**: `.nsp` (uncompressed NSP container)
- **Internal**: `.ncz` (compressed NCA files with NCZSECTN header)

## Architecture

```
browser/
├── index.html          # Main UI
├── main.js             # UI logic and event handling
├── converter.js        # Main conversion orchestrator
├── ncz.js              # NCZ decompression (NCZSECTN + NCZBLOCK)
├── pfs0.js             # PFS0 container parsing
├── keys.js             # Key parsing and derivation
├── crypto/             # Cryptographic utilities
│   ├── aes.js          # AES CBC/ECB
│   ├── aesctr.js       # AES CTR mode
│   ├── aesecb.js       # AES ECB mode
│   └── zstd.js         # Zstandard decompression
└── node/               # Node.js version
    ├── nsz.js          # CLI entry point
    ├── decompressor.js # Main decompressor
    ├── keys.js         # Key management
    └── fs/             # File system classes
        ├── pfs0.js     # PFS0 implementation
        ├── ncz.js      # NCZ implementation
        └── nca.js      # NCA header parsing
```

## Compression Types

The converter supports all NSZ compression types from the original nsz project:

1. **Section-based compression**: Each NCA section is compressed separately
2. **Block compression (NCZBLOCK)**: Files split into compressed blocks for random access
3. **Streaming compression**: Traditional zstd streaming decompression

## NCA Encryption

The converter handles all crypto types:
- **Type 1**: No encryption
- **Type 3**: CTR mode encryption
- **Type 4**: BKTR mode encryption (relocation tables)

## Key Derivation

The implementation includes full key derivation from prod.keys:
- Master key generation
- Title KEK derivation
- Key area key generation (application, ocean, system)
- AES wrapped title key unwrapping

## License

MIT License - Same as the original [nicoboss/nsz](https://github.com/nicoboss/nsz) project.