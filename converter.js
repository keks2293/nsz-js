import { ZstdDecompressor } from './crypto/zstd.js';
import { PFS0 } from './fs/pfs0.js';
import { DataReader } from './fs/ncz.js';
import { KeysParser } from './keys.js';
import { SHA256 } from './crypto/sha256.js';
import { Cnmt } from './fs/cnmt.js';
import { NCAHeader } from './fs/nca.js';
import { XCIReader } from './fs/xci.js';
import { AesXts } from './crypto/aesxts.mjs';
import { AesCtr } from './crypto/aesctr.mjs';
import { AesEcb } from './crypto/aes128.js';
import { convertXCZStreaming, convertXCZMemory } from './fs/xcz-convert.js';
import { convertNSZStreaming, convertNSZMemory } from './fs/nsz-convert.js';

class FileSliceReader extends DataReader {
    constructor(file, baseOffset = 0, totalLength = null) {
        super();
        this.file = file;
        this.baseOffset = baseOffset;
        this._length = totalLength !== null ? totalLength : file.size - baseOffset;
    }

    get length() {
        return this._length;
    }

    async read(offset, size) {
        const absOffset = this.baseOffset + offset;
        const buffer = await this.file.slice(absOffset, absOffset + size).arrayBuffer();
        return new Uint8Array(buffer);
    }
}

class NSZConverter {
    constructor(keys = null) {
        this.keys = keys;
        this.initialized = false;
    }

    async init() {
        if (this.initialized) return;
        await ZstdDecompressor.load();
        this.initialized = true;
    }

    setKeys(keyText) {
        try {
            this.keys = KeysParser.parse(keyText);
            return true;
        } catch (e) {
            console.error('Failed to parse keys:', e);
            return false;
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async decompressNSZtoNSP(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, fixPadding = false, verify = false } = options;
        onLog('info', `Processing: ${file.name} (${this.formatBytes(file.size)})`);
        await this.init();

        const pfs0Reader = await PFS0.open(new FileSliceReader(file));
        const files = pfs0Reader.getFiles();
        onLog('info', `PFS0 header: ${files.length} files`);
        onLog('info', `Found ${files.length} files in container`);


        const cnmtHashes = new Set();
        if (verify) {
            const cnmtFiles = files.filter(f => f.name.toLowerCase().endsWith('.cnmt.nca'));
            if (cnmtFiles.length > 0) {
                for (const cnmtFile of cnmtFiles) {
                    const cnmtData = await file.slice(cnmtFile.offset, cnmtFile.offset + cnmtFile.size).arrayBuffer();
                    const hashes = await this.extractCnmtHashes(cnmtData);
                    hashes.forEach(h => cnmtHashes.add(h));
                }
                onLog('info', `Found ${cnmtHashes.size} expected NCA hashes from CNMT`);
            }
        }

        const fileReader = new FileSliceReader(file, 0, file.size);
        if (writable) {
            onLog('info', 'Using streaming output (File System Access)');
            const adapter = {
                read: (offset, size) => fileReader.read(offset, size),
                write: (offset, data) => writable.write({ type: 'write', position: offset, data }),
                log: onLog,
                progress: onProgress,
            };
            const result = await convertNSZStreaming(pfs0Reader, this.keys, adapter, {
                verify, fixPadding,
                log: onLog,
                progress: onProgress,
                createHash: () => {
                    const h = new SHA256();
                    return { update: (d) => h.update(d), digest: () => h.hexdigest() };
                },
            }, (d) => this.extractCnmtHashes(d));
            onProgress(1.0, 'Done!');
            const outputName = file.name.replace(/\.(nsz|nspz|nsx)$/i, '.nsp');
            const totalSize = result.headerSize + result.totalDataSize;
            onLog('success', `Output: ${outputName} (${this.formatBytes(totalSize)})`);
            return { blob: null, name: outputName, size: totalSize, writable: true };
        } else {
            onLog('info', 'Using memory download (no File System Access)');
            const adapter = {
                read: (offset, size) => fileReader.read(offset, size),
                log: onLog,
                progress: onProgress,
            };
            const result = await convertNSZMemory(pfs0Reader, this.keys, adapter, {
                verify, fixPadding,
                log: onLog,
                progress: onProgress,
                createHash: () => {
                    const h = new SHA256();
                    return { update: (d) => h.update(d), digest: () => h.hexdigest() };
                },
            }, (d) => this.extractCnmtHashes(d));
            onProgress(1.0, 'Done!');
            const outputName = file.name.replace(/\.(nsz|nspz|nsx)$/i, '.nsp');
            onLog('success', `Output: ${outputName} (${this.formatBytes(result.size)})`);
            return { blob: result.blob, name: outputName, size: result.size };
        }
    }

    async decompressXCZtoXCI(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, verify = false } = options;
        onLog('info', 'Parsing XCI container...');
        const fileReader = new FileSliceReader(file);
        const xci = new XCIReader(fileReader);
        await xci.parse();
        const partitions = xci.getPartitions();
        onLog('info', `Found ${partitions.length} partitions: ${partitions.map(p => p.name).join(', ')}`);

        const adapter = {
            read: (offset, size) => fileReader.read(offset, size),
            log: onLog,
            progress: onProgress,
            createHash: () => {
                const h = new SHA256();
                return { update: (d) => h.update(d), digest: () => h.hexdigest() };
            },
        };

        if (writable) {
            onLog('info', 'Using streaming output (File System Access)');
            adapter.write = (offset, data) => writable.write({ type: 'write', position: offset, data });
            const totalSize = await convertXCZStreaming(xci, this.keys, adapter, {
                verify,
                log: onLog,
                progress: onProgress,
                createHash: adapter.createHash,
            }, (d) => this.extractCnmtHashes(d));
            onProgress(1.0, 'Done!');
            const outputName = file.name.replace(/\.xcz$/i, '.xci');
            onLog('success', `Output: ${outputName} (${this.formatBytes(totalSize)})`);
            return { blob: null, name: outputName, size: totalSize, writable: true };
        } else {
            onLog('info', 'Using memory download');
            const result = await convertXCZMemory(xci, this.keys, adapter, {
                verify,
                log: onLog,
                progress: onProgress,
                createHash: adapter.createHash,
            }, (d) => this.extractCnmtHashes(d));
            onProgress(1.0, 'Done!');
            const outputName = file.name.replace(/\.xcz$/i, '.xci');
            onLog('success', `Output: ${outputName} (${this.formatBytes(result.size)})`);
            return { blob: result.blob, name: outputName, size: result.size };
        }
    }

    async extractCnmtHashes(cnmtData) {
        const hashes = new Set();
        try {
            const arr = cnmtData instanceof Uint8Array ? cnmtData : new Uint8Array(cnmtData);

            if (!this.keys || !this.keys.header_key) {
                console.error('Cannot decrypt CNMT: missing keys (header_key)');
                return hashes;
            }

            const headerKey = this.keys.header_key;
            const headerKeyBytes = typeof headerKey === 'string'
                ? new Uint8Array(headerKey.match(/.{2}/g).map(b => parseInt(b, 16)))
                : headerKey;

            if (headerKeyBytes.length !== 32) {
                console.error('Invalid header_key length:', headerKeyBytes.length);
                return hashes;
            }

            const xts = new AesXts(headerKeyBytes);

            const hdrLen = Math.min(0xC00, arr.length);
            const hdrEncrypted = arr.subarray(0, hdrLen);
            const hdrDecrypted = xts.decrypt(hdrEncrypted, 0);

            const header = NCAHeader.parse(hdrDecrypted);

            if (header && header.sectionTables && header.sectionTables[0]) {
                const fsOffset = header.sectionTables[0].offset;
                const fsEndOffset = header.sectionTables[0].endOffset;
                const fsSize = fsEndOffset - fsOffset;

                if (fsSize > 0 && fsOffset + fsSize <= arr.length) {
                    const sectionData = arr.subarray(fsOffset, fsOffset + fsSize);

                    const keysArr = this.keys.keyAreaKeys;
                    const mk = header.masterKey;
                    const kakHex = keysArr[mk] && keysArr[mk][0];

                    if (!kakHex) {
                        console.error('No key_area_key_application for masterKey:', mk);
                        return hashes;
                    }

                    const kak = new Uint8Array(kakHex.match(/.{2}/g).map(b => parseInt(b, 16)));
                    const keyBlock = hdrDecrypted.subarray(0x300, 0x340);

                    let unwrapped;
                    try {
                        const nodeCrypto = await import('crypto');
                        const ecb = nodeCrypto.createDecipheriv('aes-128-ecb', kak, null);
                        ecb.setAutoPadding(false);
                        unwrapped = new Uint8Array(ecb.update(keyBlock));
                    } catch {
                        const ecb = new AesEcb(kak);
                        unwrapped = ecb.decrypt(keyBlock);
                    }
                    const sectionKey = unwrapped.subarray(32, 48);

                    const sectionHdr = hdrDecrypted.subarray(0x400, 0x600);
                    const ivBytes = sectionHdr.subarray(0x140, 0x148);

                    const raw = new Uint8Array(16);
                    for (let j = 0; j < 8; j++) raw[j] = 0;
                    raw.set(ivBytes, 8);
                    const cryptoCounter = new Uint8Array(raw).reverse();

                    const aesCtr = new AesCtr(sectionKey, cryptoCounter);
                    aesCtr.seek(fsOffset);

                    const fsData = await aesCtr.decrypt(sectionData);

                    const pfs0Start = 0x20;
                    const pfs0Magic = fsData.length > pfs0Start + 4
                        ? String.fromCharCode(fsData[pfs0Start], fsData[pfs0Start + 1], fsData[pfs0Start + 2], fsData[pfs0Start + 3])
                        : '';

                    let cnmtRaw = null;

                    if (pfs0Magic === 'PFS0') {
                        const pfs0 = new PFS0(fsData.subarray(pfs0Start));
                        const pfs0Files = pfs0.getFiles();
                        if (pfs0Files.length > 0) {
                            const f = pfs0Files[0];
                            cnmtRaw = pfs0._data.slice(f.offset, f.offset + f.size);
                        } else {
                            cnmtRaw = fsData.subarray(pfs0Start);
                        }
                    } else {
                        const magic = String.fromCharCode(fsData[0], fsData[1], fsData[2], fsData[3]);
                        if (magic === 'PFS0') {
                            cnmtRaw = fsData;
                        }
                    }

                    if (cnmtRaw) {
                        const cnmt = Cnmt.parse(cnmtRaw);
                        if (cnmt && cnmt.contentEntries) {
                            for (const entry of cnmt.contentEntries) {
                                hashes.add(entry.hash);
                            }
                        }
                    }
                }
            }
        } catch (e) {
            console.error('Error extracting CNMT hashes:', e);
        }
        return hashes;
    }

}

export { NSZConverter };
