import { DataReader } from './fs/ncz.js';
import { SHA256 } from './crypto/sha256.js';
import { KeysParser } from './keys.js';
import { ZstdDecompressor } from './crypto/zstd.js';
import { extractContentHashMap } from './fs/cnmt-hashes.js';
import { convertNSZ } from './fs/nsz-convert.js';
import { convertXCZ } from './fs/xcz-convert.js';
import { mergeNSP } from './fs/merge.js';
import { update } from './fs/update.js';
import { splitNSP as splitNSPFile } from './fs/split.js';
import { formatBytes } from './fs/format.js';

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

    async decompressNSZtoNSP(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, fixPadding = false, verify = false } = options;
        onLog('info', `Processing: ${file.name} (${formatBytes(file.size)})`);
        await this.init();

        const fileReader = new FileSliceReader(file, 0, file.size);
        const createHash = () => {
            const h = new SHA256();
            return { update: (d) => h.update(d), hex: () => h.hex() };
        };

        const result = await convertNSZ(fileReader, writable ? { writable } : { memory: true }, {
            verify, fixPadding,
            log: onLog,
            progress: onProgress,
            createHash,
            extractCnmtHashMap: (d) => extractContentHashMap(d, this.keys),
        });

        onProgress(1.0, 'Done!');
        const outputName = file.name.replace(/\.nsz$/i, '.nsp');
        onLog('success', `Output: ${outputName} (${formatBytes(result.size)})`);
        return { blob: result.blob || null, name: outputName, size: result.size, writable: !!writable };
    }

    async decompressXCZtoXCI(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, verify = false } = options;
        onLog('info', 'Parsing XCI container...');
        const fileReader = new FileSliceReader(file);
        const createHash = () => {
            const h = new SHA256();
            return { update: (d) => h.update(d), hex: () => h.hex() };
        };

        const result = await convertXCZ(fileReader, writable ? { writable } : { memory: true }, {
            verify,
            log: onLog,
            progress: onProgress,
            createHash,
            extractCnmtHashMap: (d) => extractContentHashMap(d, this.keys),
        });

        onProgress(1.0, 'Done!');
        const outputName = file.name.replace(/\.xcz$/i, '.xci');
        onLog('success', `Output: ${outputName} (${formatBytes(result.size)})`);
        return { blob: result.blob || null, name: outputName, size: result.size, writable: !!writable };
    }

    async mergeNSPs(files, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, nodelta = false } = options;
        onLog('info', `Merging ${files.length} NSPs...`);
        await this.init();

        const readers = files.map((f) => ({
            name: f.name,
            reader: new FileSliceReader(f, 0, f.size),
        }));

        const result = await mergeNSP(readers, writable ? { writable } : { memory: true }, {
            keys: this.keys,
            log: onLog,
            progress: onProgress,
            nodelta,
        });

        onProgress(1.0, 'Done!');
        const outputName = files[0].name.replace(/\.(nsp|nsz|xci|xcz)$/i, '') + '_merged.nsp';
        onLog('success', `Output: ${outputName} (${formatBytes(result.size)}), ${result.memberCount} members`);
        return { blob: result.blob || null, name: outputName, size: result.size, memberCount: result.memberCount, writable: !!writable };
    }

    async updateNSPs(files, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, writable = null, keepNpdmAcidSig = false, keepNpdmAcidKey = false, updateMode = 'two-pass' } = options;
        onLog('info', `Updating ${files.length} NSPs...`);
        await this.init();
        if (!this.keys || !this.keys.header_key) {
            throw new Error('Keys are required to update (decrypt CNMT metadata). Load keys first.');
        }
        if (files.length !== 2) {
            throw new Error('Update requires exactly two files (base + update).');
        }

        const readers = files.map((f) => ({
            name: f.name,
            reader: new FileSliceReader(f, 0, f.size),
        }));

        const result = await update(readers, writable ? { writable } : { memory: true }, {
            keys: this.keys,
            log: onLog,
            progress: onProgress,
            keepNpdmAcidSig,
            keepNpdmAcidKey,
            updateMode,
        });

        onProgress(1.0, 'Done!');
        const outputName = files[0].name.replace(/\.(nsp|nsz|xci|xcz)$/i, '') + '_updated.nsp';
        onLog('success', `Output: ${outputName} (${formatBytes(result.size)}), ${result.memberCount} members`);
        return { blob: result.blob || null, name: outputName, size: result.size, memberCount: result.memberCount, writable: !!writable };
    }

    async splitNSP(file, options = {}) {
        const { onProgress = () => {}, onLog = () => {}, outputFactory = null } = options;
        onLog('info', `Splitting ${file.name}...`);
        await this.init();
        if (!this.keys || !this.keys.header_key) {
            throw new Error('Keys are required to split (read NCA headers and CNMT metadata). Load keys first.');
        }

        const reader = new FileSliceReader(file, 0, file.size);
        const result = await splitNSPFile(reader, this.keys, outputFactory, {
            log: onLog,
            progress: onProgress,
        });

        onProgress(1.0, 'Done!');
        return result;
    }

}

export { NSZConverter };
