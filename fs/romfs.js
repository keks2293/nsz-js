// RomFS parser and builder for Nintendo Switch
// RomFS0 = uncompressed (headerVersion=2/3), files stored directly
// RomFS1 = hash-compressed (headerVersion=5/6), files in 64KB compressed blocks

import { sha256 } from '../crypto/sha256.js';
import { decompressBlock } from '../crypto/zstd.js';

const IVFC_MAGIC = 0x43465649;
const IVFC_HEADER_SIZE = 0xE0;
const IVFC_MAX_LEVEL = 6;
const ROMFS_HEADER_SIZE = 0x50;
const ROMFS_ENTRY_EMPTY = 0xFFFFFFFF;
const ROMFS_BLOCK_SIZE = 0x10000; // 64KB blocks
const HASH_TABLE_SIZE = 0x10000; // 65536 buckets

export class RomFs {
    static parse(data) {
        if (data.length < IVFC_HEADER_SIZE + ROMFS_HEADER_SIZE) return null;
        const view = new DataView(data.buffer, data.byteOffset);
        const magic = view.getUint32(0, true);
        if (magic !== IVFC_MAGIC) return null;

        const numLevels = view.getUint32(12, true);
        if (numLevels === 0 || numLevels > IVFC_MAX_LEVEL) return null;

        const levels = [];
        for (let i = 0; i < numLevels; i++) {
            const off = 16 + i * 20;
            const logicalOffset = Number(view.getBigUint64(off, true));
            const hashDataSize = Number(view.getBigUint64(off + 8, true));
            const blockSize = view.getUint32(off + 16, true);
            levels.push({ logicalOffset, hashDataSize, blockSize });
        }

        const masterHash = data.subarray(0xA0, 0xC0);
        const headerVersion = data[IVFC_HEADER_SIZE + 0x20];
        const isRomFS0 = headerVersion === 2 || headerVersion === 3;
        const isRomFS1 = headerVersion === 5 || headerVersion === 6;

        if (!isRomFS0 && !isRomFS1) return null;

        const romfsOff = IVFC_HEADER_SIZE;
        const dirHashTableOffset = Number(view.getBigUint64(romfsOff + 8, true));
        const dirHashTableSize = Number(view.getBigUint64(romfsOff + 16, true));
        const dirMetaTableOffset = Number(view.getBigUint64(romfsOff + 24, true));
        const dirMetaTableSize = Number(view.getBigUint64(romfsOff + 32, true));
        const fileHashTableOffset = Number(view.getBigUint64(romfsOff + 40, true));
        const fileHashTableSize = Number(view.getBigUint64(romfsOff + 48, true));
        const fileMetaTableOffset = Number(view.getBigUint64(romfsOff + 56, true));
        const fileMetaTableSize = Number(view.getBigUint64(romfsOff + 64, true));
        const dataOffset = Number(view.getBigUint64(romfsOff + 72, true));

        if (isRomFS0) {
            return new RomFs0(data, {
                ivfc: { levels, masterHash, numLevels },
                dirHashTable: { offset: romfsOff + dirHashTableOffset, size: dirHashTableSize },
                dirMetaTable: { offset: romfsOff + dirMetaTableOffset, size: dirMetaTableSize },
                fileHashTable: { offset: romfsOff + fileHashTableOffset, size: fileHashTableSize },
                fileMetaTable: { offset: romfsOff + fileMetaTableOffset, size: fileMetaTableSize },
                dataOffset: romfsOff + dataOffset,
            });
        }

        return new RomFs1(data, {
            ivfc: { levels, masterHash, numLevels },
            dirHashTable: { offset: romfsOff + dirHashTableOffset, size: dirHashTableSize },
            dirMetaTable: { offset: romfsOff + dirMetaTableOffset, size: dirMetaTableSize },
            fileHashTable: { offset: romfsOff + fileHashTableOffset, size: fileHashTableSize },
            fileMetaTable: { offset: romfsOff + fileMetaTableOffset, size: fileMetaTableSize },
            dataOffset: romfsOff + dataOffset,
        });
    }
}

export class RomFs0 {
    constructor(data, layout) {
        this.data = data;
        this.layout = layout;
        this.view = new DataView(data.buffer, data.byteOffset);
        this.files = this._parseFiles();
    }

    _readString(offset) {
        const bytes = this.data.subarray(offset);
        let end = 0;
        while (end < bytes.length && bytes[end] !== 0) end++;
        return new TextDecoder().decode(bytes.subarray(0, end));
    }

    _parseFiles() {
        const files = [];
        const rootDirPtr = this.view.getUint32(this.layout.dirMetaTable.offset, true);
        this._walkDirectory(rootDirPtr, this.layout.dirMetaTable.offset, this.layout.fileMetaTable.offset, '', files);
        return files;
    }

    _walkDirectory(dirPtr, dirMetaBase, fileMetaBase, prefix, files) {
        if (dirPtr === ROMFS_ENTRY_EMPTY) return;
        const dirEntry = this._readDirEntry(dirPtr + dirMetaBase);

        if (dirEntry.name) {
            const name = dirEntry.name;
        }

        let child = dirEntry.child;
        while (child !== ROMFS_ENTRY_EMPTY) {
            const childEntry = this._readDirEntry(child + dirMetaBase);
            const childName = childEntry.name;
            this._walkDirectory(child, dirMetaBase, fileMetaBase, prefix + (dirEntry.name ? dirEntry.name + '/' : '') + childName + '/', files);
            child = childEntry.sibling;
        }

        let file = dirEntry.file;
        while (file !== ROMFS_ENTRY_EMPTY) {
            const fileEntry = this._readFileEntry(file + fileMetaBase);
            const fullPrefix = prefix;
            files.push({
                path: fullPrefix + fileEntry.name,
                offset: Number(fileEntry.offset),
                size: Number(fileEntry.size),
            });
            file = fileEntry.sibling;
        }
    }

    _readDirEntry(offset) {
        return {
            parent: this.view.getUint32(offset, true),
            sibling: this.view.getUint32(offset + 4, true),
            child: this.view.getUint32(offset + 8, true),
            file: this.view.getUint32(offset + 12, true),
            hash: this.view.getUint32(offset + 16, true),
            nameSize: this.view.getUint32(offset + 20, true),
            name: this._readString(offset + 24),
        };
    }

    _readFileEntry(offset) {
        return {
            parent: this.view.getUint32(offset, true),
            sibling: this.view.getUint32(offset + 4, true),
            offset: this.view.getBigUint64(offset + 8, true),
            size: this.view.getBigUint64(offset + 16, true),
            hash: this.view.getUint32(offset + 24, true),
            nameSize: this.view.getUint32(offset + 28, true),
            name: this._readString(offset + 32),
        };
    }

    getFileData(fileInfo) {
        return this.data.subarray(fileInfo.offset, fileInfo.offset + fileInfo.size);
    }

    getAllFiles() {
        return this.files.map(f => ({
            path: f.path,
            data: this.data.subarray(f.offset, f.offset + f.size),
            size: f.size,
        }));
    }
}

export class RomFs1 {
    constructor(data, layout) {
        this.data = data;
        this.layout = layout;
        this.view = new DataView(data.buffer, data.byteOffset);
        this.files = this._parseFiles();
    }

    _readString(offset) {
        const bytes = this.data.subarray(offset);
        let end = 0;
        while (end < bytes.length && bytes[end] !== 0) end++;
        return new TextDecoder().decode(bytes.subarray(0, end));
    }

    _parseFiles() {
        const files = [];
        const rootDirPtr = this.view.getUint32(this.layout.dirMetaTable.offset, true);
        this._walkDirectory(rootDirPtr, this.layout.dirMetaTable.offset, this.layout.fileMetaTable.offset, '', files);
        return files;
    }

    _walkDirectory(dirPtr, dirMetaBase, fileMetaBase, prefix, files) {
        if (dirPtr === ROMFS_ENTRY_EMPTY) return;
        const dirEntry = this._readDirEntry(dirPtr + dirMetaBase);

        let child = dirEntry.child;
        while (child !== ROMFS_ENTRY_EMPTY) {
            const childEntry = this._readDirEntry(child + dirMetaBase);
            this._walkDirectory(child, dirMetaBase, fileMetaBase, prefix + dirEntry.name + '/' + childEntry.name + '/', files);
            child = childEntry.sibling;
        }

        let file = dirEntry.file;
        while (file !== ROMFS_ENTRY_EMPTY) {
            const fileEntry = this._readFileEntry(file + fileMetaBase);
            files.push({
                path: prefix + fileEntry.name,
                offset: Number(fileEntry.offset),
                size: Number(fileEntry.size),
            });
            file = fileEntry.sibling;
        }
    }

    _readDirEntry(offset) {
        return {
            parent: this.view.getUint32(offset, true),
            sibling: this.view.getUint32(offset + 4, true),
            child: this.view.getUint32(offset + 8, true),
            file: this.view.getUint32(offset + 12, true),
            hash: this.view.getUint32(offset + 16, true),
            nameSize: this.view.getUint32(offset + 20, true),
            name: this._readString(offset + 24),
        };
    }

    _readFileEntry(offset) {
        return {
            parent: this.view.getUint32(offset, true),
            sibling: this.view.getUint32(offset + 4, true),
            offset: this.view.getBigUint64(offset + 8, true),
            size: this.view.getBigUint64(offset + 16, true),
            hash: this.view.getUint32(offset + 24, true),
            nameSize: this.view.getUint32(offset + 28, true),
            name: this._readString(offset + 32),
        };
    }

    getFileData(fileInfo) {
        return this.data.subarray(fileInfo.offset, fileInfo.offset + fileInfo.size);
    }

    getAllFiles() {
        return this.files.map(f => ({
            path: f.path,
            data: this.data.subarray(f.offset, f.offset + f.size),
            size: f.size,
        }));
    }
}

// RomFS hash function (FNV-1a variant used by Switch)
function romfsHash(name) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < name.length; i++) {
        hash ^= name.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193);
    }
    return hash >>> 0;
}

// Check if data is RomFS0 (uncompressed, no IVFC header, direct files)
export function isRomFs0(data) {
    if (data.length < 0x100) return false;
    const magic = String.fromCharCode(data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
    if (magic !== 'IVFC\x00\x00\x00\x00') return false;

    // Check header version
    const headerVersion = data[0xE0 + 0x20];
    return headerVersion === 2 || headerVersion === 3;
}

// Check if data is RomFS1 (hash-compressed)
export function isRomFs1(data) {
    if (data.length < 0x100) return false;
    const magic = String.fromCharCode(data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
    if (magic !== 'IVFC\x00\x00\x00\x00') return false;

    const headerVersion = data[0xE0 + 0x20];
    return headerVersion === 5 || headerVersion === 6;
}
