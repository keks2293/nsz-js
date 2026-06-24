class PFS0 {
    constructor(data) {
        this._data = new Uint8Array(data);
        this._view = new DataView(this._data.buffer, this._data.byteOffset, this._data.byteLength);
        this.files = [];
        this.headerSize = 0;
        this._parse();
    }

    static async open(reader) {
        const head = new Uint8Array(await reader.read(0, 16));
        const view = new DataView(head.buffer, head.byteOffset, head.byteLength);
        const fileCount = view.getUint32(4, true);
        const stringTableSize = view.getUint32(8, true);
        const headerSize = 0x10 + fileCount * 0x18 + stringTableSize;
        const buf = new Uint8Array(await reader.read(0, headerSize));
        return new PFS0(buf);
    }

    _parse() {
        const magic = String.fromCharCode(this._data[0], this._data[1], this._data[2], this._data[3]);
        if (magic !== 'PFS0') {
            throw new Error(`Invalid PFS0 magic: ${magic}`);
        }

        const fileCount = this._view.getUint32(4, true);
        const stringTableSize = this._view.getUint32(8, true);
        this.headerSize = 0x10 + fileCount * 0x18 + stringTableSize;

        const stringTableOffset = 0x10 + fileCount * 0x18;
        const stringTable = this._data.slice(stringTableOffset, stringTableOffset + stringTableSize);

        let stringEndOffset = stringTableSize;

        for (let i = fileCount - 1; i >= 0; i--) {
            const entryOffset = 0x10 + i * 0x18;
            const relOffset = Number(this._view.getBigUint64(entryOffset, true));
            const size = Number(this._view.getBigUint64(entryOffset + 8, true));
            const nameOffset = this._view.getUint32(entryOffset + 16, true);

            let name = '';
            for (let j = nameOffset; j < stringEndOffset && j < stringTable.length && stringTable[j] !== 0; j++) {
                name += String.fromCharCode(stringTable[j]);
            }
            stringEndOffset = nameOffset;

            const absOffset = relOffset + this.headerSize;
            this.files.push({
                name,
                offset: absOffset,
                size
            });
        }

        this.files.reverse();
    }

    getFiles() {
        return this.files;
    }

    getHeaderSize() {
        return this.headerSize;
    }
}

class PFS0Writer {
    constructor(fixPadding = false) {
        this.files = [];
        this.fixPadding = fixPadding;
    }

    add(name, size) {
        const offset = this.files.length === 0
            ? 0
            : this.files[this.files.length - 1].offset + this.files[this.files.length - 1].size;
        this.files.push({ name, offset, size });
    }

    get headerSize() {
        return 0x10 + this.files.length * 0x18 + this._paddedStringTableSize;
    }

    get _stringTable() {
        return this.files.map(f => f.name).join('\0') + '\0';
    }

    get _paddedStringTableSize() {
        const enc = new TextEncoder();
        const names = this._stringTable;
        const namesLen = enc.encode(names).length;
        const rawSize = 0x10 + this.files.length * 0x18 + namesLen;
        if (this.fixPadding) {
            return namesLen + (0x20 - (rawSize % 0x20));
        }
        const pad16 = (16 - (rawSize % 16)) % 16;
        return namesLen + pad16;
    }

    buildHeader() {
        const enc = new TextEncoder();
        const names = this._stringTable;
        const tableSize = this._paddedStringTableSize;
        const namesLen = enc.encode(names).length;
        const paddedBytes = tableSize > namesLen
            ? new Uint8Array(tableSize)
            : enc.encode(names);
        if (tableSize > namesLen) {
            paddedBytes.set(enc.encode(names), 0);
            paddedBytes.fill(0, namesLen);
        }
        const size = this.headerSize;
        const buf = new Uint8Array(size);
        const v = new DataView(buf.buffer);

        buf[0] = 0x50; buf[1] = 0x46; buf[2] = 0x53; buf[3] = 0x30;
        v.setUint32(4, this.files.length, true);
        v.setUint32(8, tableSize, true);
        v.setUint32(12, 0, true);

        let soff = 0;
        for (let i = 0; i < this.files.length; i++) {
            const f = this.files[i];
            const pos = 0x10 + i * 0x18;
            v.setBigUint64(pos, BigInt(f.offset), true);
            v.setBigUint64(pos + 8, BigInt(f.size), true);
            v.setUint32(pos + 16, soff, true);
            v.setUint32(pos + 20, 0, true);
            soff += enc.encode(f.name).length + 1;
        }

        buf.set(paddedBytes, 0x10 + this.files.length * 0x18);
        return buf;
    }
}

export { PFS0, PFS0Writer };
