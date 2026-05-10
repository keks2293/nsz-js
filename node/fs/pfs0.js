import { PFS0Writer as RootPFS0Writer } from '../../pfs0.js';

export class PFS0 {
    constructor(buffer) {
        this.buffer = buffer instanceof Buffer ? buffer : Buffer.from(buffer);
        this.files = [];
        this.parse();
    }

    parse() {
        const magic = this.buffer.slice(0, 4).toString('ascii');
        if (magic !== 'PFS0') {
            throw new Error(`Invalid PFS0 magic: ${magic}`);
        }

        const fileCount = this.buffer.readUInt32LE(4);
        const stringTableSize = this.buffer.readUInt32LE(8);

        const headerSize = 0x10 + fileCount * 0x18 + stringTableSize;
        
        const stringTableOffset = 0x10 + fileCount * 0x18;
        const stringTable = this.buffer.slice(stringTableOffset, stringTableOffset + stringTableSize);

        let stringEndOffset = stringTableSize;

        for (let i = fileCount - 1; i >= 0; i--) {
            const entryOffset = 0x10 + i * 0x18;
            const offset = Number(this.buffer.readBigUInt64LE(entryOffset));
            const size = Number(this.buffer.readBigUInt64LE(entryOffset + 8));
            const nameOffset = this.buffer.readUInt32LE(entryOffset + 16);

            let name = '';
            for (let j = nameOffset; j < stringEndOffset && stringTable[j] !== 0; j++) {
                name += String.fromCharCode(stringTable[j]);
            }

            stringEndOffset = nameOffset;

            this.files.push({
                name,
                offset: offset + headerSize,
                size,
                data: this.buffer.slice(offset + headerSize, offset + headerSize + size)
            });
        }

        this.files.reverse();
    }

    getFiles() {
        return this.files;
    }

    getHeaderSize() {
        return 0x10 + this.files.length * 0x18 + this.buffer.readUInt32LE(8);
    }
}

export class PFS0Writer {
    constructor(fixPadding = true) {
        this._writer = new RootPFS0Writer(fixPadding);
        this.files = [];
    }

    add(name, data) {
        const buf = data instanceof Buffer ? data : Buffer.from(data);
        this.files.push({ name, data: buf });
        this._writer.add(name, buf.length);
    }

    build() {
        const header = this._writer.buildHeader();
        const output = Buffer.alloc(header.length + this._writer.files.reduce((s, f) => s + f.size, 0));
        Buffer.from(header.buffer, header.byteOffset, header.byteLength).copy(output, 0);
        for (let i = 0; i < this.files.length; i++) {
            this.files[i].data.copy(output, header.length + this._writer.files[i].offset);
        }
        return output;
    }
}