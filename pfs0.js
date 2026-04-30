class PFS0Reader {
    constructor(buffer) {
        this.buffer = buffer instanceof ArrayBuffer ? buffer : buffer.buffer;
        this.view = new DataView(this.buffer);
        this.files = [];
        this.headerSize = 0;
        this.stringTableSize = 0;
        this.parse();
    }

parse() {
        const magic = this.readString(0, 4);
        if (magic !== 'PFS0') {
            throw new Error(`Invalid PFS0 magic: ${magic}`);
        }

        const fileCount = this.readUint32(4);
        this.stringTableSize = this.readUint32(8);
        this.headerSize = 0x10 + fileCount * 0x18 + this.stringTableSize;
        
        const stringTableOffset = 0x10 + fileCount * 0x18;
        const stringTable = this.readBytes(stringTableOffset, this.stringTableSize);

        for (let i = 0; i < fileCount; i++) {
            const entryOffset = 0x10 + i * 0x18;
            const offset = Number(this.readUint64(entryOffset));
            const size = Number(this.readUint64(entryOffset + 8));
            const nameOffset = this.readUint32(entryOffset + 16);

            let name = '';
            for (let j = nameOffset; j < this.stringTableSize && j >= 0; j++) {
                if (stringTable[j] === 0) break;
                name += String.fromCharCode(stringTable[j]);
            }

            this.files.push({
                name,
                offset: offset + this.headerSize,
                size
            });
        }
    }

    getFiles() {
        return this.files;
    }

    getHeaderSize() {
        return this.headerSize;
    }

    getStringTableSize() {
        return this.stringTableSize;
    }

    readFile(index) {
        const file = this.files[index];
        return this.readBytes(file.offset, file.size);
    }

    readUint8(offset) {
        return this.view.getUint8(offset);
    }

    readUint16(offset) {
        return this.view.getUint16(offset, true);
    }

    readUint32(offset) {
        return this.view.getUint32(offset, true);
    }

    readUint64(offset) {
        const low = this.view.getUint32(offset, true);
        const high = this.view.getUint32(offset + 4, true);
        return BigInt(low) + (BigInt(high) << 32n);
    }

    readBytes(offset, length) {
        // Create proper Uint8Array view from sliced buffer
        const slice = this.buffer.slice(offset, offset + length);
        return new Uint8Array(slice);
    }

    readString(offset, length) {
        let str = '';
        for (let i = 0; i < length; i++) {
            const char = this.view.getUint8(offset + i);
            if (char === 0) break;
            str += String.fromCharCode(char);
        }
        return str;
    }
}

class PFS0Writer {
    constructor() {
        this.files = [];
    }

    addFile(name, data) {
        this.files.push({ name, data });
    }

    build() {
        const stringTable = this.buildStringTable();
        const headerSize = 0x10 + this.files.length * 0x18;
        const paddedStringTableSize = stringTable.length + (16 - ((headerSize + stringTable.length) % 16)) % 16;
        
        let offset = headerSize + paddedStringTableSize;
        const fileEntries = [];

        for (const file of this.files) {
            fileEntries.push({
                name: file.name,
                offset: offset,
                size: file.data.byteLength
            });
            offset += file.data.byteLength;
        }

        const header = new ArrayBuffer(headerSize + paddedStringTableSize);
        const view = new DataView(header);
        const bytes = new Uint8Array(header);

        let pos = 0;
        view.setUint32(pos, 0x50465330, false); pos += 4;
        view.setUint32(pos, this.files.length, true); pos += 4;
        view.setUint32(pos, paddedStringTableSize, true); pos += 4;
        view.setUint32(pos, 0, true); pos += 4;

        let stringPos = headerSize;
        for (let i = 0; i < fileEntries.length; i++) {
            const entry = fileEntries[i];
            const relativeOffset = entry.offset - headerSize;
            
            view.setBigUint64(pos, BigInt(relativeOffset), true); pos += 8;
            view.setBigUint64(pos, BigInt(entry.size), true); pos += 8;
            view.setUint32(pos, stringPos - headerSize, true); pos += 4;
            view.setUint32(pos, 0, true); pos += 4;

            for (let j = 0; j < entry.name.length; j++) {
                bytes[stringPos++] = entry.name.charCodeAt(j);
            }
            bytes[stringPos++] = 0;
        }

        const chunks = [new Uint8Array(header)];
        for (const file of this.files) {
            chunks.push(new Uint8Array(file.data));
        }

        return new Blob(chunks, { type: 'application/octet-stream' });
    }

    buildStringTable() {
        let str = '';
        for (const file of this.files) {
            str += file.name + '\0';
        }
        return str;
    }
}

export { PFS0Reader, PFS0Writer };