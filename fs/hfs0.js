export class HFS0Reader {
    constructor(data, baseOffset = 0) {
        this.data = data instanceof Uint8Array ? data : new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer);
        this.view = new DataView(this.data.buffer, this.data.byteOffset, this.data.byteLength);
        this._headerSize = 0;
        this.files = [];
        this.parse(baseOffset);
    }

    parse(baseOffset) {
        const magic = String.fromCharCode(
            this.view.getUint8(0),
            this.view.getUint8(1),
            this.view.getUint8(2),
            this.view.getUint8(3)
        );

        if (magic !== 'HFS0') {
            throw new Error(`Invalid HFS0 magic: ${magic}`);
        }

        const fileCount = this.view.getUint32(4, true);
        const stringTableSize = this.view.getUint32(8, true);

        this._headerSize = 0x10 + fileCount * 0x40 + stringTableSize;

        const stringTableOffset = 0x10 + fileCount * 0x40;
        const stringTable = this.data.slice(stringTableOffset, stringTableOffset + stringTableSize);

        for (let i = 0; i < fileCount; i++) {
            const entryOffset = 0x10 + i * 0x40;

            const storedOffset = Number(this.view.getBigUint64(entryOffset, true));
            const size = Number(this.view.getBigUint64(entryOffset + 8, true));
            const nameOffset = this.view.getUint32(entryOffset + 16, true);

            let name = '';
            for (let j = nameOffset; j < stringTable.length && stringTable[j] !== 0; j++) {
                name += String.fromCharCode(stringTable[j]);
            }

            this.files.push({
                name,
                offset: baseOffset + this._headerSize + storedOffset,
                size,
                storedOffset
            });
        }
    }

    getFiles() {
        return this.files;
    }

    getHeaderSize() {
        return this._headerSize;
    }
}

export class HFS0Writer {
    constructor(paddingSize = 0) {
        this.entries = [];
        this._paddingSize = paddingSize;
    }

    addFile(name, data) {
        const size = data instanceof ArrayBuffer ? data.byteLength : data.length;
        this.entries.push({ name, data, size });
    }

    addEntry(name, size) {
        this.entries.push({ name, data: null, size });
    }

    _writeHeader(output, stringBytes, dataStart, actualHeader) {
        const view = new DataView(output.buffer, output.byteOffset, output.byteLength);

        output[0] = 0x48; output[1] = 0x46; output[2] = 0x53; output[3] = 0x30;
        view.setUint32(4, this.entries.length, true);
        view.setUint32(8, stringBytes.length, true);
        view.setUint32(12, 0, true);

        const stringTableStart = 0x10 + this.entries.length * 0x40;
        output.set(stringBytes, stringTableStart);

        let sOff = 0;
        let filePos = dataStart;
        for (let i = 0; i < this.entries.length; i++) {
            const e = this.entries[i];
            const pos = 0x10 + i * 0x40;
            view.setBigUint64(pos, BigInt(filePos - actualHeader), true);
            view.setBigUint64(pos + 8, BigInt(e.size), true);
            view.setUint32(pos + 16, sOff, true);
            view.setUint32(pos + 20, 0, true);
            view.setUint32(pos + 24, 0, true);
            view.setUint32(pos + 28, 0, true);
            view.setBigUint64(pos + 32, 0n, true);
            sOff += e.name.length + 1;
            filePos += e.size;
        }
    }

    _stringTableBytes() {
        return new TextEncoder().encode(this.entries.map(e => e.name).join('\0') + '\0');
    }

    _buildLayout() {
        const stringBytes = this._stringTableBytes();
        const actualHeader = 0x10 + this.entries.length * 0x40 + stringBytes.length;
        const headerSize = Math.max(this._paddingSize, actualHeader);
        return { stringBytes, actualHeader, headerSize };
    }

    buildHeader() {
        const { stringBytes, actualHeader, headerSize } = this._buildLayout();
        const output = new Uint8Array(headerSize);
        this._writeHeader(output, stringBytes, headerSize, actualHeader);
        return { buffer: output, actualHeader, headerSize };
    }

    build() {
        const { buffer: header, actualHeader, headerSize } = this.buildHeader();

        let totalDataSize = 0;
        for (const e of this.entries) totalDataSize += e.size;

        const output = new Uint8Array(headerSize + totalDataSize);
        output.set(header, 0);

        let dataPos = headerSize;
        for (const e of this.entries) {
            if (e.data) {
                const arr = e.data instanceof ArrayBuffer ? new Uint8Array(e.data) : e.data;
                output.set(arr, dataPos);
            }
            dataPos += e.size;
        }

        return output;
    }
}
