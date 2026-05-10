import { DataReader, BufferReader } from './ncz.js';


export class HFS0Reader {
    constructor(data) {
        this.data = data instanceof Uint8Array ? data : new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer);
        this.view = new DataView(this.data.buffer, this.data.byteOffset, this.data.byteLength);
        this.files = [];
        this.parse();
    }

    parse() {
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

        const headerSize = 0x10 + fileCount * 0x40 + stringTableSize;

        const stringTableOffset = 0x10 + fileCount * 0x40;
        const stringTable = this.data.slice(stringTableOffset, stringTableOffset + stringTableSize);

        let stringEndOffset = stringTableSize;

        for (let i = 0; i < fileCount; i++) {
            const entryOffset = 0x10 + i * 0x40;

            const offset = Number(this.view.getBigUint64(entryOffset, true));
            const size = Number(this.view.getBigUint64(entryOffset + 8, true));
            const nameOffset = this.view.getUint32(entryOffset + 16, true);

            let name = '';
            for (let j = nameOffset; j < stringEndOffset && stringTable[j] !== 0; j++) {
                name += String.fromCharCode(stringTable[j]);
            }

            stringEndOffset = nameOffset;

            this.files.push({
                name,
                offset: offset + headerSize,
                size
            });
        }
    }

    getFiles() {
        return this.files;
    }

    getHeaderSize() {
        const fileCount = this.view.getUint32(4, true);
        const stringTableSize = this.view.getUint32(8, true);
        return 0x10 + fileCount * 0x40 + stringTableSize;
    }
}

export class HFS0Writer {
    constructor() {
        this.files = [];
    }

    addFile(name, data) {
        this.files.push({ name, data });
    }

    build() {
        const stringTable = this.files.map(f => f.name).join('\0') + '\0';
        const stringTableBytes = new TextEncoder().encode(stringTable);

        const headerBase = 0x10 + this.files.length * 0x40;
        const totalHeaderSize = headerBase + stringTableBytes.length;

        let fileOffset = 0;
        const fileEntries = this.files.map(f => {
            const entry = {
                name: f.name,
                offset: fileOffset,
                size: f.data.byteLength || f.data.length
            };
            fileOffset += entry.size;
            return entry;
        });

        const totalSize = totalHeaderSize + fileOffset;
        const output = new Uint8Array(totalSize);
        const view = new DataView(output.buffer);

        output[0] = 0x48; output[1] = 0x46; output[2] = 0x53; output[3] = 0x30;
        view.setUint32(4, this.files.length, true);
        view.setUint32(8, stringTableBytes.length, true);
        view.setUint32(12, 0, true);

        output.set(stringTableBytes, headerBase);

        const nameBytes = new TextEncoder();
        let stringOffset = 0;
        for (let i = 0; i < this.files.length; i++) {
            const entry = fileEntries[i];
            const pos = 0x10 + i * 0x40;

            view.setBigUint64(pos, BigInt(entry.offset), true);
            view.setBigUint64(pos + 8, BigInt(entry.size), true);
            view.setUint32(pos + 16, stringOffset, true);
            view.setUint32(pos + 20, 0, true);
            view.setUint32(pos + 24, 0, true);
            view.setUint32(pos + 28, 0, true);
            view.setBigUint64(pos + 32, 0n, true);

            const encoded = nameBytes.encode(entry.name);
            output.set(encoded, headerBase + stringOffset);
            stringOffset += encoded.length + 1;
        }

        let dataPos = totalHeaderSize;
        for (let i = 0; i < this.files.length; i++) {
            const data = this.files[i].data;
            const arr = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
            output.set(arr, dataPos);
            dataPos += arr.length;
        }

        return output;
    }
}

export class XCIReader {
    constructor(readerOrBuffer) {
        if (readerOrBuffer instanceof DataReader) {
            this.reader = readerOrBuffer;
        } else {
            this.reader = new BufferReader(readerOrBuffer);
        }
        this.hfs0 = null;
    }

    async parse() {
        const headerBytes = await this.reader.read(0, 0x200);
        const view = new DataView(headerBytes.buffer, headerBytes.byteOffset, headerBytes.byteLength);

        const magic = String.fromCharCode(
            view.getUint8(0x100),
            view.getUint8(0x101),
            view.getUint8(0x102),
            view.getUint8(0x103)
        );

        this.secureOffset = view.getUint32(0x104, true);
        this.backupOffset = view.getUint32(0x108, true);
        this.titleKekIndex = view.getUint8(0x10C);
        this.gamecardSize = view.getUint8(0x10D);
        this.gamecardHeaderVersion = view.getUint8(0x10E);
        this.gamecardFlags = view.getUint8(0x10F);
        this.packageId = Number(view.getBigUint64(0x110, true));
        this.validDataEndOffset = Number(view.getBigUint64(0x118, true));
        this.gamecardInfo = headerBytes.slice(0x120, 0x130);

        this.hfs0Offset = Number(view.getBigUint64(0x130, true));
        this.hfs0HeaderSize = Number(view.getBigUint64(0x138, true));
        this.hfs0HeaderHash = headerBytes.slice(0x140, 0x160);
        this.hfs0InitialDataHash = headerBytes.slice(0x160, 0x180);
        this.secureMode = view.getUint32(0x180, true);

        this.titleKeyFlag = view.getUint32(0x184, true);
        this.keyFlag = view.getUint32(0x188, true);
        this.normalAreaEndOffset = view.getUint32(0x18C, true);

        const hfs0Data = await this.reader.read(this.hfs0Offset, this.hfs0HeaderSize);
        this.hfs0 = new HFS0Reader(hfs0Data);
    }

    getSecurePartition() {
        return this.hfs0 ? this.hfs0.getFiles() : [];
    }
}

export class XCIWriter {
    constructor(headerBytes) {
        this.header = new Uint8Array(0x200);
        if (headerBytes && headerBytes.length >= 0x200) {
            this.header.set(headerBytes.slice(0, 0x200));
        } else {
            this.header[0x100] = 0x48; this.header[0x101] = 0x45; this.header[0x102] = 0x41; this.header[0x103] = 0x44;
        }
        this.hfs0Data = null;
    }

    setHFS0Data(hfs0Data) {
        this.hfs0Data = hfs0Data;
    }

    build() {
        if (!this.hfs0Data) throw new Error('No HFS0 data set');

        const hfs0Offset = 0x200;
        const totalSize = hfs0Offset + this.hfs0Data.length;

        const output = new Uint8Array(totalSize);
        output.set(this.header, 0);

        const view = new DataView(output.buffer, output.byteOffset, output.byteLength);

        const hfs0View = new DataView(this.hfs0Data.buffer, this.hfs0Data.byteOffset, this.hfs0Data.byteLength);
        const fileCount = hfs0View.getUint32(4, true);
        const stringTableSize = hfs0View.getUint32(8, true);
        const hfs0HeaderSize = 0x10 + fileCount * 0x40 + stringTableSize;

        view.setBigUint64(0x118, BigInt(totalSize), true);
        view.setBigUint64(0x130, BigInt(hfs0Offset), true);
        view.setBigUint64(0x138, BigInt(hfs0HeaderSize), true);

        output.set(this.hfs0Data, hfs0Offset);

        return output;
    }
}
