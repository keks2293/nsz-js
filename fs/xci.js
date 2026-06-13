import { DataReader, BufferReader } from './ncz.js';

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

        let stringEndOffset = stringTableSize;

        for (let i = 0; i < fileCount; i++) {
            const entryOffset = 0x10 + i * 0x40;

            const storedOffset = Number(this.view.getBigUint64(entryOffset, true));
            const size = Number(this.view.getBigUint64(entryOffset + 8, true));
            const nameOffset = this.view.getUint32(entryOffset + 16, true);

            let name = '';
            for (let j = nameOffset; j < stringEndOffset && stringTable[j] !== 0; j++) {
                name += String.fromCharCode(stringTable[j]);
            }

            stringEndOffset = nameOffset;

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

    _buildStringTable() {
        return new TextEncoder().encode(this.entries.map(e => e.name).join('\0') + '\0');
    }

    _getActualHeaderSize(stringBytes) {
        return 0x10 + this.entries.length * 0x40 + stringBytes.length;
    }

    _getHeaderSize(stringBytes) {
        return Math.max(this._paddingSize, this._getActualHeaderSize(stringBytes));
    }

    _writeHeader(output, stringBytes, dataStart) {
        const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
        const actualHeader = this._getActualHeaderSize(stringBytes);

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
            const enc = new TextEncoder().encode(e.name);
            sOff += enc.length + 1;
            filePos += e.size;
        }
    }

    buildHeader() {
        const stringBytes = this._buildStringTable();
        const headerSize = this._getHeaderSize(stringBytes);
        const output = new Uint8Array(headerSize);
        this._writeHeader(output, stringBytes, headerSize);
        return output;
    }

    build() {
        const stringBytes = this._buildStringTable();
        const headerSize = this._getHeaderSize(stringBytes);

        let totalDataSize = 0;
        for (const e of this.entries) totalDataSize += e.size;

        const output = new Uint8Array(headerSize + totalDataSize);
        this._writeHeader(output, stringBytes, headerSize);

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

    getActualHeaderSize() {
        return this._getActualHeaderSize(this._buildStringTable());
    }

    getHeaderSize() {
        return this._getHeaderSize(this._buildStringTable());
    }
}

const XCI_PARTITION_NAMES = new Set(['secure', 'normal', 'update', 'logo']);

export class XCIReader {
    constructor(readerOrBuffer) {
        if (readerOrBuffer instanceof DataReader) {
            this.reader = readerOrBuffer;
        } else {
            this.reader = new BufferReader(readerOrBuffer);
        }
        this.rootHfs0 = null;
        this.partitions = [];
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
        this.rootHfs0 = new HFS0Reader(hfs0Data, this.hfs0Offset);
        this.partitions = this.rootHfs0.getFiles();
    }

    getPartitions() {
        return this.partitions;
    }

    getSecurePartition() {
        return this.partitions;
    }

    async readPartitionFiles(partitionEntry) {
        const data = await this.reader.read(partitionEntry.offset, partitionEntry.size);
        return new HFS0Reader(data, partitionEntry.offset);
    }

    async readAllPartitionFiles() {
        const result = {};
        for (const p of this.partitions) {
            if (p.size > 0) {
                try {
                    result[p.name] = await this.readPartitionFiles(p);
                } catch (e) {
                    console.warn(`Failed to read partition ${p.name}: ${e.message}`);
                }
            }
        }
        return result;
    }
}

export class XCIWriter {
    constructor(headerBytes) {
        this.header = new Uint8Array(0x200);
        if (headerBytes && headerBytes.length >= 0x200) {
            this.header.set(headerBytes.slice(0, 0x200));
        } else {
            this.header[0x100] = 0x48; this.header[0x101] = 0x45; this.header[0x102] = 0x46; this.header[0x103] = 0x41;
        }
        this.partitions = [];
    }

    addPartition(name, hfs0Data) {
        this.partitions.push({ name, data: hfs0Data });
    }

    build() {
        const ROOT_HFS0_OFFSET = 0xF000;
        const PARTITION_HEADER_SIZE = 0x8000;

        const rootWriter = new HFS0Writer(PARTITION_HEADER_SIZE);
        for (const p of this.partitions) rootWriter.addEntry(p.name, p.data.length);
        const rootActualHeader = rootWriter.getActualHeaderSize();

        let partitionFilePos = 0;
        let currentDataOffset = ROOT_HFS0_OFFSET + rootActualHeader;
        const partitionEntries = [];
        for (const p of this.partitions) {
            const paddedSize = Math.max(PARTITION_HEADER_SIZE, p.data.length);
            partitionEntries.push({ name: p.name, dataOffset: currentDataOffset, dataSize: p.data.length });
            currentDataOffset += paddedSize;
            partitionFilePos += p.data.length;
        }

        const totalPaddedSize = currentDataOffset - (ROOT_HFS0_OFFSET + rootActualHeader);
        const totalSize = ROOT_HFS0_OFFSET + rootActualHeader + totalPaddedSize;
        const output = new Uint8Array(totalSize);
        const view = new DataView(output.buffer);

        const rootHeader = rootWriter.buildHeader();
        output.set(rootHeader, ROOT_HFS0_OFFSET);

        for (let i = 0; i < this.partitions.length; i++) {
            const p = this.partitions[i];
            const paddedHfs0Size = Math.max(PARTITION_HEADER_SIZE, p.data.length);
            if (paddedHfs0Size > p.data.length) {
                const realloc = new Uint8Array(paddedHfs0Size);
                realloc.set(p.data, 0);
                const partView = new DataView(realloc.buffer);
                const fileCount = partView.getUint32(4, true);
                const stringTableSize = partView.getUint32(8, true);
                const actualHfs0Header = 0x10 + fileCount * 0x40 + stringTableSize;
                if (actualHfs0Header < paddedHfs0Size) {
                    for (let j = 0; j < fileCount; j++) {
                        const epos = 0x10 + j * 0x40;
                        const stored = Number(partView.getBigUint64(epos, true));
                        partView.setBigUint64(epos, BigInt(stored + (paddedHfs0Size - p.data.length)), true);
                    }
                }
                output.set(realloc, partitionEntries[i].dataOffset);
            } else {
                output.set(p.data, partitionEntries[i].dataOffset);
            }
        }

        output.set(this.header, 0);
        view.setBigUint64(0x118, BigInt(totalSize), true);
        view.setBigUint64(0x130, BigInt(ROOT_HFS0_OFFSET), true);
        view.setBigUint64(0x138, BigInt(rootActualHeader), true);

        return output;
    }
}
