import { DataReader, BufferReader } from './ncz.js';
import { HFS0Reader, HFS0Writer } from './hfs0.js';

export { HFS0Reader, HFS0Writer };

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
