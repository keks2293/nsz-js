import { DataReader, BufferReader } from './ncz.js';
import { HFS0Reader } from './hfs0.js';

export { HFS0Reader };

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
