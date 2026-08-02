import { DataReader, BufferReader } from './ncz.js';
import { HFS0Reader } from './hfs0.js';

export { HFS0Reader };

const XCI_PARTITION_NAMES = new Set(['secure', 'normal', 'update', 'logo']);

export class XCIReader {
    constructor(readerOrBuffer) {
        if (readerOrBuffer instanceof DataReader || (readerOrBuffer && typeof readerOrBuffer.read === 'function')) {
            this.reader = readerOrBuffer;
        } else {
            this.reader = new BufferReader(readerOrBuffer);
        }
        this.rootHfs0 = null;
        this.partitions = [];
    }

    async parse() {
        const probe = await this.reader.read(0, 0x200);
        let headerBytes = probe;
        let headOffset = 0x100;

        if (String.fromCharCode(probe[0x100], probe[0x101], probe[0x102], probe[0x103]) !== 'HEAD') {
            const backup = await this.reader.read(0x1100, 0x200);
            if (String.fromCharCode(backup[0x100], backup[0x101], backup[0x102], backup[0x103]) === 'HEAD') {
                headerBytes = backup;
                headOffset = 0x1100;
            } else {
                throw new Error(`Invalid XCI container (bad HEAD magic at 0x100/0x1100)`);
            }
        }

        const view = new DataView(headerBytes.buffer, headerBytes.byteOffset, headerBytes.byteLength);

        this.headOffset = headOffset;
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

    async readPartitionHeader(partitionEntry) {
        const probe = await this.reader.read(partitionEntry.offset, 0x10);
        const v = new DataView(probe.buffer, probe.byteOffset, probe.byteLength);
        const fileCount = v.getUint32(4, true);
        const stringTableSize = v.getUint32(8, true);
        const headerSize = 0x10 + fileCount * 0x40 + stringTableSize;
        const data = await this.reader.read(partitionEntry.offset, headerSize);
        return new HFS0Reader(data, partitionEntry.offset);
    }

    async getSecureFiles() {
        const secure = this.partitions.find((p) => p.name === 'secure');
        if (!secure) return [];
        const hfs0 = await this.readPartitionHeader(secure);
        return hfs0.getFiles();
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
