export class HFS0Reader {
    constructor(buffer) {
        this.buffer = buffer instanceof ArrayBuffer ? buffer : buffer.buffer;
        this.view = new DataView(this.buffer);
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
        const stringTable = new Uint8Array(this.buffer.slice(stringTableOffset, stringTableOffset + stringTableSize));

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

export class XCIReader {
    constructor(buffer) {
        this.buffer = buffer instanceof ArrayBuffer ? buffer : buffer.buffer;
        this.view = new DataView(this.buffer);
        this.parse();
    }

    parse() {
        const signature = this.buffer.slice(0, 0x100);
        const magic = String.fromCharCode(
            this.view.getUint8(0x100),
            this.view.getUint8(0x101),
            this.view.getUint8(0x102),
            this.view.getUint8(0x103)
        );

        this.secureOffset = this.view.getUint32(0x104, true);
        this.backupOffset = this.view.getUint32(0x108, true);
        this.titleKekIndex = this.view.getUint8(0x10C);
        this.gamecardSize = this.view.getUint8(0x10D);
        this.gamecardHeaderVersion = this.view.getUint8(0x10E);
        this.gamecardFlags = this.view.getUint8(0x10F);
        this.packageId = Number(this.view.getBigUint64(0x110, true));
        this.validDataEndOffset = Number(this.view.getBigUint64(0x118, true));
        this.gamecardInfo = this.buffer.slice(0x120, 0x130);

        this.hfs0Offset = Number(this.view.getBigUint64(0x130, true));
        this.hfs0HeaderSize = Number(this.view.getBigUint64(0x138, true));
        this.hfs0HeaderHash = this.buffer.slice(0x140, 0x160);
        this.hfs0InitialDataHash = this.buffer.slice(0x160, 0x180);
        this.secureMode = this.view.getUint32(0x180, true);

        this.titleKeyFlag = this.view.getUint32(0x184, true);
        this.keyFlag = this.view.getUint32(0x188, true);
        this.normalAreaEndOffset = this.view.getUint32(0x18C, true);

        const hfs0Data = this.buffer.slice(this.hfs0Offset, this.hfs0Offset + this.hfs0HeaderSize);
        this.hfs0 = new HFS0Reader(hfs0Data);
    }

    getSecurePartition() {
        return this.hfs0.getFiles();
    }
}