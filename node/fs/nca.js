import crypto from 'crypto';
import { Keys, AESECB } from './keys.js';
import { PFS0 } from './pfs0.js';

const MEDIA_SIZE = 0x200;

export class NCAHeader {
    constructor(data) {
        this.data = data;
        this.parse();
    }

    parse() {
        this.signature1 = this.data.slice(0, 0x100);
        this.signature2 = this.data.slice(0x100, 0x200);
        this.magic = this.data.slice(0x200, 0x204).toString('ascii');
        this.isGameCard = this.data[0x204];
        this.contentType = this.data[0x205];

        this.cryptoType = this.data[0x206];
        this.keyIndex = this.data[0x207];
        this.size = Number(this.data.readBigUInt64LE(0x208));
        this.titleId = this.data.slice(0x210, 0x218).reverse().toString('hex').toUpperCase();
        this.contentIndex = this.data.readUInt32LE(0x218);
        this.sdkVersion = this.data.readUInt32LE(0x21C);
        this.cryptoType2 = this.data[0x220];

        this.padding = this.data.slice(0x221, 0x230);
        this.rightsId = this.data.slice(0x230, 0x240).toString('hex');

        if (this.magic !== 'NCA3' && this.magic !== 'NCA2') {
            throw new Error(`Invalid NCA magic: ${this.magic}`);
        }

        this.sectionTables = [];
        for (let i = 0; i < 4; i++) {
            const offset = 0x240 + i * 0x10;
            this.sectionTables.push({
                mediaOffset: this.data.readUInt32LE(offset),
                mediaEndOffset: this.data.readUInt32LE(offset + 4),
                offset: this.data.readUInt32LE(offset) * MEDIA_SIZE,
                endOffset: this.data.readUInt32LE(offset + 4) * MEDIA_SIZE,
                unknown1: this.data.readUInt32LE(offset + 8),
                unknown2: this.data.readUInt32LE(offset + 12)
            });
        }

        this.masterKey = Math.max(this.cryptoType, this.cryptoType2) - 1;
        if (this.masterKey < 0) this.masterKey = 0;

        this.encKeyBlock = this.data.slice(0x300, 0x340);
    }

    getKeyBlock() {
        return this.data.slice(0x300, 0x340);
    }

    hasTitleRights() {
        return this.rightsId !== '0'.repeat(32);
    }

    getRightsIdStr() {
        return this.rightsId;
    }

    getCryptoType() {
        return this.data[0x206];
    }

    getCryptoType2() {
        return this.data[0x220];
    }

    getRightsId() {
        return Number(this.data.readBigUInt128LE(0x230));
    }
}

export class NCA {
    constructor(data) {
        this.data = data instanceof Buffer ? data : Buffer.from(data);
        this.header = null;
        this.sectionFilesystems = [];
        this.sections = [];
        this.open();
    }

    open() {
        this.header = new NCAHeader(this.data.slice(0, 0xC00));

        for (let i = 0; i < 4; i++) {
            const offset = 0x400 + i * 0x200;
            const sectionData = this.data.slice(offset, offset + 0x200);
            
            if (sectionData[0x3] === 0x02) {
                this.sectionFilesystems.push(new PFS0(sectionData));
            }
        }

        this.titleKeyDec = this.header.keys ? this.header.keys[2] : null;
    }

    getContentType() {
        return this.header ? this.header.contentType : null;
    }

    buildId() {
        if (this.header && this.header.contentType === 0) {
            for (const fs of this.sectionFilesystems) {
                if (fs.files && fs.files.length > 0) {
                    const mainFile = fs.files[0];
                    if (mainFile.data && mainFile.data.length > 0x60) {
                        return mainFile.data.slice(0x40, 0x60).toString('hex').toUpperCase();
                    }
                }
            }
        }
        return null;
    }
}