export class ContentEntry {
    constructor(buffer) {
        const view = new DataView(buffer);
        this.hash = Array.from(new Uint8Array(buffer.slice(0, 32))).map(b => b.toString(16).padStart(2, '0')).join('');
        this.ncaId = Array.from(new Uint8Array(buffer.slice(32, 48))).map(b => b.toString(16).padStart(2, '0')).join('');

        const sizeLow = view.getUint32(48, true);
        const sizeHigh = view.getUint8(52);
        this.size = sizeLow | (sizeHigh << 32);

        this.type = view.getUint8(53);
    }
}

export class MetaEntry {
    constructor(buffer) {
        const view = new DataView(buffer);
        const titleIdBytes = new Uint8Array(buffer.slice(0, 8));
        this.titleId = Array.from(titleIdBytes).reverse().map(b => b.toString(16).padStart(2, '0')).join('');
        this.version = view.getUint32(8, true);
        this.type = view.getUint8(12);
        this.install = view.getUint8(13);
    }
}

export class Cnmt {
    static parse(buffer) {
        const view = new DataView(buffer);

        const titleIdBytes = new Uint8Array(buffer.slice(0, 8));
        const titleId = Array.from(titleIdBytes).reverse().map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        const version = view.getUint32(8, true);
        const titleType = view.getUint8(12);

        const headerOffset = view.getUint16(18, true);
        const contentEntryCount = view.getUint16(20, true);
        const metaEntryCount = view.getUint16(22, true);

        const contentEntries = [];
        const metaEntries = [];

        const contentStart = 0x20 + headerOffset;

        for (let i = 0; i < contentEntryCount; i++) {
            const entryBuffer = buffer.slice(contentStart + i * 0x38, contentStart + (i + 1) * 0x38);
            contentEntries.push(new ContentEntry(entryBuffer));
        }

        const metaStart = contentStart + contentEntryCount * 0x38;
        for (let i = 0; i < metaEntryCount; i++) {
            const entryBuffer = buffer.slice(metaStart + i * 0x20, metaStart + (i + 1) * 0x20);
            metaEntries.push(new MetaEntry(entryBuffer));
        }

        return {
            titleId,
            version,
            titleType,
            headerOffset,
            contentEntryCount,
            metaEntryCount,
            contentEntries,
            metaEntries
        };
    }
}
