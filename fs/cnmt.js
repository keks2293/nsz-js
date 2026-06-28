export class ContentEntry {
    constructor(buffer) {
        const buf = buffer instanceof ArrayBuffer ? buffer : buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
        const view = new DataView(buf);
        this.hash = Array.from(new Uint8Array(buf.slice(0, 32))).map(b => b.toString(16).padStart(2, '0')).join('');
        this.ncaId = Array.from(new Uint8Array(buf.slice(32, 48))).map(b => b.toString(16).padStart(2, '0')).join('');

        const sizeLow = view.getUint32(48, true);
        const sizeHigh = view.getUint8(52);
        this.size = sizeLow | (sizeHigh << 32);

        this.type = view.getUint8(53);
    }
}

export class MetaEntry {
    constructor(buffer) {
        const buf = buffer instanceof ArrayBuffer ? buffer : buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
        const view = new DataView(buf);
        const titleIdBytes = new Uint8Array(buf.slice(0, 8));
        this.titleId = Array.from(titleIdBytes).reverse().map(b => b.toString(16).padStart(2, '0')).join('');
        this.version = view.getUint32(8, true);
        this.type = view.getUint8(12);
        this.install = view.getUint8(13);
    }
}

export class Cnmt {
    static parse(buffer) {
        const buf = buffer instanceof ArrayBuffer ? buffer : buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
        const view = new DataView(buf);

        const titleIdBytes = new Uint8Array(buf.slice(0, 8));
        const titleId = Array.from(titleIdBytes).reverse().map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        const version = view.getUint32(8, true);
        const titleType = view.getUint8(12);

        const tableOffset = view.getUint16(0x0E, true);
        const contentEntryCount = view.getUint16(0x10, true);
        const metaEntryCount = view.getUint16(0x12, true);

        const contentEntries = [];
        const metaEntries = [];

        const contentStart = 0x20 + tableOffset;

        for (let i = 0; i < contentEntryCount; i++) {
            const entryBuffer = buf.slice(contentStart + i * 0x38, contentStart + (i + 1) * 0x38);
            contentEntries.push(new ContentEntry(entryBuffer));
        }

        const metaStart = contentStart + contentEntryCount * 0x38;
        for (let i = 0; i < metaEntryCount; i++) {
            const entryBuffer = buf.slice(metaStart + i * 0x20, metaStart + (i + 1) * 0x20);
            metaEntries.push(new MetaEntry(entryBuffer));
        }

        return {
            titleId,
            version,
            titleType,
            tableOffset,
            contentEntryCount,
            metaEntryCount,
            contentEntries,
            metaEntries
        };
    }
}
