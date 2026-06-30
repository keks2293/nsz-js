const HEXES = new Array(256).fill().map((_, i) => i.toString(16).padStart(2, '0'));

function hex(bytes, reverse = false) {
    let h = '';
    if (reverse) {
        for (let i = bytes.length - 1; i >= 0; i--) h += HEXES[bytes[i]];
    } else {
        for (let i = 0; i < bytes.length; i++) h += HEXES[bytes[i]];
    }
    return h;
}

export class ContentEntry {
    constructor(buffer) {
        const data = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        this.hash = hex(data.subarray(0, 32));
        this.ncaId = hex(data.subarray(32, 48));

        const sizeLow = view.getUint32(48, true);
        const sizeHigh = view.getUint16(52, true);
        this.size = sizeLow + (sizeHigh * 0x100000000);

        this.type = view.getUint8(53);
    }
}

export class MetaEntry {
    constructor(buffer) {
        const data = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        this.titleId = hex(data.subarray(0, 8), true);
        this.version = view.getUint32(8, true);
        this.type = view.getUint8(12);
        this.install = view.getUint8(13);
    }
}

export class Cnmt {
    static parse(buffer) {
        const data = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

        const titleId = hex(data.subarray(0, 8), true).toUpperCase();
        const version = view.getUint32(8, true);
        const titleType = view.getUint8(12);

        const tableOffset = view.getUint16(0x0E, true);
        const contentEntryCount = view.getUint16(0x10, true);
        const metaEntryCount = view.getUint16(0x12, true);

        const contentEntries = [];
        const metaEntries = [];

        const contentStart = 0x20 + tableOffset;

        for (let i = 0; i < contentEntryCount; i++) {
            const entryBuffer = data.subarray(contentStart + i * 0x38, contentStart + (i + 1) * 0x38);
            contentEntries.push(new ContentEntry(entryBuffer));
        }

        const metaStart = contentStart + contentEntryCount * 0x38;
        for (let i = 0; i < metaEntryCount; i++) {
            const entryBuffer = data.subarray(metaStart + i * 0x20, metaStart + (i + 1) * 0x20);
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
