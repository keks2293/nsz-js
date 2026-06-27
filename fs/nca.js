export class NCAHeader {
    static parse(buffer) {
        const arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        const view = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);

        const magic = String.fromCharCode(arr[0x200], arr[0x201], arr[0x202], arr[0x203]);

        if (magic !== 'NCA3' && magic !== 'NCA2') {
            return null;
        }

        const isGameCard = view.getUint8(0x204);
        const contentType = view.getUint8(0x205);
        const cryptoType = view.getUint8(0x206);
        const keyIndex = view.getUint8(0x207);

        const size = Number(view.getBigUint64(0x208, true));

        const titleIdBytes = arr.slice(0x210, 0x218);
        const titleId = Array.from(titleIdBytes).reverse().map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

        const contentIndex = view.getUint32(0x218, true);
        const sdkVersion = view.getUint32(0x21C, true);
        const cryptoType2 = view.getUint8(0x220);

        const rightsId = Array.from(arr.slice(0x230, 0x240)).map(b => b.toString(16).padStart(2, '0')).join('');

        const sectionTables = [];
        for (let i = 0; i < 4; i++) {
            const tableOffset = 0x240 + i * 0x10;
            const mediaOffset = view.getUint32(tableOffset, true);
            const mediaEndOffset = view.getUint32(tableOffset + 4, true);

            sectionTables.push({
                mediaOffset,
                mediaEndOffset,
                offset: mediaOffset * 0x200,
                endOffset: mediaEndOffset * 0x200,
                unknown1: view.getUint32(tableOffset + 8, true),
                unknown2: view.getUint32(tableOffset + 12, true)
            });
        }

        const keyBlock = arr.slice(0x300, 0x340);
        const masterKey = Math.max(cryptoType, cryptoType2) - 1;

        return {
            magic,
            isGameCard,
            contentType,
            cryptoType,
            keyIndex,
            size,
            titleId,
            contentIndex,
            sdkVersion,
            cryptoType2,
            rightsId,
            sectionTables,
            keyBlock,
            masterKey: masterKey < 0 ? 0 : masterKey,
            hasTitleRights: rightsId !== '0'.repeat(32)
        };
    }

    static getContentTypeName(type) {
        const names = ['PROGRAM', 'META', 'CONTROL', 'MANUAL', 'DATA', 'PUBLICDATA'];
        return names[type] || 'UNKNOWN';
    }
}

export class BKTR {
    static parseSection(buffer, ncaOffset) {
        const arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        const view = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);

        if (arr.length < 0x30) return null;

        const bktrOffset = Number(view.getBigUint64(0, true));
        const bktrSize = Number(view.getBigUint64(8, true));
        const magic = String.fromCharCode(arr[16], arr[17], arr[18], arr[19]);

        if (magic !== 'BKTR' || bktrSize === 0) return null;

        const version = view.getUint32(20, true);
        const entryCount = view.getUint32(24, true);

        return {
            bktrOffset,
            bktrSize,
            magic,
            version,
            entryCount,
            ncaOffset
        };
    }
}
