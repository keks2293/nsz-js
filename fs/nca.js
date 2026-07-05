import { AesEcb } from '../crypto/aes128.js';

const FsType = Object.freeze({ NONE: 0, PFS0: 2, ROMFS: 3 });

class SectionHeader {
    constructor(buffer) {
        const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        this.fsType = buffer[0x3];
        this.cryptoType = buffer[0x4];
        this.sectionStart = Number(view.getBigUint64(0x40, true));
        this.size = Number(view.getBigUint64(0x48, true));
        this.bktr1Buffer = buffer.slice(0x100, 0x120);
        this.bktr2Buffer = buffer.slice(0x120, 0x140);
        this.cryptoCounter = buffer.slice(0x140, 0x148).reverse();
    }
}

export class NCAHeader {
    static parse(buffer, keys = null) {
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
        const mk = masterKey < 0 ? 0 : masterKey;

        // Decrypt key block to get titleKeyDec
        let titleKeyDec = null;
        if (keys) {
            const kakHex = keys.keyAreaKeys?.[mk]?.[0];
            if (kakHex) {
                const kak = typeof kakHex === 'string'
                    ? KeysParser_hexToBytes(kakHex)
                    : kakHex;
                const ecb = new AesEcb(kak);
                const unwrapped = ecb.decrypt(keyBlock);
                titleKeyDec = unwrapped.slice(32, 48);
            }
        }

        // Parse section headers (0x200 bytes each at offset 0x400)
        const sections = [];
        const sectionFilesystems = [];
        for (let i = 0; i < 4; i++) {
            const sectionHeaderOffset = 0x400 + i * 0x200;
            const sectionHeaderData = arr.slice(sectionHeaderOffset, sectionHeaderOffset + 0x200);
            const sectionHdr = new SectionHeader(sectionHeaderData);
            const st = sectionTables[i];

            if (sectionHdr.fsType) {
                sections.push({
                    offset: st.offset,
                    endOffset: st.endOffset,
                    size: st.endOffset - st.offset,
                    fsType: sectionHdr.fsType,
                    cryptoType: sectionHdr.cryptoType,
                    cryptoKey: titleKeyDec,
                    sectionStart: sectionHdr.sectionStart,
                    sectionSize: sectionHdr.size,
                    cryptoCounter: sectionHdr.cryptoCounter,
                    bktr1Buffer: sectionHdr.bktr1Buffer,
                    bktr2Buffer: sectionHdr.bktr2Buffer,
                });
                sectionFilesystems.push({
                    fsType: sectionHdr.fsType,
                    cryptoType: sectionHdr.cryptoType,
                    sectionStart: sectionHdr.sectionStart,
                    size: sectionHdr.size,
                    cryptoCounter: sectionHdr.cryptoCounter,
                    bktr1Buffer: sectionHdr.bktr1Buffer,
                    bktr2Buffer: sectionHdr.bktr2Buffer,
                });
            }
        }

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
            masterKey: mk,
            hasTitleRights: rightsId !== '0'.repeat(32),
            titleKeyDec,
            sections,
            sectionFilesystems,
        };
    }

    static getContentTypeName(type) {
        const names = ['PROGRAM', 'META', 'CONTROL', 'MANUAL', 'DATA', 'PUBLICDATA'];
        return names[type] || 'UNKNOWN';
    }
}

// Inline hex-to-bytes to avoid importing KeysParser (circular dependency risk)
function KeysParser_hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
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

export { FsType, SectionHeader };
