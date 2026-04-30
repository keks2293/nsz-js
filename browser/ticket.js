export { sha256 } from './crypto/sha256.js';

export class Ticket {
    static parse(buffer) {
        const view = new DataView(buffer);
        let offset = 0;

        const signatureType = view.getUint32(offset, false);
        offset += 4;

        const signatureSizes = {
            0x010000: 0x200,
            0x010001: 0x100,
            0x010002: 0x3C,
            0x010003: 0x200,
            0x010004: 0x100,
            0x010005: 0x3C
        };

        const sigSize = signatureSizes[signatureType] || 0x100;
        offset += sigSize;

        const paddingSize = 0x40 - ((sigSize + 4) % 0x40);
        offset += paddingSize;

        const issuerBytes = new Uint8Array(buffer.slice(offset, offset + 0x40));
        let issuer = '';
        for (let i = 0; i < 0x40 && issuerBytes[i] !== 0; i++) {
            issuer += String.fromCharCode(issuerBytes[i]);
        }
        offset += 0x40;

        const titleKeyBlock = new Uint8Array(buffer.slice(offset, offset + 0x10));
        offset += 0x100;

        offset += 1;
        const keyType = view.getUint8(offset);
        offset += 1;

        offset += 0xE;

        const ticketIdBytes = new Uint8Array(buffer.slice(offset, offset + 8));
        const ticketId = Array.from(ticketIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        offset += 8;

        const deviceIdBytes = new Uint8Array(buffer.slice(offset, offset + 8));
        const deviceId = Array.from(deviceIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        offset += 8;

        const rightsIdBytes = new Uint8Array(buffer.slice(offset, offset + 16));
        const rightsId = Array.from(rightsIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        offset += 16;

        const accountId = view.getUint32(offset, false);

        const titleId = rightsId.substring(0, 16);
        const masterKeyRevision = parseInt(rightsId.charAt(18) || '0', 16);
        const titleKey = Array.from(titleKeyBlock).map(b => b.toString(16).padStart(2, '0')).join('');

        return {
            signatureType,
            issuer,
            titleKeyBlock: titleKey,
            keyType,
            ticketId,
            deviceId,
            rightsId,
            accountId,
            titleId,
            masterKeyRevision,
            titleKey
        };
    }
}

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

export class NCAHeader {
    static parse(buffer) {
        const view = new DataView(buffer);
        
        const magic = String.fromCharCode(...new Uint8Array(buffer.slice(0x200, 0x204)));
        
        if (magic !== 'NCA3' && magic !== 'NCA2') {
            return null;
        }
        
        const isGameCard = view.getUint8(0x204);
        const contentType = view.getUint8(0x205);
        const cryptoType = view.getUint8(0x206);
        const keyIndex = view.getUint8(0x207);
        
        const size = Number(view.getBigUint64(0x208, true));
        
        const titleIdBytes = new Uint8Array(buffer.slice(0x210, 0x218));
        const titleId = Array.from(titleIdBytes).reverse().map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        
        const contentIndex = view.getUint32(0x218, true);
        const sdkVersion = view.getUint32(0x21C, true);
        const cryptoType2 = view.getUint8(0x220);
        
        const rightsId = Array.from(new Uint8Array(buffer.slice(0x230, 0x240))).map(b => b.toString(16).padStart(2, '0')).join('');
        
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
        
        const keyBlock = buffer.slice(0x300, 0x340);
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
        const view = new DataView(buffer);
        
        if (buffer.length < 0x30) return null;
        
        const bktrOffset = Number(view.getBigUint64(0, true));
        const bktrSize = Number(view.getBigUint64(8, true));
        const magic = String.fromCharCode(...new Uint8Array(buffer.slice(16, 20)));
        
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

export function extractHashesFromCnmt(files) {
    const hashes = new Set();
    
    for (const file of files) {
        if (file.name.toLowerCase().endsWith('.cnmt.nca')) {
            try {
                const header = NCAHeader.parse(file.data.slice(0, 0xC00));
                if (header && header.sectionTables[0]) {
                    const fsOffset = header.sectionTables[0].offset;
                    const fsSize = header.sectionTables[0].endOffset - header.sectionTables[0].offset;
                    
                    if (fsSize > 0 && fsOffset + fsSize <= file.data.length) {
                        const fsData = file.data.slice(fsOffset, fsOffset + fsSize);
                        const cnmt = Cnmt.parse(fsData);
                        
                        if (cnmt && cnmt.contentEntries) {
                            for (const entry of cnmt.contentEntries) {
                                hashes.add(entry.hash);
                            }
                        }
                    }
                }
            } catch (e) {
                console.warn('Failed to parse CNMT:', e);
            }
        }
    }
    
    return hashes;
}

import { sha256 } from './crypto/sha256.js';