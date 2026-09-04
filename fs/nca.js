import { AesCtr, AesXts } from '../crypto/aes-ops.mjs';
import { PFS0 } from './pfs0.js';
import { Cnmt } from './cnmt.js';
import { toKeyBytes, deriveTitlekeyFromKeyArea, bytesToHex, isMetaNca, NCA_HDR, FS_HDR, NCA_HEADER_SIZE } from './nca-utils.js';

const FsType = Object.freeze({ NONE: 0, PFS0: 2, ROMFS: 3 });

class SectionHeader {
    constructor(buffer) {
        const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        this.fsType = buffer[FS_HDR.HASH_TYPE];
        this.cryptoType = buffer[FS_HDR.CRYPTO_TYPE];
        this.sectionStart = Number(view.getBigUint64(FS_HDR.PFS0_OFFSET, true));
        this.size = Number(view.getBigUint64(FS_HDR.PFS0_SIZE, true));
        this.bktr1Buffer = buffer.slice(FS_HDR.PATCH_INFO, FS_HDR.PATCH_INFO_AESCTREX);
        this.bktr2Buffer = buffer.slice(FS_HDR.PATCH_INFO_AESCTREX, FS_HDR.SECTION_CTR);
        this.cryptoCounter = buffer.slice(FS_HDR.SECTION_CTR, FS_HDR.SECTION_CTR + 8).reverse();
    }
}

export class NCAHeader {
    static parse(buffer, keys = null) {
        const arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        const view = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);

        const magic = String.fromCharCode(arr[NCA_HDR.MAGIC], arr[NCA_HDR.MAGIC + 1], arr[NCA_HDR.MAGIC + 2], arr[NCA_HDR.MAGIC + 3]);

        if (magic !== 'NCA3' && magic !== 'NCA2') {
            return null;
        }

        const isGameCard = view.getUint8(NCA_HDR.DISTRIBUTION);
        const contentType = view.getUint8(NCA_HDR.CONTENT_TYPE);
        const cryptoType = view.getUint8(NCA_HDR.CRYPTO_TYPE);
        const keyIndex = view.getUint8(NCA_HDR.KAEK_IND);

        const size = Number(view.getBigUint64(NCA_HDR.SIZE, true));

        const titleIdBytes = arr.slice(NCA_HDR.TITLE_ID, NCA_HDR.TITLE_ID + 8);
        const titleId = bytesToHex(titleIdBytes.reverse()).toUpperCase();

        const contentIndex = view.getUint32(NCA_HDR.CONTENT_INDEX, true);
        const sdkVersion = view.getUint32(NCA_HDR.SDK_VERSION, true);
        const cryptoType2 = view.getUint8(NCA_HDR.CRYPTO_TYPE2);

        const rightsId = bytesToHex(arr.slice(NCA_HDR.RIGHTS_ID, NCA_HDR.RIGHTS_ID + 0x10));

        const sectionTables = [];
        for (let i = 0; i < 4; i++) {
            const tableOffset = NCA_HDR.SECTIONS + i * NCA_HDR.SECTION_ENTRY_SIZE;
            const mediaOffset = view.getUint32(tableOffset, true);
            const mediaEndOffset = view.getUint32(tableOffset + 4, true);

            sectionTables.push({
                mediaOffset,
                mediaEndOffset,
                offset: mediaOffset * NCA_HDR.MEDIA_BLOCK_SIZE,
                endOffset: mediaEndOffset * NCA_HDR.MEDIA_BLOCK_SIZE,
                unknown1: view.getUint32(tableOffset + 8, true),
                unknown2: view.getUint32(tableOffset + 12, true)
            });
        }

        // Raw key-area bytes + master key index (exposed for inspection)
        const keyBlock = arr.slice(NCA_HDR.KEY_AREA, NCA_HDR.KEY_AREA + 0x40);
        const masterKey = Math.max(cryptoType, cryptoType2) - 1;
        const mk = masterKey < 0 ? 0 : masterKey;

        // Decrypt key area to get titleKeyDec (hactool nca.c:685)
        const titleKeyDec = deriveTitlekeyFromKeyArea(arr, keys);

        // Parse section headers (0x200 bytes each at offset 0x400)
        const sections = [];
        const sectionFilesystems = [];
        for (let i = 0; i < 4; i++) {
            const sectionHeaderOffset = NCA_HDR.FS_HEADERS + i * NCA_HDR.FS_HEADER_SIZE;
            const sectionHeaderData = arr.slice(sectionHeaderOffset, sectionHeaderOffset + NCA_HDR.FS_HEADER_SIZE);
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

export function decryptNcaHeader(raw, keys = null) {
    if (!keys || !keys.header_key) return null;
    const headerKey = toKeyBytes(keys.header_key);
    if (headerKey.length !== 32) return null;
    const arr = raw instanceof Uint8Array ? raw : new Uint8Array(raw);
    const len = Math.min(NCA_HEADER_SIZE, arr.length);
    // Header is ALWAYS XTS-encrypted (hacPack encrypts unconditionally).
    // cryptoType byte = keygen index, NOT "no encryption".
    const decrypted = new AesXts(headerKey).decrypt(arr.subarray(0, len), 0);
    return NCAHeader.parse(decrypted, keys);
}

export async function decryptNcaSection(data, section) {
    if (section.cryptoType === 1 || !section.cryptoKey) return data;
    const aesCtr = new AesCtr(section.cryptoKey, section.cryptoCounter);
    aesCtr.seek(section.offset);
    return await aesCtr.decrypt(data);
}

export async function readCnmtFromMeta(reader, entry, header) {
    if (!isMetaNca(header)) return null;
    const section = header.sections[0];
    if (!section) return null;

    const data = await reader.read(entry.offset + section.offset, section.size);
    const fsData = await decryptNcaSection(data, section);
    return parseCnmtFromDecryptedSection(fsData, section);
}

function isPfs0(data, offset) {
    return offset + 4 <= data.length
        && String.fromCharCode(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]) === 'PFS0';
}

export function parseCnmtFromDecryptedSection(fsData, section) {
    const pfs0Start = section.sectionStart;
    if (!isPfs0(fsData, pfs0Start)) return null;
    const pfs0Raw = fsData.subarray(pfs0Start);
    const pfs0 = new PFS0(pfs0Raw);
    const files = pfs0.getFiles();
    if (files.length === 0) return null;
    const f = files[0];
    const raw = pfs0Raw.subarray(f.offset, f.offset + f.size);
    return Cnmt.parse(raw);
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
