import { NCAHeader } from './nca.js';
import { Cnmt } from './cnmt.js';
import { PFS0 } from './pfs0.js';
import { AesCtr, AesXts } from '../crypto/aes-ops.mjs';

function toBytes(key) {
    if (typeof key === 'string') {
        return new Uint8Array(key.match(/.{2}/g).map(b => parseInt(b, 16)));
    }
    return key instanceof Uint8Array ? key : new Uint8Array(key);
}

export async function extractContentHashes(ncaData, keys) {
    const hashes = new Set();
    try {
        const arr = ncaData instanceof Uint8Array ? ncaData : new Uint8Array(ncaData);

        if (!keys || !keys.header_key) {
            console.error('Cannot decrypt CNMT: missing keys (header_key)');
            return hashes;
        }

        const headerKeyBytes = toBytes(keys.header_key);
        if (headerKeyBytes.length !== 32) {
            console.error('Invalid header_key length:', headerKeyBytes.length);
            return hashes;
        }

        const xts = new AesXts(headerKeyBytes);

        const hdrLen = Math.min(0xC00, arr.length);
        const hdrEncrypted = arr.subarray(0, hdrLen);
        const hdrDecrypted = xts.decrypt(hdrEncrypted, 0);

        const header = NCAHeader.parse(hdrDecrypted, keys);

        if (header && header.sections && header.sections[0]) {
            const section = header.sections[0];
            const fsOffset = section.offset;
            const fsSize = section.size;

            if (fsSize > 0 && fsOffset + fsSize <= arr.length) {
                const sectionData = arr.subarray(fsOffset, fsOffset + fsSize);

                if (!section.cryptoKey) {
                    console.error('No titleKeyDec for masterKey:', header.masterKey);
                    return hashes;
                }

                const aesCtr = new AesCtr(section.cryptoKey, section.cryptoCounter);
                aesCtr.seek(fsOffset);

                const fsData = await aesCtr.decrypt(sectionData);

                const pfs0Start = 0x20;
                const pfs0Magic = fsData.length > pfs0Start + 4
                    ? String.fromCharCode(fsData[pfs0Start], fsData[pfs0Start + 1], fsData[pfs0Start + 2], fsData[pfs0Start + 3])
                    : '';

                let cnmtRaw = null;

                if (pfs0Magic === 'PFS0') {
                    const pfs0 = new PFS0(fsData.subarray(pfs0Start));
                    const pfs0Files = pfs0.getFiles();
                    if (pfs0Files.length > 0) {
                        const f = pfs0Files[0];
                        cnmtRaw = pfs0._data.slice(f.offset, f.offset + f.size);
                    } else {
                        cnmtRaw = fsData.subarray(pfs0Start);
                    }
                } else {
                    const magic = String.fromCharCode(fsData[0], fsData[1], fsData[2], fsData[3]);
                    if (magic === 'PFS0') {
                        cnmtRaw = fsData;
                    }
                }

                if (cnmtRaw) {
                    const cnmt = Cnmt.parse(cnmtRaw);
                    if (cnmt && cnmt.contentEntries) {
                        for (const entry of cnmt.contentEntries) {
                            hashes.add(entry.hash);
                        }
                    }
                }
            }
        }
    } catch (e) {
        console.error('Error extracting CNMT hashes:', e);
    }
    return hashes;
}
