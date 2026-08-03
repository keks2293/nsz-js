import { decryptNcaHeader, decryptNcaSection, parseCnmtFromDecryptedSection } from './nca.js';

export async function extractContentHashMap(ncaData, keys) {
    const map = new Map();
    const arr = ncaData instanceof Uint8Array ? ncaData : new Uint8Array(ncaData);

    const header = decryptNcaHeader(arr, keys);
    if (!header) return map;

    try {
        const section = header.sections && header.sections[0];
        if (!section) return map;

        const fsOffset = section.offset;
        const fsSize = section.size;

        if (fsSize > 0 && fsOffset + fsSize <= arr.length) {
            const sectionData = arr.subarray(fsOffset, fsOffset + fsSize);

            if (!section.cryptoKey) {
                console.error('No titleKeyDec for masterKey:', header.masterKey);
                return map;
            }

            const fsData = await decryptNcaSection(sectionData, section);
            const cnmt = parseCnmtFromDecryptedSection(fsData, section);
            if (cnmt && cnmt.contentEntries) {
                for (const entry of cnmt.contentEntries) {
                    map.set(entry.ncaId, entry.hash);
                }
            }
        }
    } catch (e) {
        console.error('Error extracting CNMT hash map:', e);
    }
    return map;
}
