export class Ticket {
    static parse(buffer) {
        const view = new DataView(buffer);
        let offset = 0;

        const signatureType = view.getUint32(offset, true);
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
