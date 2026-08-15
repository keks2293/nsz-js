// Shared NCA utilities extracted from duplicated code in nca-pack.js, update.js, bktr.js, bktr-merge.js

export const NCA_HEADER_SIZE = 0xC00;

export function hexToBytes(hex) {
    const buf = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        buf[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return buf;
}

export function writeU64LE(buf, offset, value) {
    const n = typeof value === 'bigint' ? value : BigInt(value);
    const view = new DataView(buf.buffer, buf.byteOffset + offset, 8);
    view.setBigUint64(0, n, true);
}

export function writeU32LE(buf, offset, value) {
    const view = new DataView(buf.buffer, buf.byteOffset + offset, 4);
    view.setUint32(0, value, true);
}
