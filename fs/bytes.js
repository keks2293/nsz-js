// Generic byte-level primitives (LE integer read/write, hex encode/decode).
// Shared by container readers (ncz.js), NCA code (nca-pack.js, update.js, bktr*),
// ticket handling, etc. No NCA/format-specific knowledge — DataView only.

export function hexToBytes(hex) {
    const buf = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        buf[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return buf;
}

const HEXES = new Array(256).fill().map((_, i) => i.toString(16).padStart(2, '0'));

export function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += HEXES[bytes[i]];
    return s;
}

export function readLeU64(buf, o) {
    return Number(new DataView(buf.buffer, buf.byteOffset + o, 8).getBigUint64(0, true));
}

export function readLeU32(buf, o) {
    return new DataView(buf.buffer, buf.byteOffset + o, 4).getUint32(0, true);
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
