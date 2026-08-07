const BLOCK_SIZE = 0x10;

const rconTable = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
    0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
    0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
    0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
];

const sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

const invSbox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

const T0 = new Uint32Array(256);
const T1 = new Uint32Array(256);
const T2 = new Uint32Array(256);
const T3 = new Uint32Array(256);
const T0inv = new Uint32Array(256);
const T1inv = new Uint32Array(256);
const T2inv = new Uint32Array(256);
const T3inv = new Uint32Array(256);

{
    const xtime = (x) => ((x << 1) ^ (((x >> 7) & 1) * 0x1b)) & 0xff;

    for (let i = 0; i < 256; i++) {
        const s = sbox[i];
        const s2 = xtime(s);
        const s3 = s2 ^ s;
        T0[i] = (s2 << 24) | (s << 16) | (s << 8) | s3;

        const is = invSbox[i];
        T0inv[i] = (_gmul(0x0e, is) << 24) | (_gmul(0x09, is) << 16) | (_gmul(0x0d, is) << 8) | _gmul(0x0b, is);
        T1inv[i] = (_gmul(0x0b, is) << 24) | (_gmul(0x0e, is) << 16) | (_gmul(0x09, is) << 8) | _gmul(0x0d, is);
        T2inv[i] = (_gmul(0x0d, is) << 24) | (_gmul(0x0b, is) << 16) | (_gmul(0x0e, is) << 8) | _gmul(0x09, is);
        T3inv[i] = (_gmul(0x09, is) << 24) | (_gmul(0x0d, is) << 16) | (_gmul(0x0b, is) << 8) | _gmul(0x0e, is);
    }

    for (let i = 0; i < 256; i++) {
        T1[i] = ((T0[i] << 24) | (T0[i] >>> 8)) >>> 0;
        T2[i] = ((T0[i] << 16) | (T0[i] >>> 16)) >>> 0;
        T3[i] = ((T0[i] << 8) | (T0[i] >>> 24)) >>> 0;
    }
}

function _gmul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        const hi = a & 0x80;
        a = (a << 1) & 0xff;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

function _invMixColumnsWord(w) {
    const a0 = (w >>> 24) & 0xff, a1 = (w >>> 16) & 0xff, a2 = (w >>> 8) & 0xff, a3 = w & 0xff;
    return ((_gmul(0x0e,a0)^_gmul(0x0b,a1)^_gmul(0x0d,a2)^_gmul(0x09,a3)) << 24 |
        (_gmul(0x09,a0)^_gmul(0x0e,a1)^_gmul(0x0b,a2)^_gmul(0x0d,a3)) << 16 |
        (_gmul(0x0d,a0)^_gmul(0x09,a1)^_gmul(0x0e,a2)^_gmul(0x0b,a3)) << 8 |
        (_gmul(0x0b,a0)^_gmul(0x0d,a1)^_gmul(0x09,a2)^_gmul(0x0e,a3))) >>> 0;
}

function _checkAes128Key(key) {
    if (key.length !== BLOCK_SIZE) throw new Error(`Key must be ${BLOCK_SIZE} bytes`);
}

function _padPartialBlock(block) {
    const padLen = BLOCK_SIZE - block.length;
    const padded = new Uint8Array(BLOCK_SIZE);
    padded.set(block);
    padded.fill(padLen, block.length);
    return padded;
}

class AesEcb {
    constructor(key) {
        _checkAes128Key(key);
        this.keys = this.keySchedule(key);
        this.decKeys = this.keys.slice();
        for (let r = 1; r < 10; r++) {
            for (let c = 0; c < 4; c++) {
                this.decKeys[r * 4 + c] = _invMixColumnsWord(this.keys[r * 4 + c]);
            }
        }
    }

    keySchedule(key) {
        const constNk = 4;
        const constNr = 10;
        const expanded = new Array(4 * (constNr + 1));

        for (let i = 0; i < constNk; i++) {
            expanded[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3];
        }

        for (let i = constNk; i < 4 * (constNr + 1); i++) {
            let temp = expanded[i - 1];
            if (i % constNk === 0) {
                temp = this.subWord(this.rotateOp(temp)) ^ (rconTable[Math.floor(i / constNk) - 1] << 24);
            }
            expanded[i] = expanded[i - constNk] ^ temp;
        }

        return expanded;
    }

    rotateOp(word) {
        return ((word & 0xffffff) << 8) | ((word & 0xff000000) >>> 24);
    }

    subWord(word) {
        return (sbox[(word >>> 0) & 0xff] << 0) |
               (sbox[(word >>> 8) & 0xff] << 8) |
               (sbox[(word >>> 16) & 0xff] << 16) |
               (sbox[(word >>> 24) & 0xff] << 24);
    }

    encrypt(data) {
        if (data.length % BLOCK_SIZE) {
            data = _padPartialBlock(data);
        }
        const out = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i += BLOCK_SIZE) {
            this.encryptBlock(data.subarray(i, i + BLOCK_SIZE), out.subarray(i, i + BLOCK_SIZE));
        }
        return out;
    }

    decrypt(data) {
        if (data.length % BLOCK_SIZE) throw new Error('Data length must be a multiple of 16');
        const out = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i += BLOCK_SIZE) {
            this.decryptBlock(data.subarray(i, i + BLOCK_SIZE), out.subarray(i, i + BLOCK_SIZE));
        }
        return out;
    }

    encryptBlock(block, out) {
        const k = this.keys;
        let s0 = ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) ^ k[0];
        let s1 = ((block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]) ^ k[1];
        let s2 = ((block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11]) ^ k[2];
        let s3 = ((block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15]) ^ k[3];

        for (let r = 1; r < 10; r++) {
            const rk = r << 2;
            const t0 = T0[s0 >>> 24] ^ T1[(s1 >>> 16) & 0xff] ^ T2[(s2 >>> 8) & 0xff] ^ T3[s3 & 0xff] ^ k[rk];
            const t1 = T0[s1 >>> 24] ^ T1[(s2 >>> 16) & 0xff] ^ T2[(s3 >>> 8) & 0xff] ^ T3[s0 & 0xff] ^ k[rk | 1];
            const t2 = T0[s2 >>> 24] ^ T1[(s3 >>> 16) & 0xff] ^ T2[(s0 >>> 8) & 0xff] ^ T3[s1 & 0xff] ^ k[rk | 2];
            const t3 = T0[s3 >>> 24] ^ T1[(s0 >>> 16) & 0xff] ^ T2[(s1 >>> 8) & 0xff] ^ T3[s2 & 0xff] ^ k[rk | 3];
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        }

        if (!out) out = new Uint8Array(BLOCK_SIZE);
        out[0] = (sbox[s0 >>> 24] ^ (k[40] >>> 24)) & 0xff;
        out[1] = (sbox[(s1 >>> 16) & 0xff] ^ (k[40] >>> 16)) & 0xff;
        out[2] = (sbox[(s2 >>> 8) & 0xff] ^ (k[40] >>> 8)) & 0xff;
        out[3] = (sbox[s3 & 0xff] ^ k[40]) & 0xff;
        out[4] = (sbox[s1 >>> 24] ^ (k[41] >>> 24)) & 0xff;
        out[5] = (sbox[(s2 >>> 16) & 0xff] ^ (k[41] >>> 16)) & 0xff;
        out[6] = (sbox[(s3 >>> 8) & 0xff] ^ (k[41] >>> 8)) & 0xff;
        out[7] = (sbox[s0 & 0xff] ^ k[41]) & 0xff;
        out[8] = (sbox[s2 >>> 24] ^ (k[42] >>> 24)) & 0xff;
        out[9] = (sbox[(s3 >>> 16) & 0xff] ^ (k[42] >>> 16)) & 0xff;
        out[10] = (sbox[(s0 >>> 8) & 0xff] ^ (k[42] >>> 8)) & 0xff;
        out[11] = (sbox[s1 & 0xff] ^ k[42]) & 0xff;
        out[12] = (sbox[s3 >>> 24] ^ (k[43] >>> 24)) & 0xff;
        out[13] = (sbox[(s0 >>> 16) & 0xff] ^ (k[43] >>> 16)) & 0xff;
        out[14] = (sbox[(s1 >>> 8) & 0xff] ^ (k[43] >>> 8)) & 0xff;
        out[15] = (sbox[s2 & 0xff] ^ k[43]) & 0xff;
        return out;
    }

    decryptBlock(block, out) {
        const k = this.decKeys;
        let s0 = ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) ^ k[40];
        let s1 = ((block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]) ^ k[41];
        let s2 = ((block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11]) ^ k[42];
        let s3 = ((block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15]) ^ k[43];

        for (let r = 9; r > 0; r--) {
            const rk = r << 2;
            const t0 = T0inv[s0 >>> 24] ^ T1inv[(s3 >>> 16) & 0xff] ^ T2inv[(s2 >>> 8) & 0xff] ^ T3inv[s1 & 0xff] ^ k[rk];
            const t1 = T0inv[s1 >>> 24] ^ T1inv[(s0 >>> 16) & 0xff] ^ T2inv[(s3 >>> 8) & 0xff] ^ T3inv[s2 & 0xff] ^ k[rk | 1];
            const t2 = T0inv[s2 >>> 24] ^ T1inv[(s1 >>> 16) & 0xff] ^ T2inv[(s0 >>> 8) & 0xff] ^ T3inv[s3 & 0xff] ^ k[rk | 2];
            const t3 = T0inv[s3 >>> 24] ^ T1inv[(s2 >>> 16) & 0xff] ^ T2inv[(s1 >>> 8) & 0xff] ^ T3inv[s0 & 0xff] ^ k[rk | 3];
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        }

        if (!out) out = new Uint8Array(BLOCK_SIZE);
        out[0] = (invSbox[s0 >>> 24] ^ (k[0] >>> 24)) & 0xff;
        out[1] = (invSbox[(s3 >>> 16) & 0xff] ^ (k[0] >>> 16)) & 0xff;
        out[2] = (invSbox[(s2 >>> 8) & 0xff] ^ (k[0] >>> 8)) & 0xff;
        out[3] = (invSbox[s1 & 0xff] ^ k[0]) & 0xff;
        out[4] = (invSbox[s1 >>> 24] ^ (k[1] >>> 24)) & 0xff;
        out[5] = (invSbox[(s0 >>> 16) & 0xff] ^ (k[1] >>> 16)) & 0xff;
        out[6] = (invSbox[(s3 >>> 8) & 0xff] ^ (k[1] >>> 8)) & 0xff;
        out[7] = (invSbox[s2 & 0xff] ^ k[1]) & 0xff;
        out[8] = (invSbox[s2 >>> 24] ^ (k[2] >>> 24)) & 0xff;
        out[9] = (invSbox[(s1 >>> 16) & 0xff] ^ (k[2] >>> 16)) & 0xff;
        out[10] = (invSbox[(s0 >>> 8) & 0xff] ^ (k[2] >>> 8)) & 0xff;
        out[11] = (invSbox[s3 & 0xff] ^ k[2]) & 0xff;
        out[12] = (invSbox[s3 >>> 24] ^ (k[3] >>> 24)) & 0xff;
        out[13] = (invSbox[(s2 >>> 16) & 0xff] ^ (k[3] >>> 16)) & 0xff;
        out[14] = (invSbox[(s1 >>> 8) & 0xff] ^ (k[3] >>> 8)) & 0xff;
        out[15] = (invSbox[s0 & 0xff] ^ k[3]) & 0xff;
        return out;
    }
}

function AesCtrJS(aes, counter, data) {
    const out = new Uint8Array(data.length);
    for (let off = 0; off < data.length; off += BLOCK_SIZE) {
        aes.encryptBlock(counter, out.subarray(off, off + BLOCK_SIZE));
        for (let j = 0; j < BLOCK_SIZE && off + j < data.length; j++) {
            out[off + j] = data[off + j] ^ out[off + j];
        }
        for (let j = BLOCK_SIZE - 1; j >= 8; j--) {
            counter[j]++;
            if (counter[j]) break;
        }
    }
    return out;
}

function getTweakBytes(sector) {
    const buf = new Uint8Array(16);
    for (let i = 15; i >= 0; i--) {
        buf[i] = sector & 0xFF;
        sector = Math.floor(sector / 256);
    }
    return buf;
}

// In-place GF(2^128) multiply storing into `tweak` (the alpha-chain per block).
function gf128MulIn(tweak) {
    let carry = 0;
    for (let i = 0; i < 16; i++) {
        const newCarry = (tweak[i] >>> 7) & 1;
        const shifted = ((tweak[i] << 1) | carry) & 0xff;
        carry = newCarry;
        tweak[i] = shifted;
    }
    if (carry) tweak[0] ^= 0x87;
    return tweak;
}

const SECTOR_SIZE = 0x200;

class AesXts {
    constructor(key) {
        if (key.length !== 32) throw new Error('XTS key must be 32 bytes');
        this.k1 = key.subarray(0, 16);
        this.k2 = key.subarray(16, 32);
        const aesEnc = new AesEcb(this.k2);
        const aesDec = new AesEcb(this.k1);
        this._encTweak = (tweakBytes) => aesEnc.encryptBlock(tweakBytes);
        this._decData = (block) => aesDec.decryptBlock(block);
    }

    decrypt(data, startSector = 0) {
        const result = new Uint8Array(data.length);
        const xored = new Uint8Array(BLOCK_SIZE);
        let sector = startSector;

        for (let offset = 0; offset < data.length; offset += SECTOR_SIZE) {
            const chunkSize = Math.min(SECTOR_SIZE, data.length - offset);
            const chunk = data.subarray(offset, offset + chunkSize);
            const tweakBytes = getTweakBytes(sector);
            const tweak = this._encTweak(tweakBytes);

            for (let i = 0; i + BLOCK_SIZE <= chunk.length; i += BLOCK_SIZE) {
                const block = chunk.subarray(i, i + BLOCK_SIZE);
                for (let j = 0; j < BLOCK_SIZE; j++) xored[j] = block[j] ^ tweak[j];
                const decrypted = this._decData(xored);
                for (let j = 0; j < BLOCK_SIZE; j++) result[offset + i + j] = decrypted[j] ^ tweak[j];
                gf128MulIn(tweak);
            }
            sector++;
        }
        return result;
    }
}

export { BLOCK_SIZE, AesEcb, AesCtrJS, AesXts };
