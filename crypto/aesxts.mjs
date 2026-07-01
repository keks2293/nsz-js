// AES-XTS-128 implementation
// Key: 32 bytes (k1 = key[0:16], k2 = key[16:32])
// Sector size: 512 bytes (0x200)
// Tweak: sector number (little-endian integer -> big-endian bytes -> AES-ECB encrypt with k2)
// Used for NCA header decryption in NSZ/NSP files

import { AesEcb } from './aes128.js';

const SECTOR_SIZE = 0x200;
const BLOCK_SIZE = 0x10;

const isNode = typeof process !== 'undefined' && process.versions?.node;

let nodeCrypto = null;
if (isNode) {
    const cryptoModule = await import('crypto');
    nodeCrypto = cryptoModule.default || cryptoModule;
}

function xor(a, b) {
    const r = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) r[i] = a[i] ^ b[i];
    return r;
}

function getTweakBytes(sector) {
    let tweak = 0;
    for (let i = 0; i < 16; i++) {
        tweak |= (sector & 0xFF) << (i * 8);
        sector = Math.floor(sector / 256);
    }
    const hex = tweak.toString(16).padStart(32, '0');
    const buf = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        buf[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return buf;
}

function gf128Mul(tweak) {
    const rev = new Uint8Array(tweak).reverse();
    let t = 0n;
    for (let i = 0; i < 16; i++) {
        t = (t << 8n) | BigInt(rev[i]);
    }
    t <<= 1n;
    if (t & (1n << 128n)) {
        t ^= (1n << 128n) | 0x87n;
    }
    const hex = t.toString(16).padStart(32, '0');
    const result = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        result[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return result.reverse();
}

function aesEcbEncryptNode(key, data) {
    const c = nodeCrypto.createCipheriv('aes-128-ecb', key, null);
    c.setAutoPadding(false);
    return new Uint8Array(c.update(data));
}

function aesEcbDecryptNode(key, data) {
    const d = nodeCrypto.createDecipheriv('aes-128-ecb', key, null);
    d.setAutoPadding(false);
    return new Uint8Array(d.update(data));
}

class AesXts {
    constructor(key) {
        if (key.length !== 32) throw new Error('XTS key must be 32 bytes');
        this.k1 = key.subarray(0, 16);
        this.k2 = key.subarray(16, 32);

        if (nodeCrypto) {
            this._encTweak = (tweakBytes) => aesEcbEncryptNode(this.k2, tweakBytes);
            this._decData = (block) => aesEcbDecryptNode(this.k1, block);
        } else {
            this._aesEnc = new AesEcb(this.k2);
            this._aesDec = new AesEcb(this.k1);
            this._encTweak = (tweakBytes) => this._aesEnc.encryptBlock(tweakBytes);
            this._decData = (block) => this._aesDec.decryptBlock(block);
        }
    }

    decrypt(data, startSector = 0) {
        const result = new Uint8Array(data.length);
        let sector = startSector;

        for (let offset = 0; offset < data.length; offset += SECTOR_SIZE) {
            const chunkSize = Math.min(SECTOR_SIZE, data.length - offset);
            const chunk = data.subarray(offset, offset + chunkSize);
            const tweakBytes = getTweakBytes(sector);
            let tweak = this._encTweak(tweakBytes);

            for (let i = 0; i < chunk.length; i += BLOCK_SIZE) {
                const blockEnd = Math.min(i + BLOCK_SIZE, chunk.length);
                if (blockEnd - i < BLOCK_SIZE) break;
                const block = chunk.subarray(i, i + BLOCK_SIZE);
                const xored = xor(block, tweak);
                const decrypted = this._decData(xored);
                const plaintext = xor(decrypted, tweak);
                result.set(plaintext, offset + i);
                tweak = gf128Mul(tweak);
            }
            sector++;
        }
        return result;
    }
}

export { AesXts };
