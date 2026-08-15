import { BLOCK_SIZE, AesEcb, AesCtrJS, AesXts } from './aes128.js';
import { isNode } from './platform.js';

let nodeCrypto = null;

if (isNode) {
    const { default: crypto } = await import('crypto');
    nodeCrypto = crypto;
}

const hasWebCrypto = !isNode && typeof crypto !== 'undefined' && crypto.subtle?.encrypt;

// Override the AES-CTR backend for benchmarking/debugging on Node.
// Values: 'auto' (default), 'node', 'webcrypto', 'js'.
export function aesBackend() {
    const v = isNode ? process.env.NSZ_AES_CTR_BACKEND : undefined;
    if (v === undefined || v === 'auto') return 'auto';
    if (v === 'node' || v === 'webcrypto' || v === 'js') return v;
    throw new Error(`NSZ_AES_CTR_BACKEND: unsupported value "${v}" (use auto|node|webcrypto|js)`);
}

function webcryptoSubtle() {
    return globalThis.crypto?.subtle;
}

class AesCtr {
    constructor(key, nonce, offset = 0, backend = 'auto') {
        if (key.length !== BLOCK_SIZE) throw new Error(`Key must be ${BLOCK_SIZE} bytes`);
        this.key = key;
        this.nonce = nonce;
        this._counter = null;
        this._cryptoKey = null;
        this._backend = backend === 'auto'
            ? (nodeCrypto ? 'node' : (hasWebCrypto ? 'webcrypto' : 'js'))
            : backend;
        if (this._backend === 'node') {
            // cipher created in seek()
        } else if (this._backend === 'js') {
            this._fallbackAes = new AesEcb(key);
        }
        this.seek(offset);
    }

    seek(offset) {
        const counter = this._counter || (this._counter = new Uint8Array(BLOCK_SIZE));
        counter.set(this.nonce.subarray(0, 8));
        let tmp = Math.floor(offset / 16);
        for (let j = BLOCK_SIZE - 1; j >= 8; j--) {
            counter[j] = tmp & 0xff;
            tmp = Math.floor(tmp / 256);
        }
        if (this._backend === 'node') {
            this._cipher = nodeCrypto.createCipheriv('aes-128-ctr', this.key, counter);
        }
        this._pos = offset;
    }

    async _ensureCryptoKey() {
        if (!this._cryptoKey) {
            const subtle = webcryptoSubtle();
            this._cryptoKey = await subtle.importKey(
                'raw', this.key, { name: 'AES-CTR' }, false, ['encrypt']
            );
        }
    }

    // 16-byte keystream block for the current counter (does not advance it)
    async _keystreamBlock() {
        if (this._backend === 'webcrypto') {
            await this._ensureCryptoKey();
            return new Uint8Array(await webcryptoSubtle().encrypt(
                { name: 'AES-CTR', counter: this._counter, length: 64 },
                this._cryptoKey, new Uint8Array(BLOCK_SIZE)
            ));
        }
        return this._fallbackAes.encryptBlock(this._counter);
    }

    // data starts at a 16-aligned absolute position; counter is seek()ed there
    async _encryptAligned(data) {
        if (this._backend === 'webcrypto') {
            await this._ensureCryptoKey();
            const result = await webcryptoSubtle().encrypt(
                { name: 'AES-CTR', counter: this._counter, length: 64 },
                this._cryptoKey, data
            );
            const blocks = (data.length + 15) >> 4;
            for (let b = 0; b < blocks; b++) {
                for (let j = BLOCK_SIZE - 1; j >= 8; j--) {
                    this._counter[j]++;
                    if (this._counter[j]) break;
                }
            }
            return new Uint8Array(result);
        }
        return AesCtrJS(this._fallbackAes, this._counter, data);
    }

    async encrypt(data) {
        if (this._backend === 'node') {
            const out = this._cipher.update(data);
            this._pos += data.length;
            return out;
        }
        // Stateless paths (webcrypto / pure-JS) generate keystream per whole block,
        // so a chunk that starts mid-block needs the tail of the previous block's
        // keystream first, then block-aligned continuation.
        let pos = this._pos;
        if (pos % BLOCK_SIZE === 0) {
            // aligned fast path: no head, return the cipher output directly (no extra copy)
            this.seek(pos);
            const res = await this._encryptAligned(data);
            this._pos = pos + data.length;
            return res;
        }
        const out = new Uint8Array(data.length);
        let src = 0;
        const blockOff = pos % BLOCK_SIZE;
        this.seek(pos);
        const ks = await this._keystreamBlock();
        const headLen = Math.min(BLOCK_SIZE - blockOff, data.length);
        for (let i = 0; i < headLen; i++) out[src + i] = data[src + i] ^ ks[blockOff + i];
        src += headLen;
        pos += headLen;
        if (src < data.length) {
            this.seek(pos);
            const res = await this._encryptAligned(data.subarray(src));
            out.set(res, src);
            pos += data.length - src;
        }
        this._pos = pos;
        return out;
    }

    async decrypt(data) {
        return await this.encrypt(data);
    }
}

function createAesXts(key) {
    const xts = new AesXts(key);
    if (nodeCrypto) {
        const encCipher = nodeCrypto.createCipheriv('aes-128-ecb', xts.k2, null);
        encCipher.setAutoPadding(false);
        const decCipher = nodeCrypto.createDecipheriv('aes-128-ecb', xts.k1, null);
        decCipher.setAutoPadding(false);
        const encDataCipher = nodeCrypto.createCipheriv('aes-128-ecb', xts.k1, null);
        encDataCipher.setAutoPadding(false);
        xts._encTweak = (tweakBytes) => new Uint8Array(encCipher.update(tweakBytes));
        xts._decData = (block) => new Uint8Array(decCipher.update(block));
        xts._encData = (block) => new Uint8Array(encDataCipher.update(block));
    }
    return xts;
}

export { AesCtr, createAesXts as AesXts };
