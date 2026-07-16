import { BLOCK_SIZE, AesEcb, AesCtrJS, AesXts } from './aes128.js';

const isNode = typeof process !== 'undefined' && process.versions?.node;

let nodeCrypto = null;

if (isNode) {
    const { default: crypto } = await import('crypto');
    nodeCrypto = crypto;
}

const hasWebCrypto = !isNode && typeof crypto !== 'undefined' && crypto.subtle?.encrypt;

class AesCtr {
    constructor(key, nonce, offset = 0) {
        if (key.length !== BLOCK_SIZE) throw new Error(`Key must be ${BLOCK_SIZE} bytes`);
        this.key = key;
        this.nonce = nonce;
        this._counter = null;
        this._cryptoKey = null;
        if (nodeCrypto) {
            // cipher created in seek()
        } else if (hasWebCrypto) {
            // cryptoKey lazy in encrypt()
        } else {
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
        if (nodeCrypto) {
            this._cipher = nodeCrypto.createCipheriv('aes-128-ctr', this.key, counter);
        }
    }

    async encrypt(data) {
        if (nodeCrypto) {
            return this._cipher.update(data);
        }
        if (hasWebCrypto) {
            if (!this._cryptoKey) {
                this._cryptoKey = await crypto.subtle.importKey(
                    'raw', this.key, { name: 'AES-CTR' }, false, ['encrypt']
                );
            }
            const blocks = (data.length + 15) >> 4;
            const result = await crypto.subtle.encrypt(
                { name: 'AES-CTR', counter: this._counter, length: 64 },
                this._cryptoKey, data
            );
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
        xts._encTweak = (tweakBytes) => new Uint8Array(encCipher.update(tweakBytes));
        xts._decData = (block) => new Uint8Array(decCipher.update(block));
    }
    return xts;
}

export { AesCtr, createAesXts as AesXts };
