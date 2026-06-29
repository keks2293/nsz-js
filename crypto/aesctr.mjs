// AES-CTR - matches Python PyCryptodome: Counter.new(64, prefix=nonce[0:8], initial_value=blockIdx)
// Counter block = nonce[0:8] + BE64(blockIdx)
// Input nonce may be any length (e.g. ncz.js passes full 16-byte initial block), first 8 bytes used
// Node.js: uses crypto.createCipheriv (OpenSSL, hardware-accelerated)
// Browser: uses Web Crypto API (hardware-accelerated)

import { AesEcb, aesCtr } from './aes128.js';

const BLOCK_SIZE = 0x10;

function _checkAes128Key(key) {
    if (key.length !== BLOCK_SIZE) throw new Error(`Key must be ${BLOCK_SIZE} bytes`);
}

const isNode = typeof process !== 'undefined' && process.versions?.node;

let useNodeCrypto = false;
let useWebCrypto = false;
let nodeCrypto = null;

if (isNode) {
    const cryptoModule = await import('crypto');
    nodeCrypto = cryptoModule.default || cryptoModule;
    useNodeCrypto = true;
} else if (typeof crypto !== 'undefined' && crypto.subtle && typeof crypto.subtle.encrypt === 'function') {
    useWebCrypto = true;
}

class AesCtr {
    constructor(key, nonce, offset = 0) {
        _checkAes128Key(key);
        this.key = key;
        this.nonce = nonce;
        if (useNodeCrypto) {
            this._cipher = null;
        } else if (useWebCrypto) {
            this._cryptoKey = null;
        } else {
            this._fallbackAes = new AesEcb(key);
        }
        this.seek(offset);
    }

    seek(offset) {
        if (!this._counter) this._counter = new Uint8Array(BLOCK_SIZE);
        const counter = this._counter;
        counter.set(this.nonce.subarray(0, 8));
        let tmp = offset >> 4;
        for (let j = BLOCK_SIZE - 1; j >= 8; j--) {
            counter[j] = tmp & 0xff;
            tmp >>>= 8;
        }
        if (useNodeCrypto) {
            this._cipher = nodeCrypto.createCipheriv('aes-128-ctr', this.key, counter);
        }
    }

    _nodeTransform(data) {
        return this._cipher.update(data);
    }

    _pureJSTransform(data) {
        return aesCtr(this._fallbackAes, this._counter, data);
    }

    async encrypt(data) {
        if (useNodeCrypto) {
            return this._nodeTransform(data);
        }
        if (useWebCrypto) {
            if (!this._cryptoKey) {
                this._cryptoKey = await crypto.subtle.importKey(
                    'raw', this.key,
                    { name: 'AES-CTR' },
                    false, ['encrypt']
                );
            }
            const blocks = (data.length + 15) >> 4;
            const result = await crypto.subtle.encrypt(
                { name: 'AES-CTR', counter: this._counter, length: 64 },
                this._cryptoKey,
                data
            );
            for (let b = 0; b < blocks; b++) {
                for (let j = BLOCK_SIZE - 1; j >= 8; j--) {
                    this._counter[j]++;
                    if (this._counter[j]) break;
                }
            }
            return new Uint8Array(result);
        }
        return this._pureJSTransform(data);
    }

    async decrypt(data) {
        return await this.encrypt(data);
    }
}

export { AesCtr };
