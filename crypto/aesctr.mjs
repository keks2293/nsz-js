// AES-CTR - matches Python PyCryptodome: Counter.new(64, prefix=nonce[0:8], initial_value=blockIdx)
// Counter block = nonce[0:8] + BE64(blockIdx)
// Node.js: uses crypto.createCipheriv (OpenSSL, hardware-accelerated)
// Browser: uses Web Crypto API (hardware-accelerated)

import { AesEcb, aesCtr } from './aes128.js';

const BLOCK_SIZE = 0x10;

function _checkAes128Key(key) {
    if (key.length !== BLOCK_SIZE) throw new Error(`Key must be ${BLOCK_SIZE} bytes`);
}

function buildCounter(nonce, blockIndex) {
    const counter = new Uint8Array(BLOCK_SIZE);
    for (let j = 0; j < 8; j++) counter[j] = nonce[j];
    let tmp = blockIndex;
    for (let j = BLOCK_SIZE - 1; j >= 8; j--) {
        counter[j] = tmp & 0xff;
        tmp >>>= 8;
    }
    return counter;
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
        this.blockIndex = Math.floor(offset / BLOCK_SIZE);
        if (useNodeCrypto) {
            this._cipher = nodeCrypto.createCipheriv('aes-128-ctr', this.key, buildCounter(this.nonce, this.blockIndex));
        }
    }

    encrypt(data) {
        if (this._fallbackAes) {
            return this._pureJSTransform(data);
        }
        if (useNodeCrypto) {
            return this._nodeTransform(data);
        }
        return this._webTransform(data);
    }

    _nodeTransform(data) {
        this.blockIndex += Math.ceil(data.length / BLOCK_SIZE);
        return new Uint8Array(this._cipher.update(data));
    }

    _pureJSTransform(data) {
        const counter = buildCounter(this.nonce, this.blockIndex);
        const result = aesCtr(this._fallbackAes, counter, data);
        this.blockIndex += Math.ceil(data.length / BLOCK_SIZE);
        return result;
    }

    async _webTransform(data) {
        if (!this._cryptoKey) {
            this._cryptoKey = await crypto.subtle.importKey(
                'raw', this.key,
                { name: 'AES-CTR' },
                false, ['encrypt']
            );
        }
        const counter = buildCounter(this.nonce, this.blockIndex);
        const result = await crypto.subtle.encrypt(
            { name: 'AES-CTR', counter, length: 64 },
            this._cryptoKey,
            data
        );
        this.blockIndex += Math.ceil(data.length / BLOCK_SIZE);
        return new Uint8Array(result);
    }

    decrypt(data) {
        return this.encrypt(data);
    }
}

export { AesCtr };
