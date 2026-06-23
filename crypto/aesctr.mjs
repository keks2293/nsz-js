// AES-CTR - matches Python PyCryptodome: Counter.new(64, prefix=nonce[0:8], initial_value=blockIdx)
// Counter block = nonce[0:8] + BE64(blockIdx)
// Node.js: uses crypto.createCipheriv (OpenSSL, hardware-accelerated)
// Browser: uses Web Crypto API (hardware-accelerated)

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
} else {
    throw new Error('Web Crypto API not available. Use a modern browser with HTTPS or localhost.');
}

const BLOCK_SIZE = 0x10;

function _checkAes128Key(key) {
    if (key.length !== BLOCK_SIZE) throw new Error(`Key must be ${BLOCK_SIZE} bytes`);
}

class AESCTR {
    constructor(key, nonce, offset = 0) {
        _checkAes128Key(key);
        this.key = key;
        this.nonce = nonce;
        if (useNodeCrypto) {
            this._cipher = null;
        } else {
            this._cryptoKey = null;
        }
        this.seek(offset);
    }

    seek(offset) {
        this.blockIndex = Math.floor(offset / BLOCK_SIZE);
        if (useNodeCrypto) {
            const iv = new Uint8Array(BLOCK_SIZE);
            for (let j = 0; j < 8; j++) iv[j] = this.nonce[j];
            let tmp = this.blockIndex;
            for (let j = BLOCK_SIZE - 1; j >= 8; j--) {
                iv[j] = tmp & 0xff;
                tmp >>>= 8;
            }
            this._cipher = nodeCrypto.createCipheriv('aes-128-ctr', this.key, iv);
        }
    }

    async encrypt(data) {
        return await this._transform(data);
    }

    async decrypt(data) {
        return await this._transform(data);
    }

    async _transform(data) {
        if (useNodeCrypto) {
            return this._nodeTransform(data);
        }
        return await this._webTransform(data);
    }

    _nodeTransform(data) {
        this.blockIndex += Math.ceil(data.length / BLOCK_SIZE);
        return new Uint8Array(this._cipher.update(data));
    }

    async _webTransform(data) {
        if (!this._cryptoKey) {
            this._cryptoKey = await crypto.subtle.importKey(
                'raw', this.key,
                { name: 'AES-CTR' },
                false, ['encrypt']
            );
        }
        const counter = new Uint8Array(BLOCK_SIZE);
        for (let j = 0; j < 8; j++) counter[j] = this.nonce[j];
        let tmp = this.blockIndex;
        for (let j = BLOCK_SIZE - 1; j >= 8; j--) {
            counter[j] = tmp & 0xff;
            tmp >>>= 8;
        }
        const result = await crypto.subtle.encrypt(
            { name: 'AES-CTR', counter, length: 64 },
            this._cryptoKey,
            data
        );
        this.blockIndex += Math.ceil(data.length / BLOCK_SIZE);
        return new Uint8Array(result);
    }
}

export { AESCTR };
