// AES-CTR - matches Python PyCryptodome: Counter.new(64, prefix=nonce[0:8], initial_value=blockIdx)
// Counter block = nonce[0:8] + BE64(blockIdx)
// Node.js: uses crypto.createCipheriv (OpenSSL, hardware-accelerated)
// Browser: uses Web Crypto API (hardware-accelerated)

const isNode = typeof process !== 'undefined' && process.versions?.node;

let useNodeCrypto = false;
let nodeCrypto = null;

if (isNode) {
    const cryptoModule = await import('crypto');
    nodeCrypto = cryptoModule.default || cryptoModule;
    useNodeCrypto = true;
} else if (typeof crypto === 'undefined' || !crypto.subtle || typeof crypto.subtle.encrypt !== 'function') {
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
            this._nextBlockIdx = -1;
        } else {
            this._cryptoKey = null;
        }
        this.seek(offset);
    }

    seek(offset) {
        this.blockIndex = Math.floor(offset / BLOCK_SIZE);
    }

    async encrypt(data, offset = null) {
        return await this._transform(data, offset);
    }

    async decrypt(data, offset = null) {
        return await this._transform(data, offset);
    }

    async _transform(data, offset) {
        if (useNodeCrypto) {
            return this._nodeTransform(data, offset);
        }
        return await this._webTransform(data, offset);
    }

    _nodeTransform(data, offset) {
        let blockIdx;
        if (offset !== null) {
            blockIdx = Math.floor(offset / BLOCK_SIZE);
        } else {
            blockIdx = this.blockIndex;
        }
        if (!this._cipher || blockIdx !== this._nextBlockIdx) {
            const iv = new Uint8Array(BLOCK_SIZE);
            for (let j = 0; j < 8; j++) iv[j] = this.nonce[j];
            let tmp = blockIdx;
            for (let j = BLOCK_SIZE - 1; j >= 8; j--) {
                iv[j] = tmp & 0xff;
                tmp >>>= 8;
            }
            this._cipher = nodeCrypto.createCipheriv('aes-128-ctr', this.key, iv);
        }
        this._nextBlockIdx = blockIdx + Math.ceil(data.length / BLOCK_SIZE);
        this.blockIndex = this._nextBlockIdx;
        return new Uint8Array(this._cipher.update(data));
    }

    async _webTransform(data, offset) {
        if (!this._cryptoKey) {
            this._cryptoKey = await crypto.subtle.importKey(
                'raw', this.key,
                { name: 'AES-CTR' },
                false, ['encrypt']
            );
        }
        let blockIdx;
        if (offset !== null) {
            blockIdx = Math.floor(offset / BLOCK_SIZE);
        } else {
            blockIdx = this.blockIndex;
        }
        const counter = new Uint8Array(BLOCK_SIZE);
            for (let j = 0; j < 8; j++) counter[j] = this.nonce[j];
            let tmp = blockIdx;
            for (let j = BLOCK_SIZE - 1; j >= 8; j--) {
            counter[j] = tmp & 0xff;
            tmp >>>= 8;
        }
        const result = await crypto.subtle.encrypt(
            { name: 'AES-CTR', counter, length: 64 },
            this._cryptoKey,
            data
        );
        this.blockIndex = blockIdx + Math.ceil(data.length / BLOCK_SIZE);
        return new Uint8Array(result);
    }
}

export { AESCTR };
