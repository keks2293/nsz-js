// AES-CTR - matches Python PyCryptodome: Counter.new(64, prefix=nonce[0:8], initial_value=blockIdx)
// Counter block = nonce[0:8] + BE64(blockIdx)
// Node.js: uses crypto.createCipheriv (OpenSSL, hardware-accelerated)
// Browser: uses Web Crypto API (hardware-accelerated) when available
// Fallback: aes-js (pure JS)
// https://github.com/ricmoo/aes-js

const isNode = typeof process !== 'undefined' && process.versions?.node;

let useNodeCrypto = false;
let nodeCrypto = null;
let useWebCrypto = false;

if (isNode) {
    try {
        nodeCrypto = await import('crypto');
        useNodeCrypto = true;
    } catch {}
} else {
    useWebCrypto = typeof crypto !== 'undefined' && crypto.subtle && typeof crypto.subtle.encrypt === 'function';
}

// Load aes-js for fallback and BKTR
let aesjs;
if (typeof window !== 'undefined' && window.aesjs) {
    aesjs = window.aesjs;
} else {
    const m = await import('aes-js');
    aesjs = m.default || m;
}

class AESCTR {
    constructor(key, nonce) {
        this.key = key.slice(0, 16);
        this.nonce = nonce.slice(0, 8);
        if (useNodeCrypto) {
            this._cipher = null;
            this._nextBlockIdx = -1;
        } else if (useWebCrypto) {
            this._cryptoKey = null;
        } else {
            this.aes = new aesjs.AES(this.key);
        }
    }

    seek(offset) {
        this.blockIndex = Math.floor(offset / 16);
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
        if (useWebCrypto) {
            return await this._webTransform(data, offset);
        }
        if (offset !== null) this.seek(offset);
        return this._xorKeystream(data);
    }

    _nodeTransform(data, offset) {
        let blockIdx;
        if (offset !== null) {
            blockIdx = Math.floor(offset / 16);
        } else {
            blockIdx = this.blockIndex;
        }
        if (!this._cipher || blockIdx !== this._nextBlockIdx) {
            const iv = new Uint8Array(16);
            for (let j = 0; j < 8; j++) iv[j] = this.nonce[j];
            let tmp = blockIdx;
            for (let j = 15; j >= 8; j--) {
                iv[j] = tmp & 0xff;
                tmp >>>= 8;
            }
            const c = nodeCrypto.default || nodeCrypto;
            this._cipher = c.createCipheriv('aes-128-ctr', this.key, iv);
        }
        this._nextBlockIdx = blockIdx + Math.ceil(data.length / 16);
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
            blockIdx = Math.floor(offset / 16);
        } else {
            blockIdx = this.blockIndex;
        }
        const counter = new Uint8Array(16);
        for (let j = 0; j < 8; j++) counter[j] = this.nonce[j];
        let tmp = blockIdx;
        for (let j = 15; j >= 8; j--) {
            counter[j] = tmp & 0xff;
            tmp >>>= 8;
        }
        const result = await crypto.subtle.encrypt(
            { name: 'AES-CTR', counter, length: 64 },
            this._cryptoKey,
            data
        );
        this.blockIndex = blockIdx + Math.ceil(data.length / 16);
        return new Uint8Array(result);
    }

    _xorKeystream(data) {
        const len = data.length;
        const arr = data instanceof Uint8Array ? data : new Uint8Array(data);
        const output = new Uint8Array(len);

        for (let i =0; i < len; i += 16) {
            const blockIdx = this.blockIndex + Math.floor(i / 16);
            
            const ctr = new Uint8Array(16);
            for (let j = 0; j < 8; j++) ctr[j] = this.nonce[j];
            let tmp = blockIdx;
            for (let j = 15; j >= 8; j--) {
                ctr[j] = tmp & 0xff;
                tmp >>= 8;
            }
            
            const keystreamBlock = this.aes.encrypt(ctr);
            
            const blockLen = Math.min(16, len - i);
            for (let j = 0; j < blockLen; j++) {
                output[i + j] = arr[i + j] ^ keystreamBlock[j];
            }
        }
        
        this.blockIndex += Math.floor(len / 16);
        return output;
    }
}

class AESCTR_BKTR {
    constructor(key, nonce, ctrVal = 0) {
        this.key = key.slice(0, 16);
        this.nonce = nonce.slice(0, 16);
        this.ctrVal = ctrVal;
        this.aes = new aesjs.AES(this.key);
    }

    seek(offset) {
        this.blockIndex = Math.floor(offset / 16);
    }

    encrypt(data, offset = null) {
        if (offset !== null) this.seek(offset);
        return this._xorKeystream(data);
    }

    decrypt(data, offset = null) {
        if (offset !== null) this.seek(offset);
        return this._xorKeystream(data);
    }

    _xorKeystream(data) {
        const len = data.length;
        const arr = data instanceof Uint8Array ? data : new Uint8Array(data);
        const output = new Uint8Array(len);

        for (let i = 0; i < len; i += 16) {
            const blockIdx = this.blockIndex + Math.floor(i / 16);

            const ctr = new Uint8Array(16);
            for (let j = 0; j < 16; j++) ctr[j] = this.nonce[j];
            let tmp = blockIdx;
            for (let j = 15; j >= 8; j--) {
                ctr[j] ^= (tmp & 0xff);
                tmp >>= 8;
            }

            const keystreamBlock = this.aes.encrypt(ctr);

            const blockLen = Math.min(16, len - i);
            for (let j = 0; j < blockLen; j++) {
                output[i + j] = arr[i + j] ^ keystreamBlock[j];
            }
        }

        this.blockIndex += Math.floor(len / 16);
        return output;
    }
}

export { AESCTR, AESCTR_BKTR };
