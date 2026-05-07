// AES-CTR - matches Python PyCryptodome: Counter.new(64, prefix=nonce[0:8], initial_value=blockIdx)
// Counter block = nonce[0:8] + BE64(blockIdx)
// Uses aes-js (pure JS) for AES-ECB - works in both Node.js and browsers.
// https://github.com/ricmoo/aes-js

// Browser: aes-js loads via <script src="static/aes-js.js"> and sets window.aesjs
// Node.js: import from 'aes-js' npm package
// Use top-level await to dynamically import in Node.js

let aesjs;
if (typeof window !== 'undefined' && window.aesjs) {
    // Browser: use global set by script tag
    aesjs = window.aesjs;
} else {
    // Node.js: dynamically import the package
    const aesjsModule = await import('aes-js');
    aesjs = aesjsModule.default || aesjsModule;
}

const AES = aesjs.AES;
const Counter = aesjs.Counter;

class AESCTR {
    constructor(key, nonce) {
        this.key = key.slice(0, 16);
        this.nonce = nonce.slice(0, 16);
        // Create AES-128-ECB instance
        this.aes = new AES(this.key);
    }

    seek(offset) {
        this.blockIndex = Math.floor(offset / 16);
    }

    encrypt(data, offset = null) {
        if (offset !== null) {
            this.seek(offset);
        }
        return this._xorKeystream(data);
    }

    decrypt(data, offset = null) {
        if (offset !== null) {
            this.seek(offset);
        }
        return this._xorKeystream(data);
    }

    _xorKeystream(data) {
        const len = data.length;
        const arr = data instanceof Uint8Array ? data : new Uint8Array(data);
        const output = new Uint8Array(len);

        for (let i =0; i < len; i += 16) {
            const blockIdx = this.blockIndex + Math.floor(i / 16);
            
            // Build counter block: nonce[0:8] + BE64(blockIdx)
            // Python: Counter.new(64, prefix=nonce[0:8], initial_value=blockIdx)
            const ctr = new Uint8Array(16);
            // First 8 bytes: nonce[0:8]
            for (let j = 0; j < 8; j++) {
                ctr[j] = this.nonce[j];
            }
            // Last 8 bytes: blockIdx as BIG-endian uint64
            let tmp = blockIdx;
            for (let j = 15; j >= 8; j--) {
                ctr[j] = tmp & 0xff;
                tmp >>= 8;
            }
            
            // Encrypt counter with AES-ECB
            const keystreamBlock = this.aes.encrypt(ctr);
            
            // XOR data with keystream block
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
        this.aes = new AES(this.key);
    }

    seek(offset) {
        this.blockIndex = Math.floor(offset / 16);
    }

    encrypt(data, offset = null) {
        if (offset !== null) {
            this.seek(offset);
        }
        return this._xorKeystream(data);
    }

    decrypt(data, offset = null) {
        if (offset !== null) {
            this.seek(offset);
        }
        return this._xorKeystream(data);
    }

    _xorKeystream(data) {
        const len = data.length;
        const arr = data instanceof Uint8Array ? data : new Uint8Array(data);
        const output = new Uint8Array(len);

        for (let i = 0; i < len; i += 16) {
            const blockIdx = this.blockIndex + Math.floor(i / 16);

            // BKTR uses full 16-byte counter
            const ctr = new Uint8Array(16);
            for (let j = 0; j < 16; j++) {
                ctr[j] = this.nonce[j];
            }
            // Add blockIdx to last 8 bytes
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
