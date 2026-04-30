// AES-CTR - matches Python PyCryptodome: Counter.new(64, prefix=nonce[0:8], initial_value=blockIndex)
// Counter block = nonce[0:8] + LE64(blockIndex)
// Uses aes-js library for correct AES-ECB encryption of counter blocks

// Get aes-js from global scope (it's loaded as a regular script, not an ES module)
const _aesjs = (typeof window !== 'undefined' && window.aesjs) ? window.aesjs : 
               (typeof globalThis !== 'undefined' && globalThis.aesjs) ? globalThis.aesjs : null;

if (!_aesjs) {
    console.error('aes-js library not found. Make sure crypto/aes-js.js is loaded before main.js');
}

class AESCTR {
    constructor(key, nonce) {
        this.key = key.slice(0, 16);
        this.nonce = nonce.slice(0, 16);
        // Create AES instance for ECB encryption of counter blocks
        this.aes = _aesjs ? new _aesjs.AES(this.key) : null;
        this._debugLogged = false;
    }

    seek(offset) {
        this.blockIndex = Math.floor(offset / 16);
    }

    encrypt(data, offset = 0) {
        this.seek(offset);
        return this._xorKeystream(data);
    }

    decrypt(data, offset = 0) {
        this.seek(offset);
        return this._xorKeystream(data);
    }

    _xorKeystream(data) {
        const len = data.length;
        const arr = data instanceof Uint8Array ? data : new Uint8Array(data);
        const output = new Uint8Array(len);

        if (!this._debugLogged) {
            this._debugLogged = true;
            console.log('AESCTR: key=', Array.from(this.key).map(b=>b.toString(16).padStart(2,'0')).join(''));
            console.log('AESCTR: nonce=', Array.from(this.nonce).map(b=>b.toString(16).padStart(2,'0')).join(''));
        }

        // If aes-js is not available, decryption is skipped (data returned as-is)
        if (!this.aes) {
            console.warn('AES-CTR: aes-js not available, skipping decryption');
            return data;
        }

        for (let i = 0; i < len; i += 16) {
            const blockIdx = this.blockIndex + Math.floor(i / 16);

            // Build counter block: nonce[0:8] + BE64(blockIdx)
            // PyCryptodome Counter.new(64, prefix=nonce[0:8], initial_value=blockIdx) uses big-endian for counter
            const ctr = new Uint8Array(16);
            // First 8 bytes: nonce[0:8]
            for (let j = 0; j < 8; j++) {
                ctr[j] = this.nonce[j];
            }
            // Last 8 bytes: blockIdx as BIG-endian uint64 (matching PyCryptodome default)
            let tmp = blockIdx;
            for (let j = 15; j >= 8; j--) {
                ctr[j] = tmp & 0xff;
                tmp >>= 8;
            }

            // Encrypt counter with AES-ECB to get keystream block
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
        // BKTR uses full 16-byte counter from section header
        this.nonce = nonce.slice(0, 16);
        // Create AES instance for ECB encryption of counter blocks
        this.aes = _aesjs ? new _aesjs.AES(this.key) : null;
        this.ctrVal = ctrVal;
    }

    seek(offset) {
        this.blockIndex = Math.floor(offset / 16);
    }

    encrypt(data, offset = 0) {
        this.seek(offset);
        return this._xorKeystream(data);
    }

    decrypt(data, offset = 0) {
        this.seek(offset);
        return this._xorKeystream(data);
    }

    _xorKeystream(data) {
        const len = data.length;
        const arr = data instanceof Uint8Array ? data : new Uint8Array(data);
        const output = new Uint8Array(len);

        if (!this.aes) {
            console.warn('AES-CTR_BKTR: aes-js not available, skipping decryption');
            return data;
        }

        for (let i = 0; i < len; i += 16) {
            const blockIdx = this.blockIndex + Math.floor(i / 16);

            // Build counter block: nonce[0:8] + BE64(blockIdx)
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

            // Encrypt counter with AES-ECB to get keystream block
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

export { AESCTR, AESCTR_BKTR };