// AES-CTR - matches Python PyCryptodome: Counter.new(64, prefix=nonce[0:8], initial_value=blockIndex)
// Counter block = nonce[0:8] + BE64(blockIndex)
// Uses Web Crypto API for AES-ECB encryption of counter blocks (works in Node.js + browser)

// AES-CTR - matches Python PyCryptodome: Counter.new(64, prefix=nonce[0:8], initial_value=blockIndex)
// Counter block = nonce[0:8] + BE64(blockIndex)
// Uses Web Crypto API for AES-ECB (works in Node.js + browser)

// Get crypto module (Node.js has crypto, browser has window.crypto)
let _crypto = null;
if (typeof crypto !== 'undefined' && crypto.subtle) {
    _crypto = crypto;
} else if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
    _crypto = globalThis.crypto;
}

class AESCTR {
    constructor(key, nonce) {
        this.key = key.slice(0, 16);
        this.nonce = nonce.slice(0, 16);
        this._debugLogged = false;
        // Import key for AES-ECB
        this._importKey();
    }

    async _importKey() {
        if (!_crypto) return;
        try {
            this.cryptoKey = await _crypto.subtle.importKey(
                'raw',
                this.key,
                { name: 'AES-ECB' },
                false,
                ['encrypt']
            );
        } catch (e) {
            console.warn('AES-CTR: Web Crypto AES-ECB not available:', e.message);
        }
    }

    seek(offset) {
        this.blockIndex = Math.floor(offset / 16);
    }

    async encrypt(data, offset = 0) {
        await this._importKey();
        this.seek(offset);
        return this._xorKeystream(data);
    }

    async decrypt(data, offset = 0) {
        await this._importKey();
        this.seek(offset);
        return this._xorKeystream(data);
    }

    async _xorKeystream(data) {
        const len = data.length;
        const arr = data instanceof Uint8Array ? data : new Uint8Array(data);
        const output = new Uint8Array(len);

        if (!this._debugLogged) {
            this._debugLogged = true;
            console.log('AESCTR: key=', Array.from(this.key).map(b=>b.toString(16).padStart(2,'0')).join(''));
            console.log('AESCTR: nonce=', Array.from(this.nonce).map(b=>b.toString(16).padStart(2,'0')).join(''));
        }

        // If Web Crypto not available, return data as-is
        if (!this.cryptoKey) {
            console.warn('AES-CTR: Web Crypto not available, skipping decryption');
            return data;
        }

        for (let i = 0; i < len; i += 16) {
            const blockIdx = this.blockIndex + Math.floor(i / 16);

            // Build counter block: nonce[0:8] + BE64(blockIdx)
            const ctr = new Uint8Array(16);
            for (let j = 0; j < 8; j++) {
                ctr[j] = this.nonce[j];
            }
            let tmp = blockIdx;
            for (let j = 15; j >= 8; j--) {
                ctr[j] = tmp & 0xff;
                tmp >>= 8;
            }

            // Encrypt counter with AES-ECB
            const encryptedCtr = await _crypto.subtle.encrypt(
                { name: 'AES-ECB' },
                this.cryptoKey,
                ctr
            );
            const keystreamBlock = new Uint8Array(encryptedCtr);

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
        this.ctrVal = ctrVal;
        this._importKey();
    }

    async _importKey() {
        if (!_crypto) return;
        try {
            this.cryptoKey = await _crypto.subtle.importKey(
                'raw',
                this.key,
                { name: 'AES-ECB' },
                false,
                ['encrypt']
            );
        } catch (e) {
            console.warn('AES-CTR_BKTR: Web Crypto AES-ECB not available:', e.message);
        }
    }

    seek(offset) {
        this.blockIndex = Math.floor(offset / 16);
    }

    async encrypt(data, offset = 0) {
        await this._importKey();
        this.seek(offset);
        return this._xorKeystream(data);
    }

    async decrypt(data, offset = 0) {
        await this._importKey();
        this.seek(offset);
        return this._xorKeystream(data);
    }

    async _xorKeystream(data) {
        const len = data.length;
        const arr = data instanceof Uint8Array ? data : new Uint8Array(data);
        const output = new Uint8Array(len);

        if (!this.cryptoKey) {
            console.warn('AES-CTR_BKTR: Web Crypto not available, skipping decryption');
            return data;
        }

        for (let i = 0; i < len; i += 16) {
            const blockIdx = this.blockIndex + Math.floor(i / 16);

            const ctr = new Uint8Array(16);
            // BKTR uses full 16-byte counter (nonce is already the counter from section header)
            for (let j = 0; j < 16; j++) {
                ctr[j] = this.nonce[j];
            }
            // Add blockIndex to last 8 bytes
            let tmp = blockIdx;
            for (let j = 15; j >= 8; j--) {
                ctr[j] ^= (tmp & 0xff);
                tmp >>= 8;
            }

            const encryptedCtr = await _crypto.subtle.encrypt(
                { name: 'AES-ECB' },
                this.cryptoKey,
                ctr
            );
            const keystreamBlock = new Uint8Array(encryptedCtr);

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