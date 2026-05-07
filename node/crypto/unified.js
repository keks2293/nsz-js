// Unified crypto module that works in both Node.js and browser environments
import { AESECB as AESECBRaw } from './aes128.js';
import { sha256 as sha256Raw } from './sha256.js';

let crypto;
try {
    crypto = await import('crypto');
} catch (e) {
    crypto = null;
}

export function aes128Encrypt(key, data) {
    if (crypto) {
        const cipher = crypto.default.createCipheriv('aes-128-ecb', key, null);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    }
    return new AESECBRaw(key).encrypt(data);
}

export function aes128Decrypt(key, data) {
    if (crypto) {
        const decipher = crypto.default.createDecipheriv('aes-128-ecb', key, null);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
    return new AESECBRaw(key).decrypt(data);
}

export function sha256(data) {
    if (crypto) {
        return crypto.default.createHash('sha256').update(data).digest('hex');
    }
    return sha256Raw(data);
}
