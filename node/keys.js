import crypto from 'crypto';
import fs from 'fs';

const crc32Table = (() => {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[i] = c;
    }
    return table;
})();

export class Keys {
    static load(filePath) {
        const content = fs.readFileSync(filePath, 'utf-8');
        return this.parse(content);
    }

    static parse(keyText) {
        const keys = {};
        const lines = keyText.split('\n');

        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;

            const match = trimmed.match(/^\s*([a-z0-9_]+)\s*=\s*([A-F0-9a-f]+)\s*$/i);
            if (match) {
                keys[match[1]] = match[2];
            }
        }

        return this.deriveKeys(keys);
    }

    static deriveKeys(keys) {
        const derived = { ...keys };
        derived.titleKeks = [];
        derived.keyAreaKeys = [];

        for (let i = 0; i < 32; i++) {
            derived.keyAreaKeys.push([null, null, null]);
        }

        for (let i = 0; i < 32; i++) {
            const keyName = `master_key_${i.toString(16).padStart(2, '0')}`;
            if (keys[keyName]) {
                try {
                    const masterKey = this.hexToBytes(keys[keyName]);
                    const titlekekSource = this.hexToBytes(keys.titlekek_source);

                    const dec = Buffer.alloc(16);
                    for (let j = 0; j < 16; j++) {
                        dec[j] = masterKey[j] ^ titlekekSource[j];
                    }
                    derived.titleKeks[i] = this.bytesToHex(dec);

                    const applicationSource = this.hexToBytes(keys.key_area_key_application_source);
                    derived.keyAreaKeys[i][0] = this.deriveKeyAreaKey(masterKey, applicationSource);

                    const oceanSource = this.hexToBytes(keys.key_area_key_ocean_source);
                    derived.keyAreaKeys[i][1] = this.deriveKeyAreaKey(masterKey, oceanSource);

                    const systemSource = this.hexToBytes(keys.key_area_key_system_source);
                    derived.keyAreaKeys[i][2] = this.deriveKeyAreaKey(masterKey, systemSource);
                } catch (e) {
                    console.warn(`Failed to derive keys for revision ${i}:`, e);
                }
            }
        }

        return derived;
    }

    static deriveKeyAreaKey(masterKey, sourceKey) {
        const kekSeed = this.hexToBytes(this.getKeyOrDefault('aes_kek_generation_source', '4d870986c45d20722fba1053da92e8a9'));
        const keySeed = this.hexToBytes(this.getKeyOrDefault('aes_key_generation_source', '89615ee05c31b6805fe58f3da24f7aa8'));

        const masterKeyBuffer = Buffer.isBuffer(masterKey) ? masterKey : Buffer.from(masterKey);
        const kekSeedBuffer = Buffer.isBuffer(kekSeed) ? kekSeed : Buffer.from(kekSeed);

        const kek = crypto.createCipheriv('aes-128-ecb', masterKeyBuffer.slice(0, 16), null);
        const decryptedKek = Buffer.concat([kek.update(kekSeedBuffer), kek.final()]);

        const srcKek = crypto.createCipheriv('aes-128-ecb', decryptedKek, null);
        const decryptedSrcKek = Buffer.concat([srcKek.update(sourceKey), srcKek.final()]);

        const finalKey = crypto.createCipheriv('aes-128-ecb', decryptedSrcKek, null);
        const result = Buffer.concat([finalKey.update(keySeed), finalKey.final()]);

        return result;
    }

    static unwrapAesWrappedTitlekey(wrappedKey, keyGeneration, keys) {
        const masterKey = this.hexToBytes(keys[`master_key_${keyGeneration.toString(16).padStart(2, '0')}`]);
        return this.deriveKeyAreaKey(masterKey, wrappedKey);
    }

    static hexToBytes(hex) {
        if (!hex) return Buffer.alloc(0);
        const bytes = Buffer.alloc(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    static bytesToHex(bytes) {
        if (Buffer.isBuffer(bytes)) {
            return bytes.toString('hex');
        }
        return '';
    }

    static getKeyOrDefault(key, defaultValue) {
        return key || defaultValue;
    }
}

export class AESECB {
    static encrypt(key, data) {
        const cipher = crypto.createCipheriv('aes-128-ecb', key.slice(0, 16), null);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    }

    static decrypt(key, data) {
        const decipher = crypto.createDecipheriv('aes-128-ecb', key.slice(0, 16), null);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
}

export class AESCTR {
    constructor(key, nonce) {
        this.key = key;
        this.nonce = nonce.slice(0, 8);
    }

    encrypt(data, offset = 0) {
        const counter = this.computeCounter(offset);
        const combinedNonce = Buffer.concat([this.nonce, counter]);
        const cipher = crypto.createCipheriv('aes-128-ctr', this.key.slice(0, 16), combinedNonce);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    }

    decrypt(data, offset = 0) {
        return this.encrypt(data, offset);
    }

    computeCounter(offset) {
        const counter = Buffer.alloc(8);
        const initialValue = Math.floor(offset / 16);

        for (let i = 7; i >= 0; i--) {
            counter[i] = initialValue & 0xff;
        }

        return counter;
    }
}

export function crc32(data) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < data.length; i++) {
        crc = crc32Table[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}