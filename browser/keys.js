import { AESECB } from './crypto/aes128.js';

class KeysParser {
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

                    const dec = new Uint8Array(16);
                    for (let j = 0; j < 16; j++) {
                        dec[j] = masterKey[j] ^ titlekekSource[j];
                    }
                    derived.titleKeks[i] = this.bytesToHex(dec);

                    const applicationSource = this.hexToBytes(keys.key_area_key_application_source);
                    derived.keyAreaKeys[i][0] = this.deriveKeyAreaKey(masterKey, applicationSource, keys);

                    const oceanSource = this.hexToBytes(keys.key_area_key_ocean_source);
                    derived.keyAreaKeys[i][1] = this.deriveKeyAreaKey(masterKey, oceanSource, keys);

                    const systemSource = this.hexToBytes(keys.key_area_key_system_source);
                    derived.keyAreaKeys[i][2] = this.deriveKeyAreaKey(masterKey, systemSource, keys);
                } catch (e) {
                    console.warn(`Failed to derive keys for revision ${i}:`, e);
                }
            }
        }

        return derived;
    }

    static deriveKeyAreaKey(masterKey, sourceKey, keys) {
        const kekSeed = this.hexToBytes(this.getKeyOrDefault(keys, 'aes_kek_generation_source', '4d870986c45d20722fba1053da92e8a9'));
        const keySeed = this.hexToBytes(this.getKeyOrDefault(keys, 'aes_key_generation_source', '89615ee05c31b6805fe58f3da24f7aa8'));
        
        const aes = new AESECB(masterKey);
        const kek = aes.decrypt(kekSeed);
        
        const aes2 = new AESECB(kek);
        const srcKek = aes2.decrypt(sourceKey);
        
        const aes3 = new AESECB(srcKek);
        const result = aes3.decrypt(keySeed);
        
        return this.bytesToHex(result);
    }

    static hexToBytes(hex) {
        if (!hex) return new Uint8Array(0);
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    static bytesToHex(bytes) {
        if (bytes instanceof Uint8Array) {
            return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        }
        return '';
    }

    static getKeyOrDefault(keys, key, defaultValue) {
        return keys[key] || defaultValue;
    }
}

export { KeysParser };