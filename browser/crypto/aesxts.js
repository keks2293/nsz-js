import { AESECB } from './aes128.js';

class AESXTS {
    constructor(keys, sector = 0) {
        if (!Array.isArray(keys) || keys.length !== 32) {
            throw new TypeError('XTS mode requires 32-byte key tuple');
        }
        
        const key1 = keys.slice(0, 16);
        const key2 = keys.slice(16, 32);
        
        this.K1 = new AESECB(key1);
        this.K2 = new AESECB(key2);
        
        this.sector = sector;
        this.blockSize = 16;
        this.sectorSize = 0x200;
    }

    encrypt(data, sector = null) {
        if (sector === null) sector = this.sector;
        
        const result = new Uint8Array(data.length);
        let offset = 0;
        let currentSector = sector;
        
        while (offset < data.length) {
            const sectorData = data.slice(offset, offset + this.sectorSize);
            const encrypted = this.encryptSector(sectorData, currentSector);
            result.set(encrypted, offset);
            offset += this.sectorSize;
            currentSector++;
        }
        
        return result;
    }

    decrypt(data, sector = null) {
        if (sector === null) sector = this.sector;
        
        const result = new Uint8Array(data.length);
        let offset = 0;
        let currentSector = sector;
        
        while (offset < data.length) {
            const sectorData = data.slice(offset, offset + this.sectorSize);
            const decrypted = this.decryptSector(sectorData, currentSector);
            result.set(decrypted, offset);
            offset += this.sectorSize;
            currentSector++;
        }
        
        return result;
    }

    encryptSector(data, sector) {
        const tweak = this.getTweak(sector);
        const encryptedTweak = this.K1.encrypt(this.intToBytes(tweak));
        
        const result = new Uint8Array(data.length);
        let offset = 0;
        let currentTweak = encryptedTweak;
        
        while (offset < data.length) {
            const block = data.slice(offset, offset + 16);
            const xored = this.xor(block, currentTweak);
            const encrypted = this.K1.encryptBlock(xored);
            result.set(this.xor(encrypted, currentTweak), offset);
            
            currentTweak = this.gfmul(currentTweak);
            offset += 16;
        }
        
        return result;
    }

    decryptSector(data, sector) {
        const tweak = this.getTweak(sector);
        const encryptedTweak = this.K1.encrypt(this.intToBytes(tweak));
        
        const result = new Uint8Array(data.length);
        let offset = data.length - 16;
        let currentTweak = encryptedTweak;
        
        const blocks = Math.ceil(data.length / 16);
        for (let i = 0; i < blocks - 1; i++) {
            currentTweak = this.gfmul(currentTweak);
        }
        
        while (offset >= 0) {
            const block = data.slice(offset, offset + 16);
            const decrypted = this.xor(this.K1.decryptBlock(this.xor(block, currentTweak)), currentTweak);
            result.set(decrypted, offset);
            
            currentTweak = this.gfmul(currentTweak);
            offset -= 16;
        }
        
        return result;
    }

    getTweak(sector) {
        let tweak = 0n;
        for (let i = 0; i < 16; i++) {
            tweak |= BigInt(sector & 0xff) << BigInt(i * 8);
            sector >>= 8;
        }
        return tweak;
    }

    intToBytes(val) {
        const bytes = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            bytes[i] = Number((val >> BigInt(i * 8)) & 0xffn);
        }
        return bytes;
    }

    xor(a, b) {
        const result = new Uint8Array(Math.max(a.length, b.length));
        for (let i = 0; i < result.length; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    gfmul(a) {
        let val = 0n;
        for (let i = 0; i < 16; i++) {
            val |= BigInt(a[i]) << BigInt(i * 8);
        }
        
        let hi = false;
        for (let i = 0; i < 128; i++) {
            hi = (val & 1n) !== 0n;
            val >>= 1n;
            if (hi) {
                val ^= 0x87n;
            }
        }
        
        return this.intToBytes(val);
    }

    setSector(sector) {
        this.sector = sector;
    }
}

class AESXTSN extends AESXTS {
    constructor(keys, sectorSize = 0x200, sector = 0) {
        super(keys, sector);
        this.sectorSize = sectorSize;
    }

    setSectorSize(sectorSize) {
        this.sectorSize = sectorSize;
    }
}

export { AESXTS, AESXTSN };