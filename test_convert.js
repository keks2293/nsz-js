#!/usr/bin/env node
// Quick NSZ to NSP converter using the fixed crypto modules
// This is a Node.js version of the browser code

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Load aes-js
const aesjs = require('./browser/crypto/aes-js.js');

// Simple SHA256
function sha256(data) {
    return crypto.createHash('sha256').update(Buffer.from(data)).digest('hex');
}

// PFS0 Reader (simplified)
class PFS0Reader {
    constructor(data) {
        this.data = data instanceof Buffer ? new Uint8Array(data) : data;
        this.view = new DataView(this.data.buffer, this.data.byteOffset, this.data.byteLength);
    }
    
    getFiles() {
        const magic = this.view.getUint32(0, true);
        if (magic !== 0x30534650) throw new Error('Not PFS0');
        
        const fileCount = this.view.getUint32(8, true);
        const strTableSize = this.view.getUint32(12, true);
        const headerSize = 16 + fileCount * 16 + strTableSize;
        
        const files = [];
        for (let i = 0; i < fileCount; i++) {
            const offset = 16 + i * 16;
            const dataOffset = this.view.getUint32(offset, true);
            const dataSize = this.view.getUint32(offset + 8, true);
            
            const nameOffset = this.view.getUint32(offset + 12, true);
            let nameStart = 16 + fileCount * 16 + nameOffset;
            let nameEnd = nameStart;
            while (this.data[nameEnd] !== 0) nameEnd++;
            const name = Buffer.from(this.data.slice(nameStart, nameEnd)).toString('utf8');
            
            files.push({ name, offset: dataOffset, size: dataSize });
        }
        return files;
    }
}

// AES-CTR (fixed version)
class AESCTR {
    constructor(key, nonce) {
        this.key = key.slice(0, 16);
        this.nonce = nonce.slice(0, 16);
        this.aes = new aesjs.AES(this.key);
        this.blockIndex = 0;
    }
    
    seek(offset) {
        this.blockIndex = Math.floor(offset / 16);
    }
    
    decrypt(data, offset = 0) {
        this.seek(offset);
        return this._xorKeystream(data);
    }
    
    _xorKeystream(data) {
        const len = data.length;
        const arr = data instanceof Uint8Array ? data : new Uint8Array(data);
        const output = new Uint8Array(len);
        
        for (let i = 0; i < len; i += 16) {
            const blockIdx = this.blockIndex + Math.floor(i / 16);
            
            // Build counter: nonce[0:8] + BE64(blockIdx)
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

// Main conversion
async function convertNSZtoNSP(inputPath, outputPath) {
    console.log(`Reading: ${inputPath}`);
    const data = new Uint8Array(fs.readFileSync(inputPath));
    
    // Parse PFS0
    const pfs0 = new PFS0Reader(data);
    const files = pfs0.getFiles();
    console.log(`Found ${files.length} files`);
    
    // Find NCZ files
    const nczFiles = files.filter(f => f.name.toLowerCase().endsWith('.ncz'));
    console.log(`NCZ files: ${nczFiles.length}`);
    
    // Build output NSP
    const outputParts = [];
    let outputSize = 0;
    
    // ... (simplified - just copy for now)
    console.log('\nTODO: Implement full decompression with fixed AES-CTR');
    console.log('For now, please use the browser version (browser/index.html)');
}

// Run
const args = process.argv.slice(2);
if (args.length < 1) {
    console.log('Usage: node test_convert.js <input.nsz> [output.nsp]');
    process.exit(1);
}

const input = args[0];
const output = args[1] || input.replace('.nsz', '.nsp');
convertNSZtoNSP(input, output).catch(e => console.error('Error:', e));
