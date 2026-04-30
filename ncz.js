import { ZstdDecompressor } from './crypto/zstd.js';
import { AESCTR, AESCTR_BKTR } from './crypto/aesctr.js';
import { AESXTS } from './crypto/aesxts.js';

const UNCOMPRESSABLE_HEADER_SIZE = 0x4000;

const CRYPTO_NONE = 1;
const CRYPTO_XTS = 2;
const CRYPTO_CTR = 3;
const CRYPTO_BKTR = 4;
const CRYPTO_NCA0 = 0x3041434E; // "NCA0" - legacy no crypto

class NCZDecompressor {
    constructor(data, keys = null) {
        this.data = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
        this.view = new DataView(this.data.buffer, this.data.byteOffset, this.data.byteLength);
        this.keys = keys;
        this.pos = 0;
    }

    async decompress(onProgress = () => {}) {
        this.pos = 0;
        
        const header = this.readBytes(UNCOMPRESSABLE_HEADER_SIZE);
        
        const magic = this.readString(8);
        if (magic !== 'NCZSECTN') {
            throw new Error(`Invalid NCZ magic: ${magic}`);
        }

        const sectionCount = this.readInt64();
        console.log('DEBUG NCZ: sectionCount =', sectionCount);
        const sections = [];
        
        for (let i = 0; i < sectionCount; i++) {
            sections.push(this.readSection());
        }

        if (sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE > 0) {
            sections.unshift({
                offset: UNCOMPRESSABLE_HEADER_SIZE,
                size: sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE,
                cryptoType: 1
            });
        }

        let ncaSize = UNCOMPRESSABLE_HEADER_SIZE;
        for (const s of sections) {
            ncaSize += s.size;
        }
        
        const blockMagic = this.peekString(8);
        const useBlockCompression = blockMagic === 'NCZBLOCK';

        let blockDec = null;
        
        if (useBlockCompression) {
            blockDec = this.createBlockDecompressorReader();
        }

        // Calculate total compressed data size (from end of header to EOF)
        const dataEnd = this.data.length;
        const headerEnd = 0x4000 + 8 + (sections.length * 0x40);
        let compressedSize = 0;
        if (useBlockCompression) {
            // Skip block header
            this.pos += 8 + 1 + 1 + 1 + 1 + 4 + 8; // magic + version/type/unused/blockSizeExp + numBlocks + decompSize
            const numBlocks = this.readUint32();
            this.pos += numBlocks * 4; // skip block size list
            compressedSize = dataEnd - this.pos;
        } else {
            this.pos = headerEnd;
            compressedSize = dataEnd - this.pos;
        }
        
        console.log('DEBUG header end:', headerEnd, 'compressed size:', compressedSize);
        
        // Debug: show what's at various positions
        console.log('DEBUG data at 0x4000:', Array.from(this.data.slice(0x4000, 0x4008)));
        console.log('DEBUG data at 0x4010:', Array.from(this.data.slice(0x4010, 0x4018)));
        console.log('DEBUG data at headerEnd:', Array.from(this.data.slice(headerEnd, headerEnd + 8)));
        
// CORRECT: find zstd magic by scanning from known position
        // Standard zstd magic: 28 b5 19 2d (LE: 28 b5 2f fd for some variants)
        const startScan = 0x4000 + 8;
        let zstdPos = -1;
        
        // Also try skippable frames: 5a xx xx xx 
        const magic2 = [0x28, 0xb5, 0x2f, 0xfd]; // LE variant
        const magic1 = [0x28, 0xb5, 0x19, 0x2d]; // Standard
        
        // Scan ALL data for zstd magic
        console.log('DEBUG scanning for zstd magic...');
        const scanResults = [];
        for (let i = 0x4000; i < this.data.length - 4; i += 1) {
            const b0 = this.data[i];
            if ((b0 === 0x28 && this.data[i+1] === 0xb5 && this.data[i+2] === 0x19 && this.data[i+3] === 0x2d) ||
                (b0 === 0x28 && this.data[i+1] === 0xb5 && this.data[i+2] === 0x2f && this.data[i+3] === 0xfd)) {
                zstdPos = i;
                console.log('DEBUG found zstd magic at offset:', i.toString(16), '(' + i + ')');
                console.log('DEBUG zstd first bytes:', Array.from(this.data.slice(i, i + 8)));
                scanResults.push(i);
                if (scanResults.length >= 3) break;
            }
        }
        
        if (zstdPos < 0) {
            console.log('DEBUG NO zstd magic found');
        } else {
            console.log('DEBUG zstd positions found:', scanResults);
        }
        
        const actualZstdStart = zstdPos > 0 ? zstdPos : headerEnd;
        console.log('DEBUG zstd stream start:', actualZstdStart);
        console.log('DEBUG file total size:', this.data.length);
        
        // NOW we know there's zstd! Try to decompress
        if (zstdPos > 0) {
            console.log('DEBUG FOUND zstd at', actualZstdStart, '- attempting decompression...');
            const fullCompressed = this.data.slice(actualZstdStart);
            console.log('DEBUG compressed size:', fullCompressed.length);
            
            const fullDecompressed = await this.decompressChunk(fullCompressed);
            console.log('DEBUG decompressed size:', fullDecompressed ? fullDecompressed.length : 0);
            
            if (fullDecompressed && fullDecompressed.length > 0) {
                console.log('DEBUG SUCCESS! Using decompressed data');
                const output = new Uint8Array(ncaSize);
                output.set(header);
                // Copy decompressed data at proper positions, then decrypt if needed
                // Decompressed stream starts at NCA offset 0x4000 (16384)
                // Section's NCA offset - 0x4000 = position in decompressed data
                for (const s of sections) {
                    if (s.offset < UNCOMPRESSABLE_HEADER_SIZE) continue;
                    const decompOffset = s.offset - UNCOMPRESSABLE_HEADER_SIZE;
                    const sectionData = fullDecompressed.slice(decompOffset, decompOffset + s.size);
                    
                    // Decrypt if needed (cryptoType 3=CTR, 4=BKTR)
                    // Use decryptSection which handles all crypto types
                    let decryptedData = sectionData;
                    if (s.cryptoType === 3 || s.cryptoType === 4) {
                        decryptedData = this.decryptSection(sectionData, s, s.offset);
                    }
                    
                    output.set(decryptedData, s.offset);
                    console.log('DEBUG section:', s.offset, 'size', sectionData.length, 'cryptoType', s.cryptoType);
                }
                return output.buffer;
            } else {
                console.log('DEBUG fzstd failed - trying raw copy');
            }
        }
        
        // Total raw data size = file size - start position
        const totalRawSize = this.data.length - actualZstdStart;
        console.log('DEBUG total raw data:', totalRawSize);
        
        // For each section, the data is stored sequentially
        // Need to calculate offset based on cumulative sizes, not the section table's sizes!
        // The section sizes in table are decompressed sizes, not compressed!
        
        // Use cumulative offset within the raw data
        let rawDataOffset = actualZstdStart;
        
        const output = new Uint8Array(ncaSize);
        output.set(header);

        // Process each section - use raw data sequentially
        for (const s of sections) {
            if (s.offset < UNCOMPRESSABLE_HEADER_SIZE) {
                continue;
            }
            
            const maxSize = Math.min(s.size, this.data.length - rawDataOffset);
            const rawData = this.data.slice(rawDataOffset, rawDataOffset + maxSize);
            console.log('DEBUG section:', s.offset, 'rawDataOffset:', rawDataOffset, 'slice size:', rawData.length, 'need:', s.size, 'cryptoType:', s.cryptoType);
            
            // Decrypt if needed (cryptoType 3=CTR, 4=BKTR)
            let processedData = rawData;
            try {
                if ((s.cryptoType === 3 || s.cryptoType === 4)) {
                    console.log('DEBUG decrypting section at', s.offset, 'size', rawData.length, 'key:', s.cryptoKey ? 'present' : 'none');
                    if (s.cryptoKey) {
                        const crypto = new AESCTR(s.cryptoKey, s.cryptoCounter);
                        const blockIndexOffset = UNCOMPRESSABLE_HEADER_SIZE + s.offset;
                        processedData = crypto.decrypt(rawData, blockIndexOffset);
                        console.log('DEBUG decrypted, result len:', processedData ? processedData.length : 0);
                    } else {
                        console.log('DEBUG no key, copying as-is');
                    }
                } else {
                    console.log('DEBUG copy section at', s.offset, 'size', rawData.length, 'cryptoType', s.cryptoType);
                }
            } catch(e) {
                console.log('DEBUG decrypt error:', e.message);
                processedData = rawData;
            }
            
            // Copy processed data to output position
            output.set(processedData, s.offset);
            
            // Move to next section's data
            rawDataOffset += rawData.length;
            const chunkSize = 0x10000;
            if (blockDec) {
                let remaining = s.size;
                let offset = s.offset;
                while (remaining > 0) {
                    const chunkReadSize = Math.min(chunkSize, remaining);
                    const decompressed = blockDec.read(chunkReadSize);
                    if (!decompressed || decompressed.length === 0) break;
                    
                    let chunk = decompressed;
                    // Decrypt if needed (cryptoType 3=CTR, 4=BKTR)
                    // Note: decryptSection uses section.cryptoKey, not this.keys
                    if (s.cryptoType === 3 || s.cryptoType === 4) {
                        chunk = this.decryptSection(decompressed, s, offset);
                    }
                    
                    output.set(chunk.slice(0, Math.min(chunk.length, ncaSize - offset)), offset);
                    remaining -= chunkReadSize;
                    offset += chunkReadSize;
                }
            }
        }

        return output.buffer;
    }

    readSection() {
        const offset = this.readInt64();
        const size = this.readInt64();
        const cryptoType = this.readInt64();
        const cryptoType2 = this.readInt64();
        console.log('DEBUG section:', offset, size, cryptoType, cryptoType2);
        
        const cryptoKey = this.readBytes(16);
        const cryptoCounter = this.readBytes(16);
        
        return {
            offset,
            size,
            cryptoType,
            cryptoType2,
            cryptoKey: cryptoKey instanceof Uint8Array ? cryptoKey : new Uint8Array(cryptoKey),
            cryptoCounter: cryptoCounter instanceof Uint8Array ? cryptoCounter : new Uint8Array(cryptoCounter)
        };
    }

async createBlockDecompressorReader() {
        // Skip block header to get to compressed data
        this.pos += 8; // NCZBLOCK magic
        this.pos += 4; // version, type, unused, blockSizeExponent
        const blockSizeExponent = this.view.getUint8(this.pos - 1);
        const numberOfBlocks = this.readUint32();
        const decompressedSize = this.readInt64();
        
        const compressedBlockSizeList = [];
        for (let i = 0; i < numberOfBlocks; i++) {
            compressedBlockSizeList.push(this.readUint32());
        }
        
        const decompressedData = await this.decompressChunk(this.data.slice(this.pos));
        
        return new BlockDecompressorReader(
            decompressedData,
            blockSizeExponent,
            numberOfBlocks,
            decompressedSize,
            compressedBlockSizeList
        );
    }

    async decompressChunk(data) {
        try {
            console.log('DEBUG decompress input:', data.length, 'bytes, type:', data.constructor.name);
            
            // Try native DecompressionStream (supports zstd in modern browsers)
            if (typeof DecompressionStream !== 'undefined') {
                try {
                    console.log('Trying native DecompressionStream...');
                    const stream = new ReadableStream({
                        start(controller) {
                            controller.enqueue(data);
                            controller.close();
                        }
                    }).pipeThrough(new DecompressionStream('zstd'));
                    const chunks = [];
                    const reader = stream.getReader();
                    while (true) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        chunks.push(value);
                    }
                    if (chunks.length > 0) {
                        const totalLen = chunks.reduce((a, b) => a + b.length, 0);
                        const result = new Uint8Array(totalLen);
                        let pos = 0;
                        for (const c of chunks) {
                            result.set(c, pos);
                            pos += c.length;
                        }
                        console.log('DEBUG native result:', result.length, 'bytes');
                        return result;
                    }
                } catch(e) {
                    console.log('FAIL native:', e.message);
                }
            }
            
            // Fallback to ZstdDecompressor
            const zstd = new ZstdDecompressor();
            let result = null;
            try { result = zstd.decompress(data); } catch(e) { console.log('FAIL zstd:', e.message); }
            console.log('DEBUG zstd result:', result ? result.length + ' bytes' : 'null');
            return result || new Uint8Array(0);
        } catch (e) {
            console.error('Decompression ERROR:', e.message);
            return new Uint8Array(0);
        }
    }

    readBytes(length) {
        const bytes = this.data.slice(this.pos, this.pos + length);
        this.pos += length;
        return bytes;
    }

readInt64() {
        const result = this.readInt64At(this.pos);
        this.pos += 8;
        return result;
    }

    readInt64At(offset) {
        const low = this.view.getUint32(offset, true);
        const high = this.view.getUint32(offset + 4, true);
        return Number(BigInt(low) + (BigInt(high) << 32n));
    }

    readUint32() {
        const val = this.readUint32At(this.pos);
        this.pos += 4;
        return val;
    }

    readUint32At(offset) {
        return (
            (this.data[offset] & 0xff) |
            ((this.data[offset + 1] & 0xff) << 8) |
            ((this.data[offset + 2] & 0xff) << 16) |
            ((this.data[offset + 3] & 0xff) << 24)
        );
    }

    peekString(length) {
        let str = '';
        for (let i = 0; i < length && this.pos + i < this.data.length; i++) {
            const char = this.data[this.pos + i];
            if (char === 0) break;
            str += String.fromCharCode(char);
        }
        return str;
    }

    readString(length) {
        const str = this.peekString(length);
        this.pos += length;
        return str;
    }

    decryptSection(data, section, offset) {
        const cryptoType = section.cryptoType;
        
        // offset is already the position in NCA (e.g., s.offset which is >= 0x4000)
        // No need to add UNCOMPRESSABLE_HEADER_SIZE
        if (cryptoType === CRYPTO_NONE || cryptoType === CRYPTO_NCA0) {
            return data;
        } else if (cryptoType === CRYPTO_CTR) {
            const crypto = new AESCTR(section.cryptoKey, section.cryptoCounter);
            return crypto.decrypt(data, offset);
        } else if (cryptoType === CRYPTO_BKTR) {
            const crypto = new AESCTR_BKTR(section.cryptoKey, section.cryptoCounter, section.cryptoType2 || 0);
            crypto.seek(offset);
            return crypto.decrypt(data, offset);
        } else if (cryptoType === CRYPTO_XTS) {
            const crypto = new AESXTS(section.cryptoKey);
            const sector = Math.floor(offset / 0x200);
            return crypto.decrypt(data, sector);
        }
    }
}

class BlockDecompressorReader {
    constructor(data, blockSizeExponent, numberOfBlocks, decompressedSize, compressedBlockSizeList) {
        this.data = data;
        this.blockSize = Math.pow(2, blockSizeExponent);
        this.numberOfBlocks = numberOfBlocks;
        this.decompressedSize = decompressedSize;
        this.compressedBlockSizeList = compressedBlockSizeList;
        this.currentBlock = null;
        this.currentBlockId = -1;
        this.position = 0;

        this.compressedBlockOffsetList = [0];
        for (let i = 0; i < compressedBlockSizeList.length - 1; i++) {
            this.compressedBlockOffsetList.push(
                this.compressedBlockOffsetList[i] + compressedBlockSizeList[i]
            );
        }
    }

    readBlock(blockId) {
        if (this.currentBlockId === blockId) {
            return this.currentBlock;
        }

        let decompressedSize = this.blockSize;
        if (blockId >= this.numberOfBlocks - 1) {
            const remainder = this.decompressedSize % this.blockSize;
            if (remainder > 0) {
                decompressedSize = remainder;
            }
        }

        const offset = this.compressedBlockOffsetList[blockId];
        const compressedSize = this.compressedBlockSizeList[blockId];
        
        if (offset + compressedSize > this.data.length) {
            throw new Error('Block data exceeds file bounds');
        }
        
        const compressedData = this.data.slice(offset, offset + compressedSize);
        
        if (compressedSize < decompressedSize) {
            const zstd = new ZstdDecompressor();
            this.currentBlock = zstd.decompress(compressedData);
        } else {
            this.currentBlock = compressedData;
        }
        
        this.currentBlockId = blockId;
        return this.currentBlock;
    }

    read(length) {
        let buffer = new Uint8Array(0);
        let remaining = length;
        
        while (remaining > 0) {
            const blockOffset = this.position % this.blockSize;
            const blockId = Math.floor(this.position / this.blockSize);
            
            if (blockId >= this.numberOfBlocks) {
                break;
            }
            
            const block = this.readBlock(blockId);
            const available = block.length - blockOffset;
            const toRead = Math.min(remaining, available);
            
            const newBuffer = new Uint8Array(buffer.length + toRead);
            newBuffer.set(buffer, 0);
            newBuffer.set(block.slice(blockOffset, blockOffset + toRead), buffer.length);
            buffer = newBuffer;
            
            this.position += toRead;
            remaining -= toRead;
        }
        
        return buffer.slice(0, length);
    }

    seek(offset, whence = 0) {
        if (whence === 0) {
            this.position = offset;
        } else if (whence === 1) {
            this.position += offset;
        } else if (whence === 2) {
            this.position = this.decompressedSize + offset;
        }
    }
}

export { NCZDecompressor, BlockDecompressorReader, UNCOMPRESSABLE_HEADER_SIZE };