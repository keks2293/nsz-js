const UNCOMPRESSABLE_HEADER_SIZE = 0x4000;

export class NCZ {
    constructor(data) {
        this.data = data instanceof Buffer ? data : Buffer.from(data);
    }

    getSections() {
        const magic = this.data.slice(0, 8).toString('ascii');
        if (magic !== 'NCZSECTN') {
            throw new Error(`Invalid NCZ magic: ${magic}`);
        }

        let offset = 8;
        const sectionCount = Number(this.data.readBigUInt64LE(offset));
        offset += 8;

        const sections = [];
        for (let i = 0; i < sectionCount; i++) {
            const sectionOffset = Number(this.data.readBigUInt64LE(offset));
            offset += 8;
            const sectionSize = Number(this.data.readBigUInt64LE(offset));
            offset += 8;
            const cryptoType = Number(this.data.readBigUInt64LE(offset));
            offset += 8;
            offset += 8;
            const cryptoKey = this.data.slice(offset, offset + 16);
            offset += 16;
            const cryptoCounter = this.data.slice(offset, offset + 16);
            offset += 16;

            sections.push({
                offset: sectionOffset,
                size: sectionSize,
                cryptoType,
                cryptoKey,
                cryptoCounter
            });
        }

        if (sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE > 0) {
            sections.unshift({
                offset: UNCOMPRESSABLE_HEADER_SIZE,
                size: sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE,
                cryptoType: 0
            });
        }

        let ncaSize = UNCOMPRESSABLE_HEADER_SIZE;
        for (const s of sections) {
            ncaSize += s.size;
        }

        return { sections, ncaSize, headerEnd: offset };
    }

    decompress(progressCallback = null) {
        return this._decompress(progressCallback);
    }

    async _decompress(progressCallback = null) {
        const { sections, ncaSize, headerEnd } = this.getSections();

        const header = this.data.slice(0, UNCOMPRESSABLE_HEADER_SIZE);
        const output = Buffer.alloc(ncaSize);
        header.copy(output, 0);

        const compressedData = this.data.slice(headerEnd);
        const blockMagic = compressedData.slice(0, 8).toString('ascii');
        const useBlockCompression = blockMagic === 'NCZBLOCK';

        if (useBlockCompression) {
            return await this.decompressWithBlocks(sections, compressedData, output, ncaSize, progressCallback);
        } else {
            return await this.decompressWithStreaming(sections, compressedData, output, ncaSize, progressCallback);
        }
    }

    async decompressWithStreaming(sections, compressedData, output, ncaSize, progressCallback) {
        const zstd = await import('zstd-codec');
        const decompressor = new zstd.ZstdDecompressor();
        decompressor.init();

        const stream = new ZstdStream(decompressor, compressedData);

        let decompressedOffset = UNCOMPRESSABLE_HEADER_SIZE;

        for (let sIdx = 0; sIdx < sections.length; sIdx++) {
            const s = sections[sIdx];
            let i = s.offset;
            const end = s.offset + s.size;

            if (sIdx === 0) {
                const uncompressedSize = UNCOMPRESSABLE_HEADER_SIZE - sections[0].offset;
                if (uncompressedSize > 0) {
                    i += uncompressedSize;
                }
            }

            while (i < end) {
                const chunkSize = Math.min(0x10000, end - i);

                const chunk = stream.read(chunkSize);
                if (chunk.length === 0) break;

                if (s.cryptoType === 3 || s.cryptoType === 4) {
                    this.decryptChunk(chunk, s.cryptoKey, s.cryptoCounter, i).copy(output, i);
                } else {
                    chunk.copy(output, i);
                }

                i += chunk.length;
                decompressedOffset += chunk.length;

                if (progressCallback) {
                    progressCallback(decompressedOffset / ncaSize);
                }
            }
        }

        return output;
    }

    async decompressWithBlocks(sections, compressedData, output, ncaSize, progressCallback) {
        const blockHeaderOffset = 0;
        const blockMagic = compressedData.slice(blockHeaderOffset, 8).toString('ascii');
        if (blockMagic !== 'NCZBLOCK') {
            throw new Error('Invalid NCZBLOCK magic');
        }

        const version = compressedData[8];
        const type = compressedData[9];
        const blockSizeExponent = compressedData[11];
        const blockSize = Math.pow(2, blockSizeExponent);
        const numberOfBlocks = compressedData.readUInt32LE(12);
        const decompressedSize = Number(compressedData.readBigUInt64LE(16));

        const compressedBlockSizeList = [];
        for (let i = 0; i < numberOfBlocks; i++) {
            const size = compressedData.readUInt32LE(20 + i * 4);
            compressedBlockSizeList.push(size);
        }

        const blockDataOffset = 20 + numberOfBlocks * 4;
        const compressedBlockOffsetList = [blockDataOffset];
        for (let i = 0; i < compressedBlockSizeList.length - 1; i++) {
            compressedBlockOffsetList.push(compressedBlockOffsetList[i] + compressedBlockSizeList[i]);
        }

        const blockDecompressor = new AsyncBlockDecompressorReader(
            compressedData,
            blockSize,
            numberOfBlocks,
            decompressedSize,
            compressedBlockSizeList,
            compressedBlockOffsetList
        );

        let decompressedOffset = UNCOMPRESSABLE_HEADER_SIZE;

        for (let sIdx = 0; sIdx < sections.length; sIdx++) {
            const s = sections[sIdx];
            let i = s.offset;
            const end = s.offset + s.size;

            if (sIdx === 0) {
                const uncompressedSize = UNCOMPRESSABLE_HEADER_SIZE - sections[0].offset;
                if (uncompressedSize > 0) {
                    i += uncompressedSize;
                }
            }

            while (i < end) {
                const chunkSize = Math.min(0x10000, end - i);
                const chunk = await blockDecompressor.read(chunkSize);

                if (chunk.length === 0) break;

                if (s.cryptoType === 3 || s.cryptoType === 4) {
                    this.decryptChunk(chunk, s.cryptoKey, s.cryptoCounter, i).copy(output, i);
                } else {
                    chunk.copy(output, i);
                }

                i += chunk.length;
                decompressedOffset += chunk.length;

                if (progressCallback) {
                    progressCallback(decompressedOffset / ncaSize);
                }
            }
        }

        return output;
    }

    decryptChunk(data, key, counter, offset) {
        const ctr = Buffer.from(counter);
        const ofs = Math.floor(offset / 16);

        for (let j = 0; j < 8; j++) {
            ctr[0x10 - j - 1] = ofs & 0xff;
            ofs >>= 8;
        }

        const output = Buffer.alloc(data.length);

        for (let i = 0; i < data.length; i++) {
            const keyByte = key[i % 16];
            const ctrByte = ctr[8 + (i % 8)];
            output[i] = data[i] ^ keyByte ^ ctrByte;
        }

        return output;
    }
}

class ZstdStream {
    constructor(data) {
        this.data = data;
        this.pos = 0;
        this.buffer = Buffer.alloc(0);
        this._decompressor = null;
        this._frameComplete = true;
    }

    async _getDecompressor() {
        if (!this._decompressor) {
            const zstd = await import('zstd-codec');
            this._decompressor = new zstd.ZstdDecompressor();
            this._decompressor.init();
        }
        return this._decompressor;
    }

    async read(size) {
        while (this.buffer.length < size && this.pos < this.data.length) {
            // Find the end of the current zstd frame
            const frameEnd = this._findFrameEnd(this.pos);
            if (frameEnd === -1) {
                // No complete frame found, read what we can
                break;
            }
            
            const frameData = this.data.slice(this.pos, frameEnd);
            const decompressor = await this._getDecompressor();
            
            try {
                const decompressed = decompressor.decompress(frameData);
                this.buffer = Buffer.concat([this.buffer, decompressed]);
                this.pos = frameEnd;
                this._frameComplete = true;
            } catch (e) {
                // Frame decompression failed, skip it
                this.pos = frameEnd;
                this._frameComplete = true;
                break;
            }
        }

        if (this.buffer.length === 0 && this.pos >= this.data.length) {
            return Buffer.alloc(0);
        }

        const result = this.buffer.slice(0, size);
        this.buffer = this.buffer.slice(size);
        return result;
    }

    _findFrameEnd(startPos) {
        // zstd magic number: 0xFD2FB528
        const magic = Buffer.from([0x28, 0xB5, 0x2F, 0xFD]);
        let pos = startPos;
        
        while (pos + 4 <= this.data.length) {
            if (this.data[pos] === magic[0] &&
                this.data[pos + 1] === magic[1] &&
                this.data[pos + 2] === magic[2] &&
                this.data[pos + 3] === magic[3]) {
                
                // Found magic, try to find frame size
                // Read frame header to determine frame size
                if (pos + 18 <= this.data.length) {
                    const headerType = this.data[pos + 4] >> 6;
                    
                    if (headerType === 1) {
                        // Single frame with no frame size
                        return -1;
                    } else if (headerType === 2) {
                        // Frame with 4-byte frame size
                        const frameSize = this.data.readUInt32LE(pos + 8);
                        return pos + 18 + frameSize;
                    } else if (headerType === 3) {
                        // Frame with 2-byte frame size
                        const frameSize = this.data.readUInt16LE(pos + 6);
                        return pos + 10 + frameSize;
                    } else if (headerType === 0) {
                        // Frame with no header size field (older format)
                        return -1;
                    }
                }
                
                pos += 4;
            } else {
                pos++;
            }
        }
        
        return -1;
    }
}

class BlockDecompressorReader {
    constructor(data, blockSize, numberOfBlocks, decompressedSize, compressedBlockSizeList, compressedBlockOffsetList) {
        this.data = data;
        this.blockSize = blockSize;
        this.numberOfBlocks = numberOfBlocks;
        this.decompressedSize = decompressedSize;
        this.compressedBlockSizeList = compressedBlockSizeList;
        this.compressedBlockOffsetList = compressedBlockOffsetList;
        this.currentBlock = null;
        this.currentBlockId = -1;
        this.position = 0;
    }

    read(size) {
        const buffer = [];
        let remaining = size;

        while (remaining > 0) {
            const blockOffset = this.position % this.blockSize;
            const blockId = Math.floor(this.position / this.blockSize);

            if (blockId >= this.numberOfBlocks) break;

            const block = this.getBlock(blockId);
            const available = block.length - blockOffset;
            const toRead = Math.min(remaining, available);

            buffer.push(block.slice(blockOffset, blockOffset + toRead));

            this.position += toRead;
            remaining -= toRead;
        }

        return Buffer.concat(buffer);
    }

    getBlock(blockId) {
        if (this.currentBlockId === blockId) {
            return this.currentBlock;
        }

        const offset = this.compressedBlockOffsetList[blockId];
        const compressedSize = this.compressedBlockSizeList[blockId];

        let decompressedSize = this.blockSize;
        if (blockId >= this.numberOfBlocks - 1) {
            const remainder = this.decompressedSize % this.blockSize;
            if (remainder > 0) {
                decompressedSize = remainder;
            }
        }

        const compressedData = this.data.slice(offset, offset + compressedSize);

        if (compressedSize < decompressedSize) {
            this.currentBlock = this.decompressor.decompress(compressedData);
        } else {
            this.currentBlock = compressedData;
        }

        this.currentBlockId = blockId;
        return this.currentBlock;
    }

    async decompressor() {
        if (this._decompressor) return this._decompressor;
        const zstd = await import('zstd-codec');
        this._decompressor = new zstd.ZstdDecompressor();
        this._decompressor.init();
        return this._decompressor;
    }

    async getDecompressor() {
        const zstd = await import('zstd-codec');
        const dec = new zstd.ZstdDecompressor();
        dec.init();
        return dec;
    }
}

class AsyncBlockDecompressorReader {
    constructor(data, blockSize, numberOfBlocks, decompressedSize, compressedBlockSizeList, compressedBlockOffsetList) {
        this.data = data;
        this.blockSize = blockSize;
        this.numberOfBlocks = numberOfBlocks;
        this.decompressedSize = decompressedSize;
        this.compressedBlockSizeList = compressedBlockSizeList;
        this.compressedBlockOffsetList = compressedBlockOffsetList;
        this.currentBlock = null;
        this.currentBlockId = -1;
        this.position = 0;
        this._decompressor = null;
    }

    async _getDecompressor() {
        if (!this._decompressor) {
            const zstd = await import('zstd-codec');
            this._decompressor = new zstd.ZstdDecompressor();
            this._decompressor.init();
        }
        return this._decompressor;
    }

    async read(size) {
        const buffer = [];
        let remaining = size;

        while (remaining > 0) {
            const blockOffset = this.position % this.blockSize;
            const blockId = Math.floor(this.position / this.blockSize);

            if (blockId >= this.numberOfBlocks) break;

            const block = await this.getBlock(blockId);
            const available = block.length - blockOffset;
            const toRead = Math.min(remaining, available);

            buffer.push(block.slice(blockOffset, blockOffset + toRead));

            this.position += toRead;
            remaining -= toRead;
        }

        return Buffer.concat(buffer);
    }

    async getBlock(blockId) {
        if (this.currentBlockId === blockId) {
            return this.currentBlock;
        }

        const offset = this.compressedBlockOffsetList[blockId];
        const compressedSize = this.compressedBlockSizeList[blockId];

        let decompressedSize = this.blockSize;
        if (blockId >= this.numberOfBlocks - 1) {
            const remainder = this.decompressedSize % this.blockSize;
            if (remainder > 0) {
                decompressedSize = remainder;
            }
        }

        const compressedData = this.data.slice(offset, offset + compressedSize);

        if (compressedSize < decompressedSize) {
            const decompressor = await this._getDecompressor();
            this.currentBlock = decompressor.decompress(compressedData);
        } else {
            this.currentBlock = compressedData;
        }

        this.currentBlockId = blockId;
        return this.currentBlock;
    }
}