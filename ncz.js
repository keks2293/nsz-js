import { ZstdDecompressor } from './crypto/zstd.js';
import { AESCTR } from './crypto/aesctr.mjs';

const UNCOMPRESSABLE_HEADER_SIZE = 0x4000;

function allocByte(n) {
    return new Uint8Array(n);
}

function concatBytes(...arrays) {
    let totalLength = 0;
    for (const arr of arrays) {
        totalLength += arr.length;
    }
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

function bytesToAscii(bytes, start, end) {
    let str = '';
    for (let i = start; i < end; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return str;
}

function readBigUInt64LE(bytes, offset) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return view.getBigUint64(offset, true);
}

function readUInt32LE(bytes, offset) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return view.getUint32(offset, true);
}

function readUInt16LE(bytes, offset) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return view.getUint16(offset, true);
}

function sliceBytes(bytes, start, end) {
    return bytes.slice(start, end);
}

class NCZSection {
    constructor(data, offset) {
        this.offset = Number(readBigUInt64LE(data, offset));
        this.size = Number(readBigUInt64LE(data, offset + 8));
        this.cryptoType = Number(readBigUInt64LE(data, offset + 16));
        this.cryptoKey = sliceBytes(data, offset + 32, offset + 48);
        this.cryptoCounter = sliceBytes(data, offset + 48, offset + 64);
    }
}

class NCZBlockHeader {
    constructor(data, offset) {
        this.magic = bytesToAscii(data, offset, offset + 8);
        this.version = data[offset + 8];
        this.type = data[offset + 9];
        this.unused = data[offset + 10];
        this.blockSizeExponent = data[offset + 11];
        this.numberOfBlocks = readUInt32LE(data, offset + 12);
        this.decompressedSize = Number(readBigUInt64LE(data, offset + 16));
        this.compressedBlockSizeList = [];
        for (let i = 0; i < this.numberOfBlocks; i++) {
            this.compressedBlockSizeList.push(readUInt32LE(data, offset + 20 + i * 4));
        }
    }
}

class FakeSection {
    constructor(offset, size) {
        this.offset = offset;
        this.size = size;
        this.cryptoType = 1;
        this.cryptoKey = allocByte(16);
        this.cryptoCounter = allocByte(16);
    }
}

class NCZDecompressor {
    constructor(data, keys = null) {
        this.data = data instanceof Uint8Array ? data : new Uint8Array(data);
        this.keys = keys;
        this.ncaHeader = null;
    }

    async decompress(progressCallback = null) {
        const { sections, ncaSize, headerEnd } = this.getSections();
        console.log('[NCZ] sections:', sections.length, 'ncaSize:', ncaSize, 'headerEnd:', headerEnd);

        const output = allocByte(ncaSize);
        if (this.ncaHeader) {
            output.set(this.ncaHeader, 0);
        }

        const compressedData = sliceBytes(this.data, headerEnd);
        const blockMagic = bytesToAscii(compressedData, 0, 8);
        const useBlockCompression = blockMagic === 'NCZBLOCK';
        console.log('[NCZ] compression mode:', useBlockCompression ? 'block' : 'streaming');

        if (useBlockCompression) {
            return await this._decompressWithBlocks(sections, compressedData, output, progressCallback);
        } else {
            return await this._decompressWithStreaming(sections, compressedData, output, progressCallback);
        }
    }

    getSections() {
        console.log('[NCZ] data length:', this.data.length, 'first 16 bytes:', Array.from(this.data.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' '));
        const magic = bytesToAscii(this.data, 0, 8);
        console.log('[NCZ] magic at offset 0:', JSON.stringify(magic));

        let nczhdrOffset = 0;
        if (magic !== 'NCZSECTN') {
            const magicAt4000 = bytesToAscii(this.data, UNCOMPRESSABLE_HEADER_SIZE, UNCOMPRESSABLE_HEADER_SIZE + 8);
            console.log('[NCZ] magic at offset 0x4000:', JSON.stringify(magicAt4000));
            if (magicAt4000 === 'NCZSECTN') {
                console.log('[NCZ] NCA header detected at offset 0, NCZSECTN at 0x4000');
                this.ncaHeader = sliceBytes(this.data, 0, UNCOMPRESSABLE_HEADER_SIZE);
                nczhdrOffset = UNCOMPRESSABLE_HEADER_SIZE;
            } else {
                throw new Error(`Invalid NCZ magic: ${magic} (at 0) / ${magicAt4000} (at 0x4000)`);
            }
        }

        let offset = nczhdrOffset + 8;
        console.log('[NCZ] Reading sectionCount at offset', offset, 'value:', this.data.slice(offset, offset+8).map(b => b.toString(16).padStart(2,'0')).join(' '));
        const sectionCount = Number(readBigUInt64LE(this.data, offset));
        console.log('[NCZ] sectionCount:', sectionCount);
        offset += 8;

        const sections = [];
        for (let i = 0; i < sectionCount; i++) {
            sections.push(new NCZSection(this.data, offset));
            offset += 64;
        }

        if (sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE > 0) {
            sections.unshift(new FakeSection(
                UNCOMPRESSABLE_HEADER_SIZE,
                sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE
            ));
        }

        let ncaSize = UNCOMPRESSABLE_HEADER_SIZE;
        for (const s of sections) {
            ncaSize += s.size;
        }

        return { sections, ncaSize, headerEnd: offset };
    }

    async _decompressWithStreaming(sections, compressedData, output, progressCallback = null) {
        const stream = new StreamingZstdReader(compressedData);

        let decompressedOffset = UNCOMPRESSABLE_HEADER_SIZE;
        let firstSection = true;

        for (const section of sections) {
            let i = section.offset;
            const end = section.offset + section.size;

            if (firstSection) {
                firstSection = false;
                const uncompressedSize = UNCOMPRESSABLE_HEADER_SIZE - sections[0].offset;
                if (uncompressedSize > 0) {
                    i += uncompressedSize;
                }
            }

            let aesCtr = null;
            if (section.cryptoType === 3 || section.cryptoType === 4) {
                aesCtr = new AESCTR(section.cryptoKey, section.cryptoCounter);
            }

            while (i < end) {
                const chunkSize = Math.min(0x10000, end - i);
                const chunk = await stream.read(chunkSize);
                if (chunk.length === 0) break;

                if (aesCtr) {
                    const decrypted = aesCtr.decrypt(chunk, i);
                    output.set(decrypted, i);
                } else {
                    output.set(chunk, i);
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

    async _decompressWithBlocks(sections, compressedData, output, progressCallback = null) {
        const blockHeader = new NCZBlockHeader(compressedData, 0);
        const blockDecompressor = new AsyncBlockDecompressorReader(
            compressedData,
            blockHeader.blockSizeExponent,
            blockHeader.numberOfBlocks,
            blockHeader.decompressedSize
        );

        let decompressedOffset = UNCOMPRESSABLE_HEADER_SIZE;
        let firstSection = true;

        for (const section of sections) {
            let i = section.offset;
            const end = section.offset + section.size;

            if (firstSection) {
                firstSection = false;
                const uncompressedSize = UNCOMPRESSABLE_HEADER_SIZE - sections[0].offset;
                if (uncompressedSize > 0) {
                    i += uncompressedSize;
                }
            }

            let aesCtr = null;
            if (section.cryptoType === 3 || section.cryptoType === 4) {
                aesCtr = new AESCTR(section.cryptoKey, section.cryptoCounter);
            }

            while (i < end) {
                const chunkSize = Math.min(0x10000, end - i);
                const chunk = await blockDecompressor.read(chunkSize);
                if (chunk.length === 0) break;

                if (aesCtr) {
                    const decrypted = aesCtr.decrypt(chunk, i);
                    output.set(decrypted, i);
                } else {
                    output.set(chunk, i);
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
}

class StreamingZstdReader {
    constructor(data) {
        this.data = data;
        this.pos = 0;
        this.buffer = allocByte(0);
        this._decompressor = null;
    }

    async _getDecompressor() {
        if (!this._decompressor) {
            if (typeof fzstd !== 'undefined' && fzstd.decompress) {
                this._decompressor = fzstd;
            } else {
                throw new Error('fzstd not loaded');
            }
        }
        return this._decompressor;
    }

    async read(size) {
        while (this.buffer.length < size && this.pos < this.data.length) {
            const frameEnd = this._findFrameEnd(this.pos);
            if (frameEnd === -1 || frameEnd > this.data.length) {
                break;
            }

            const frameData = sliceBytes(this.data, this.pos, frameEnd);
            const decompressor = await this._getDecompressor();

            try {
                const decompressed = decompressor.decompress(frameData);
                this.buffer = concatBytes(this.buffer, decompressed);
                this.pos = frameEnd;
            } catch (e) {
                this.pos = frameEnd;
                break;
            }
        }

        if (this.buffer.length === 0 && this.pos >= this.data.length) {
            return allocByte(0);
        }

        const result = sliceBytes(this.buffer, 0, size);
        this.buffer = sliceBytes(this.buffer, size);
        return result;
    }

    _findFrameEnd(startPos) {
        const magic = new Uint8Array([0x28, 0xB5, 0x2F, 0xFD]);
        let pos = startPos;

        while (pos + 18 <= this.data.length) {
            if (this.data[pos] === magic[0] &&
                this.data[pos + 1] === magic[1] &&
                this.data[pos + 2] === magic[2] &&
                this.data[pos + 3] === magic[3]) {

                const headerType = this.data[pos + 4] >> 6;

                if (headerType === 2) {
                    const frameSize = readUInt32LE(this.data, pos + 8);
                    return pos + 18 + frameSize;
                } else if (headerType === 3) {
                    const frameSize = readUInt16LE(this.data, pos + 6);
                    return pos + 10 + frameSize;
                } else {
                    return -1;
                }
            }
            pos++;
        }
        return -1;
    }
}

class AsyncBlockDecompressorReader {
    constructor(data, blockSizeExponent, numberOfBlocks, decompressedSize) {
        this.data = data;
        this.blockSize = Math.pow(2, blockSizeExponent);
        this.numberOfBlocks = numberOfBlocks;
        this.decompressedSize = decompressedSize;
        this.currentBlock = null;
        this.currentBlockId = -1;
        this.position = 0;
        this._decompressor = null;

        const compressedBlockSizeList = [];
        for (let i = 0; i < numberOfBlocks; i++) {
            compressedBlockSizeList.push(readUInt32LE(data, 20 + i * 4));
        }

        const blockDataOffset = 20 + numberOfBlocks * 4;
        this.compressedBlockOffsetList = [blockDataOffset];
        for (let i = 0; i < numberOfBlocks - 1; i++) {
            this.compressedBlockOffsetList.push(
                this.compressedBlockOffsetList[i] + compressedBlockSizeList[i]
            );
        }
        this.compressedBlockSizeList = compressedBlockSizeList;
    }

    async _getDecompressor() {
        if (!this._decompressor) {
            if (typeof fzstd !== 'undefined' && fzstd.decompress) {
                this._decompressor = fzstd;
            } else {
                throw new Error('fzstd not loaded');
            }
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

            buffer.push(sliceBytes(block, blockOffset, blockOffset + toRead));

            this.position += toRead;
            remaining -= toRead;
        }

        return concatBytes(...buffer);
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
                decompressedSize = Number(remainder);
            }
        }

        const compressedData = sliceBytes(this.data, offset, offset + compressedSize);

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

export { NCZDecompressor, UNCOMPRESSABLE_HEADER_SIZE };
