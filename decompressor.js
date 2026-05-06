import { ZstdDecompressor } from './zstd.js';

const UNCOMPRESSABLE_HEADER_SIZE = 0x4000;

class BlockDecompressorReader {
    constructor() {
        this.position = 0;
        this.blockSize = 1 << 16; // default 64KB
        this.numberOfBlocks = 0;
        this.decompressedSize = 0;
        this.compressedBlockOffsetList = [];
        this.compressedBlockSizeList = [];
        this.currentBlock = null;
        this.currentBlockId = -1;
        this.file = null;
        this.decompressor = null;
    }

    async init(file, blockHeader) {
        this.file = file;
        this.blockSize = 1 << blockHeader.blockSizeExponent;
        this.numberOfBlocks = blockHeader.numberOfBlocks;
        this.decompressedSize = blockHeader.decompressedSize;
        this.compressedBlockSizeList = blockHeader.compressedBlockSizeList;
        
        // Get initial offset (right after Block header)
        const initialOffset = await file.tell();
        
        // Build compressed block offset list
        this.compressedBlockOffsetList = [initialOffset];
        for (let i = 0; i < blockHeader.numberOfBlocks - 1; i++) {
            this.compressedBlockOffsetList.push(
                this.compressedBlockOffsetList[i] + blockHeader.compressedBlockSizeList[i]
            );
        }
        
        // Load zstd decompressor
        await ZstdDecompressor.load();
    }

    async decompressBlock(blockID) {
        if (this.currentBlockId === blockID) {
            return this.currentBlock;
        }
        
        let decompressedBlockSize = this.blockSize;
        if (blockID >= this.numberOfBlocks - 1) {
            const remainder = this.decompressedSize % this.blockSize;
            if (remainder > 0) {
                decompressedBlockSize = remainder;
            }
        }
        
        const offset = this.compressedBlockOffsetList[blockID];
        const compressedSize = this.compressedBlockSizeList[blockID];
        
        this.file.seek(offset);
        const compressedData = await file.read(compressedSize);
        
        if (compressedSize < decompressedBlockSize) {
            this.currentBlock = await this.decompressor.decompress(compressedData);
        } else {
            this.currentBlock = compressedData;
        }
        
        this.currentBlockId = blockID;
        return this.currentBlock;
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

    async read(length) {
        let buffer = new Uint8Array(0);
        let remaining = length;
        
        while (remaining > 0) {
            const blockOffset = this.position % this.blockSize;
            const blockId = Math.floor(this.position / this.blockSize);
            
            if (blockId >= this.numberOfBlocks) {
                break;
            }
            
            const block = await this.decompressBlock(blockId);
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
}

export { NCZDecompressor, BlockDecompressorReader, UNCOMPRESSABLE_HEADER_SIZE };
