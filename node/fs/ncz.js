import { AESCTR } from '../../crypto/aesctr.mjs';

const UNCOMPRESSABLE_HEADER_SIZE = 0x4000;

class ZstdDecompressor {
    static async load() {
        if (this.ready) return;
        const module = await import('../../static/zstddec.mjs');
        this.decoder = new module.ZSTDDecoder();
        await this.decoder.init();
        this.ready = true;
    }

    static async decompress(data) {
        await this.load();
        return this.decoder.decode(data, 0);
    }
}

export class NCZ {
    constructor(data) {
        this.data = data instanceof Buffer ? data : Buffer.from(data);
    }

    getSections() {
        let offset = 0;
        const magic = this.data.slice(0, 8).toString('ascii');
        
        if (magic !== 'NCZSECTN') {
            const magicAt4000 = this.data.slice(UNCOMPRESSABLE_HEADER_SIZE, UNCOMPRESSABLE_HEADER_SIZE + 8).toString('ascii');
            if (magicAt4000 === 'NCZSECTN') {
                offset = UNCOMPRESSABLE_HEADER_SIZE;
            } else {
                throw new Error(`Invalid NCZ magic: ${magic} (at 0) / ${magicAt4000} (at 0x4000)`);
            }
        }
        
        const sectionCount = Number(this.data.readBigUInt64LE(offset + 8));
        offset += 16;

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
                cryptoType: 0,
                cryptoKey: null,
                cryptoCounter: null
            });
        }

        let ncaSize = UNCOMPRESSABLE_HEADER_SIZE;
        for (const s of sections) {
            ncaSize += s.size;
        }

        return { sections, ncaSize, headerEnd: offset };
    }

    async decompress(progressCallback = null) {
        const { sections, ncaSize, headerEnd } = this.getSections();

        const output = Buffer.alloc(ncaSize);
        
        const magic = this.data.slice(0, 8).toString('ascii');
        if (magic !== 'NCZSECTN') {
            const header = this.data.slice(0, UNCOMPRESSABLE_HEADER_SIZE);
            header.copy(output, 0);
        }

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
        const decompressed = await ZstdDecompressor.decompress(compressedData);
        decompressed.copy(output, UNCOMPRESSABLE_HEADER_SIZE);

        let decompressedOffset = UNCOMPRESSABLE_HEADER_SIZE;
        let firstSection = true;

        for (let sIdx = 0; sIdx < sections.length; sIdx++) {
            const s = sections[sIdx];
            let i = s.offset;
            const end = s.offset + s.size;

            if (firstSection) {
                firstSection = false;
                const uncompressedSize = UNCOMPRESSABLE_HEADER_SIZE - sections[0].offset;
                if (uncompressedSize > 0) {
                    i += uncompressedSize;
                }
            }

            let aesCtr = null;
            if (s.cryptoType === 3 || s.cryptoType === 4) {
                aesCtr = new AESCTR(s.cryptoKey, s.cryptoCounter);
            }

            while (i < end) {
                const chunkSize = Math.min(0x10000, end - i);
                const chunk = output.slice(i, i + chunkSize);

                if (aesCtr) {
                    const decrypted = aesCtr.decrypt(new Uint8Array(chunk), i);
                    Buffer.from(decrypted).copy(output, i);
                }

                i += chunkSize;
                decompressedOffset += chunkSize;

                if (progressCallback) {
                    progressCallback(decompressedOffset / ncaSize);
                }
            }
        }

        return output;
    }

    async decompressWithBlocks(sections, compressedData, output, ncaSize, progressCallback) {
        const blockSizeExponent = compressedData[11];
        const blockSize = Math.pow(2, blockSizeExponent);
        const numberOfBlocks = compressedData.readUInt32LE(12);
        const decompressedSize = Number(compressedData.readBigUInt64LE(16));

        const compressedBlockSizeList = [];
        for (let i = 0; i < numberOfBlocks; i++) {
            compressedBlockSizeList.push(compressedData.readUInt32LE(20 + i * 4));
        }

        const blockDataOffset = 20 + numberOfBlocks * 4;
        const compressedBlockOffsetList = [blockDataOffset];
        for (let i = 0; i < numberOfBlocks - 1; i++) {
            compressedBlockOffsetList.push(compressedBlockOffsetList[i] + compressedBlockSizeList[i]);
        }

        let decompressedOffset = UNCOMPRESSABLE_HEADER_SIZE;
        let currentBlock = null;
        let currentBlockId = -1;

        const getBlock = async (blockId) => {
            if (currentBlockId === blockId) return currentBlock;

            const offset = compressedBlockOffsetList[blockId];
            const compressedSize = compressedBlockSizeList[blockId];

            let blockDecompressedSize = blockSize;
            if (blockId >= numberOfBlocks - 1) {
                const remainder = decompressedSize % blockSize;
                if (remainder > 0) {
                    blockDecompressedSize = Number(remainder);
                }
            }

            const blockData = compressedData.slice(offset, offset + compressedSize);

            if (compressedSize < blockDecompressedSize) {
                currentBlock = Buffer.from(await ZstdDecompressor.decompress(blockData));
            } else {
                currentBlock = blockData;
            }

            currentBlockId = blockId;
            return currentBlock;
        };

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

            let aesCtr = null;
            if (s.cryptoType === 3 || s.cryptoType === 4) {
                aesCtr = new AESCTR(s.cryptoKey, s.cryptoCounter);
            }

            while (i < end) {
                const blockOffset = i % blockSize;
                const blockId = Math.floor(i / blockSize);

                if (blockId >= numberOfBlocks) break;

                const block = await getBlock(blockId);
                const available = block.length - blockOffset;
                const toRead = Math.min(end - i, available);

                let chunk = block.slice(blockOffset, blockOffset + toRead);

                if (aesCtr) {
                    const decrypted = aesCtr.decrypt(new Uint8Array(chunk), i);
                    chunk = Buffer.from(decrypted);
                }

                chunk.copy(output, i);
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
