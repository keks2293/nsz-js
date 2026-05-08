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

function sliceBytes(bytes, start, end) {
    return bytes.slice(start, end);
}

function getZstdWindowSize(data) {
    if (data.length < 6) return 0;
    const n3 = data[0] | (data[1] << 8) | (data[2] << 16);
    if (n3 !== 0x2FB528 || data[3] !== 0xFD) return 0;
    const singleSegment = (data[4] >> 5) & 1;
    if (singleSegment) return 0;
    const windowLog = data[5] >> 3;
    const windowBase = 1 << (10 + windowLog);
    const mantissa = data[5] & 7;
    return windowBase + (windowBase >> 3) * mantissa;
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
            return await this._decompressWithBlocks(sections, compressedData, output, ncaSize, progressCallback);
        } else {
            return await this._decompressWithStreaming(sections, compressedData, output, ncaSize, progressCallback);
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
                // Check if this is actually NCA (not NCZ)
                if (magic.startsWith('\x78') || magic.startsWith('N')) {
                    console.log('[NCZ] Detected NCA file (not compressed NCZ)');
                    // Return empty sections - caller should copy as-is
                    return { sections: [], ncaSize: this.data.length, headerEnd: 0 };
                }
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

    async _decompressWithStreaming(sections, compressedData, output, ncaSize, progressCallback = null) {
        if (typeof process !== 'undefined' && process.versions && process.versions.node) {
            console.log('[ZSTD] Using zstd CLI for Node.js');
            const { spawn } = await import('node:child_process');
            const proc = spawn('zstd', ['-d', '--no-check'], { stdio: ['pipe', 'pipe', 'pipe'] });
            const chunks = [];
            proc.stdout.on('data', (chunk) => chunks.push(chunk));
            let stderr = '';
            proc.stderr.on('data', (chunk) => stderr += chunk.toString());
            proc.stdin.write(Buffer.from(compressedData));
            proc.stdin.end();
            await new Promise((resolve, reject) => {
                proc.on('exit', (code) => {
                    if (code === 0) resolve();
                    else reject(new Error(`zstd failed with code ${code}: ${stderr}`));
                });
                proc.on('error', reject);
            });
            const result = Buffer.concat(chunks);
            const decompressed = new Uint8Array(result.buffer, result.byteOffset, result.byteLength);
            output.set(decompressed, UNCOMPRESSABLE_HEADER_SIZE);
        } else {
            const windowSize = getZstdWindowSize(compressedData);
            if (windowSize > 32 * 1024 * 1024) {
                throw new Error(
                    `Browser zstd decompression not available: frame uses ${(windowSize / 1024 / 1024).toFixed(0)}MB zstd window, ` +
                    `but fzstd (browser JS library) only supports up to 32MB. ` +
                    `Use the Node.js CLI (nsz-convert.js) which uses the native zstd tool.`
                );
            }
            console.log('[ZSTD] Using fzstd (chunked) for browser');
            try {
                const fzstd = await import('./static/fzstd.mjs');
                let writePos = UNCOMPRESSABLE_HEADER_SIZE;
                const d = new fzstd.Decompress(chunk => {
                    output.set(chunk, writePos);
                    writePos += chunk.length;
                });
                const CHUNK = 0x10000;
                let pos = 0;
                while (pos < compressedData.length) {
                    const end = Math.min(pos + CHUNK, compressedData.length);
                    d.push(compressedData.subarray(pos, end), end >= compressedData.length);
                    pos = end;
                }
            } catch (e) {
                throw new Error(
                    `Browser zstd decompression failed: ${e.message}. ` +
                    `This NCZ file uses a large zstd window (>32MB) which the browser's fzstd library cannot handle. ` +
                    `Use the Node.js CLI (nsz-convert.js) instead, which uses the native zstd tool.`
                );
            }
        }

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
                const chunk = output.slice(i, i + chunkSize);

                if (aesCtr) {
                    const decrypted = aesCtr.decrypt(chunk, i);
                    output.set(decrypted, i);
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

    async _decompressWithBlocks(sections, compressedData, output, ncaSize, progressCallback = null) {
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

class AsyncBlockDecompressorReader {
    constructor(data, blockSizeExponent, numberOfBlocks, decompressedSize) {
        this.data = data;
        this.blockSize = Math.pow(2, blockSizeExponent);
        this.numberOfBlocks = numberOfBlocks;
        this.decompressedSize = decompressedSize;
        this.currentBlock = null;
        this.currentBlockId = -1;
        this.position = 0;

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
            const decompressor = new ZstdDecompressor();
            await decompressor.load();
            this.currentBlock = decompressor.decompress(compressedData);
        } else {
            this.currentBlock = compressedData;
        }

        this.currentBlockId = blockId;
        return this.currentBlock;
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
}

export { NCZDecompressor };
