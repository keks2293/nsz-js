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

const READ_CHUNK_SIZE = 0x60000000; // 1.5 GB per chunk, safe below 2GB ArrayBuffer limit

class DataReader {
    async read(offset, size) {
        throw new Error('abstract');
    }

    get length() {
        throw new Error('abstract');
    }
}

class BufferReader extends DataReader {
    constructor(buffer) {
        super();
        this.buffer = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    }

    get length() {
        return this.buffer.length;
    }

    async read(offset, size) {
        return this.buffer.slice(offset, offset + size);
    }
}

class ChunkedBufferReader extends DataReader {
    constructor(chunks, totalLength) {
        super();
        this.chunks = chunks;
        this._length = totalLength;
        this.chunkOffsets = [];
        let offset = 0;
        for (const chunk of chunks) {
            this.chunkOffsets.push(offset);
            offset += chunk.length;
        }
    }

    get length() {
        return this._length;
    }

    async read(offset, size) {
        if (size === 0) return new Uint8Array(0);
        // Find the chunk containing offset
        let ci = 0;
        for (let i = this.chunkOffsets.length - 1; i >= 0; i--) {
            if (offset >= this.chunkOffsets[i]) {
                ci = i;
                break;
            }
        }
        const chunkStart = this.chunkOffsets[ci];
        const chunk = this.chunks[ci];
        const relOffset = offset - chunkStart;
        const available = chunk.length - relOffset;
        if (available >= size) {
            return chunk.slice(relOffset, relOffset + size);
        }
        // Crosses chunk boundary: read both parts
        const first = chunk.slice(relOffset);
        const remaining = size - first.length;
        const second = await this.read(offset + first.length, remaining);
        const result = new Uint8Array(size);
        result.set(first, 0);
        result.set(second, first.length);
        return result;
    }
}

class FileDescriptorReader extends DataReader {
    constructor(fd, baseOffset = 0, totalLength = null) {
        super();
        this.fd = fd;
        this.baseOffset = baseOffset;
        this._length = totalLength;
        this._fs = null;
    }

    get length() {
        return this._length;
    }

    async _getFs() {
        if (!this._fs) {
            this._fs = await import('fs/promises');
        }
        return this._fs;
    }

    async read(offset, size) {
        const fs = await this._getFs();
        const buf = Buffer.alloc(size);
        const { bytesRead } = await fs.read(this.fd, buf, 0, size, this.baseOffset + offset);
        if (bytesRead < size) {
            return new Uint8Array(buf.buffer, buf.byteOffset, bytesRead);
        }
        return new Uint8Array(buf.buffer, buf.byteOffset, size);
    }
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
        if (data instanceof DataReader) {
            this.reader = data;
        } else {
            this.reader = new BufferReader(data);
        }
        this.keys = keys;
        this.ncaHeader = null;
    }

    async decompress(progressCallback = null, writeChunk = null) {
        const { sections, ncaSize, headerEnd } = await this.getSections();
        console.log('[NCZ] sections:', sections.length, 'ncaSize:', ncaSize, 'headerEnd:', headerEnd);

        // Read compressed data magic to determine mode
        const magicBytes = await this.reader.read(headerEnd, 8);
        const blockMagic = bytesToAscii(magicBytes, 0, 8);
        const useBlockCompression = blockMagic === 'NCZBLOCK';
        console.log('[NCZ] compression mode:', useBlockCompression ? 'block' : 'streaming');

        if (writeChunk) {
            if (this.ncaHeader) {
                await writeChunk(this.ncaHeader, 0);
            }
            if (useBlockCompression) {
                console.log('[NCZ] Using streaming block decompression');
                return await this._decompressWithBlocks(sections, null, ncaSize, headerEnd, progressCallback, writeChunk);
            } else {
                return await this._decompressWithStreamingStream(sections, ncaSize, headerEnd, progressCallback, writeChunk);
            }
        } else {
            // Memory mode (Node.js): allocate full output buffer
            const output = allocByte(ncaSize);
            if (this.ncaHeader) {
                output.set(this.ncaHeader, 0);
            }
            if (useBlockCompression) {
                return await this._decompressWithBlocks(sections, output, ncaSize, headerEnd, progressCallback);
            } else {
                const compressedData = await this.reader.read(headerEnd, this.reader.length - headerEnd);
                return await this._decompressWithStreaming(sections, compressedData, output, ncaSize, progressCallback);
            }
        }
    }

    async getSections() {
        const magicBytes = await this.reader.read(0, 8);
        const magic = bytesToAscii(magicBytes, 0, 8);
        console.log('[NCZ] magic at offset 0:', JSON.stringify(magic));

        let nczhdrOffset = 0;
        if (magic !== 'NCZSECTN') {
            const magicAt4000Bytes = await this.reader.read(UNCOMPRESSABLE_HEADER_SIZE, 8);
            const magicAt4000 = bytesToAscii(magicAt4000Bytes, 0, 8);
            console.log('[NCZ] magic at offset 0x4000:', JSON.stringify(magicAt4000));
            if (magicAt4000 === 'NCZSECTN') {
                console.log('[NCZ] NCA header detected at offset 0, NCZSECTN at 0x4000');
                this.ncaHeader = await this.reader.read(0, UNCOMPRESSABLE_HEADER_SIZE);
                nczhdrOffset = UNCOMPRESSABLE_HEADER_SIZE;
            } else {
                if (magic.startsWith('\x78') || magic.startsWith('N')) {
                    console.log('[NCZ] Detected NCA file (not compressed NCZ)');
                    const dataLen = this.reader.length;
                    return { sections: [], ncaSize: dataLen, headerEnd: 0 };
                }
                throw new Error(`Invalid NCZ magic: ${magic} (at 0) / ${magicAt4000} (at 0x4000)`);
            }
        }

        let offset = nczhdrOffset + 8;
        const sectionCountBytes = await this.reader.read(offset, 8);
        const sectionCount = Number(readBigUInt64LE(sectionCountBytes, 0));
        console.log('[NCZ] sectionCount:', sectionCount);
        offset += 8;

        const sections = [];
        for (let i = 0; i < sectionCount; i++) {
            const sectionData = await this.reader.read(offset, 64);
            sections.push(new NCZSection(sectionData, 0));
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

    async _decompressWithStreaming(sections, compressedData, output, ncaSize, progressCallback = null, writeChunk = null) {
        let decompressed;
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
            decompressed = new Uint8Array(result.buffer, result.byteOffset, result.byteLength);
        } else {
            console.log('[ZSTD] Using zstddec WASM for browser');
            const { ZSTDDecoder } = await import('./static/zstddec.mjs');
            const decoder = new ZSTDDecoder();
            await decoder.init();
            decompressed = decoder.decode(compressedData, 0);
        }

        const streaming = writeChunk !== null;
        if (streaming) {
            await writeChunk(decompressed, UNCOMPRESSABLE_HEADER_SIZE);
        } else {
            output.set(decompressed, UNCOMPRESSABLE_HEADER_SIZE);
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
                const relOffset = i - UNCOMPRESSABLE_HEADER_SIZE;
                const chunk = decompressed.slice(relOffset, relOffset + chunkSize);

                if (aesCtr) {
                    const decrypted = aesCtr.decrypt(chunk, i);
                    if (streaming) {
                        await writeChunk(decrypted, i);
                    } else {
                        output.set(decrypted, i);
                    }
                }

                i += chunkSize;
                decompressedOffset += chunkSize;

                if (progressCallback) {
                    progressCallback(decompressedOffset / ncaSize);
                }
            }
        }

        return streaming ? null : output;
    }

    async _decompressWithBlocks(sections, output, ncaSize, headerEnd, progressCallback = null, writeChunk = null) {
        console.log('[NCZ] _decompressWithBlocks start, headerEnd:', headerEnd, 'ncaSize:', ncaSize, 'has writeChunk:', !!writeChunk);
        const blockHeaderData = await this.reader.read(headerEnd, 24);
        console.log('[NCZ] blockHeaderData read:', blockHeaderData.length, 'bytes');
        const blockHeader = new NCZBlockHeader(blockHeaderData, 0);
        console.log('[NCZ] block magic:', JSON.stringify(blockHeader.magic), 'numBlocks:', blockHeader.numberOfBlocks, 'blockSize:', Math.pow(2, blockHeader.blockSizeExponent), 'decompressedSize:', blockHeader.decompressedSize);
        const sizeListSize = blockHeader.numberOfBlocks * 4;
        console.log('[NCZ] reading size list:', sizeListSize, 'bytes at offset', headerEnd + 24);
        const sizeListData = await this.reader.read(headerEnd + 24, sizeListSize);
        console.log('[NCZ] size list read:', sizeListData.length, 'bytes');
        const blockDecompressor = new AsyncBlockDecompressorReader(
            this.reader,
            headerEnd,
            blockHeader.blockSizeExponent,
            blockHeader.numberOfBlocks,
            blockHeader.decompressedSize,
            sizeListData
        );

        let decompressedOffset = UNCOMPRESSABLE_HEADER_SIZE;
        let firstSection = true;
        const streaming = writeChunk !== null;

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

                let data = chunk;
                if (aesCtr) {
                    data = aesCtr.decrypt(chunk, i);
                }

                if (streaming) {
                    await writeChunk(data, i);
                } else {
                    output.set(data, i);
                }

                i += chunk.length;
                decompressedOffset += chunk.length;

                if (progressCallback) {
                    progressCallback(decompressedOffset / ncaSize);
                }
            }
        }

        return streaming ? null : output;
    }

    async _decompressWithStreamingStream(sections, ncaSize, headerEnd, progressCallback, writeChunk) {
        console.log('[NCZ] Streaming (non-block) mode with chunked decompression');
        const remaining = this.reader.length - headerEnd;
        const compressedChunks = [];
        let pos = headerEnd;
        let toRead = remaining;
        while (toRead > 0) {
            const size = Math.min(toRead, READ_CHUNK_SIZE);
            const chunk = await this.reader.read(pos, size);
            compressedChunks.push(chunk);
            pos += size;
            toRead -= size;
        }
        const sortedSections = [...sections].sort((a, b) => a.offset - b.offset);
        const sectionAesCtrs = new Map();
        for (const s of sortedSections) {
            if (s.cryptoType === 3 || s.cryptoType === 4) {
                sectionAesCtrs.set(s, new AESCTR(s.cryptoKey, s.cryptoCounter));
            }
        }
        if (typeof process !== 'undefined' && process.versions && process.versions.node) {
            console.log('[ZSTD] Using zstd CLI for Node.js streaming');
            const { spawn } = await import('node:child_process');
            const proc = spawn('zstd', ['-d', '--no-check'], { stdio: ['pipe', 'pipe', 'pipe'] });
            for (const chunk of compressedChunks) {
                proc.stdin.write(Buffer.from(chunk));
            }
            proc.stdin.end();
            let stderr = '';
            proc.stderr.on('data', (c) => stderr += c.toString());
            const exitPromise = new Promise((resolve, reject) => {
                proc.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`zstd failed: ${stderr}`)));
                proc.on('error', reject);
            });
            let decompOffset = UNCOMPRESSABLE_HEADER_SIZE;
            for await (const nodeChunk of proc.stdout) {
                const dc = new Uint8Array(nodeChunk.buffer, nodeChunk.byteOffset, nodeChunk.byteLength);
                decompOffset = await this._processStreamDecompressedChunk(dc, decompOffset, sortedSections, sectionAesCtrs, progressCallback, writeChunk, ncaSize);
            }
            await exitPromise;
        } else {
            console.log('[ZSTD] Using zstddec WASM streaming decompression');
            const { ZSTDDecoder } = await import('./static/zstddec.mjs');
            const decoder = new ZSTDDecoder();
            await decoder.init();
            let decompOffset = UNCOMPRESSABLE_HEADER_SIZE;
            for (const decompChunk of decoder.decodeStreaming(compressedChunks)) {
                decompOffset = await this._processStreamDecompressedChunk(decompChunk, decompOffset, sortedSections, sectionAesCtrs, progressCallback, writeChunk, ncaSize);
            }
        }
        return null;
    }

    async _processStreamDecompressedChunk(decompChunk, decompOffset, sortedSections, sectionAesCtrs, progressCallback, writeChunk, ncaSize) {
        let offset = 0;
        while (offset < decompChunk.length) {
            const ncaPos = decompOffset + offset;
            let aesCtr = null;
            let boundary = decompChunk.length;
            for (const section of sortedSections) {
                if (ncaPos >= section.offset && ncaPos < section.offset + section.size) {
                    if (sectionAesCtrs.has(section)) {
                        aesCtr = sectionAesCtrs.get(section);
                    }
                    boundary = Math.min(boundary, offset + (section.offset + section.size - ncaPos));
                    break;
                }
            }
            const subSize = boundary - offset;
            let data = decompChunk.slice(offset, offset + subSize);
            if (aesCtr) data = aesCtr.decrypt(data, ncaPos);
            await writeChunk(data, ncaPos);
            offset += subSize;
            if (progressCallback) progressCallback((decompOffset + offset) / ncaSize);
        }
        return decompOffset + decompChunk.length;
    }
}

class AsyncBlockDecompressorReader {
    constructor(reader, baseOffset, blockSizeExponent, numberOfBlocks, decompressedSize, sizeListData) {
        this.reader = reader;
        this.baseOffset = baseOffset;
        this.blockSize = Math.pow(2, blockSizeExponent);
        this.numberOfBlocks = numberOfBlocks;
        this.decompressedSize = decompressedSize;
        this.currentBlock = null;
        this.currentBlockId = -1;
        this.position = 0;

        const compressedBlockSizeList = [];
        for (let i = 0; i < numberOfBlocks; i++) {
            compressedBlockSizeList.push(readUInt32LE(sizeListData, i * 4));
        }

        const blockDataOffset = 24 + numberOfBlocks * 4;
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

        const relOffset = this.compressedBlockOffsetList[blockId];
        const compressedSize = this.compressedBlockSizeList[blockId];

        let decompressedSize = this.blockSize;
        if (blockId >= this.numberOfBlocks - 1) {
            const remainder = this.decompressedSize % this.blockSize;
            if (remainder > 0) {
                decompressedSize = Number(remainder);
            }
        }

        const compressedData = await this.reader.read(this.baseOffset + relOffset, compressedSize);

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

export { NCZDecompressor, DataReader, BufferReader, ChunkedBufferReader, FileDescriptorReader, READ_CHUNK_SIZE };
