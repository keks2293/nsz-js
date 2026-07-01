import { ZstdDecompressor } from '../crypto/zstd.js';
import { AesCtr } from '../crypto/aesctr.mjs';

const UNCOMPRESSABLE_HEADER_SIZE = 0x4000;
const SECTION_CHUNK_SIZE = 0x1000000; // 16MB

function allocByte(n) {
    return new Uint8Array(n);
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
    return bytes.subarray(start, end);
}

const READ_CHUNK_SIZE = 0x1000000; // 16 MB per chunk, streaming decompressor handles any size

class DataReader {
    async read(offset, size) {
        throw new Error('abstract');
    }

    get length() {
        throw new Error('abstract');
    }
}

class AdapterNCZReader extends DataReader {
    constructor(adapter, fileOffset, fileSize) {
        super();
        this._adapter = adapter;
        this._fileOffset = fileOffset;
        this._length = fileSize;
    }
    get length() { return this._length; }
    async read(offset, size) {
        return this._adapter.read(this._fileOffset + offset, size);
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
        return this.buffer.subarray(offset, offset + size);
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
            return chunk.subarray(relOffset, relOffset + size);
        }
        // Crosses chunk boundary: read both parts
        const first = chunk.subarray(relOffset);
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
    }

    get length() {
        return this._length;
    }

    async read(offset, size) {
        const buf = Buffer.alloc(size);
        const fs = await import('fs');
        const { bytesRead } = await new Promise((resolve, reject) => {
            fs.read(this.fd, buf, 0, size, this.baseOffset + offset, (err, bytesRead, buffer) => {
                if (err) reject(err);
                else resolve({ bytesRead, buffer });
            });
        });
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

        let useBlock = false;
        if (headerEnd < this.reader.length) {
            const magicBytes = await this.reader.read(headerEnd, 8);
            const magic = bytesToAscii(magicBytes, 0, 8);
            useBlock = magic === 'NCZBLOCK';
            console.log('[NCZ] compression mode:', useBlock ? 'block' : 'streaming');
        }

        if (writeChunk) {
            if (this.ncaHeader) await writeChunk(this.ncaHeader, 0);
        } else {
            const output = allocByte(ncaSize);
            if (this.ncaHeader) output.set(this.ncaHeader, 0);
            const wfn = async (chunk, pos) => output.set(chunk, pos);

            if (useBlock) {
                await this._decompressBlocks(sections, ncaSize, headerEnd, progressCallback, wfn);
            } else if (headerEnd < this.reader.length) {
                await this._decompressStream(sections, ncaSize, headerEnd, progressCallback, wfn);
            }
            return output;
        }

        if (useBlock) {
            await this._decompressBlocks(sections, ncaSize, headerEnd, progressCallback, writeChunk);
        } else if (headerEnd < this.reader.length) {
            await this._decompressStream(sections, ncaSize, headerEnd, progressCallback, writeChunk);
        }
    }

    async _decompressStream(sections, ncaSize, headerEnd, progressCallback, writeChunk) {
        const remaining = this.reader.length - headerEnd;
        const sortedSections = [...sections].sort((a, b) => a.offset - b.offset);
        const sectionAesCtrs = new Map();
        for (const s of sortedSections) {
            if (s.cryptoType === 3 || s.cryptoType === 4) {
                sectionAesCtrs.set(s, new AesCtr(s.cryptoKey, s.cryptoCounter));
            }
        }

        const processChunk = async (chunk, decompOffset) => {
            let offset = 0;
            let lastAesCtr = null;
            let lastDecryptEnd = -1;
            while (offset < chunk.length) {
                const ncaPos = decompOffset + offset;
                let aesCtr = null;
                let boundary = chunk.length;
                for (const s of sortedSections) {
                    if (ncaPos >= s.offset && ncaPos < s.offset + s.size) {
                        if (sectionAesCtrs.has(s)) aesCtr = sectionAesCtrs.get(s);
                        boundary = Math.min(boundary, offset + (s.offset + s.size - ncaPos));
                        break;
                    }
                }
                const subSize = boundary - offset;
                let data = chunk.subarray(offset, offset + subSize);
                if (aesCtr) {
                    if (aesCtr !== lastAesCtr || ncaPos !== lastDecryptEnd) {
                        aesCtr.seek(ncaPos);
                    }
                    data = await aesCtr.decrypt(data);
                    lastDecryptEnd = ncaPos + data.length;
                    lastAesCtr = aesCtr;
                }
                await writeChunk(data, ncaPos);
                offset += subSize;
                if (progressCallback) progressCallback((decompOffset + offset) / ncaSize);
            }
            return decompOffset + chunk.length;
        };

        if (typeof process !== 'undefined' && process.versions && process.versions.node) {
            console.log('[ZSTD] Using zstd CLI for Node.js streaming');
            const { spawn } = await import('node:child_process');
            const proc = spawn('zstd', ['-d', '--no-check'], { stdio: ['pipe', 'pipe', 'pipe'] });
            let stderr = '';
            proc.stderr.on('data', c => stderr += c.toString());
            const exitPromise = new Promise(r => proc.on('close', (code) => r(code)));

            const decompressPromise = (async () => {
                let decompOffset = UNCOMPRESSABLE_HEADER_SIZE;
                for await (const nodeChunk of proc.stdout) {
                    decompOffset = await processChunk(
                        new Uint8Array(nodeChunk.buffer, nodeChunk.byteOffset, nodeChunk.byteLength),
                        decompOffset
                    );
                }
            })();

            let pos = headerEnd;
            let toRead = remaining;
            while (toRead > 0) {
                const size = Math.min(toRead, READ_CHUNK_SIZE);
                const chunk = await this.reader.read(pos, size);
                if (!proc.stdin.write(chunk)) {
                    await new Promise(r => proc.stdin.once('drain', r));
                }
                pos += chunk.length;
                toRead -= chunk.length;
            }
            proc.stdin.end();
            await decompressPromise;
            const exitCode = await exitPromise;
            if (exitCode !== 0) throw new Error(`zstd decompress failed (exit ${exitCode}): ${stderr}`);
        } else {
            console.log('[ZSTD] Using zstddec WASM streaming decompression (async)');
            const { initZstddec, decodeStream } = await import('../crypto/zstddec-stream-wrapper.js');
            await initZstddec();
            let pos = headerEnd;
            let toRead = remaining;
            let decompOffset = UNCOMPRESSABLE_HEADER_SIZE;
            for await (const chunk of decodeStream(async () => {
                if (toRead <= 0) return null;
                const size = Math.min(toRead, READ_CHUNK_SIZE);
                const data = await this.reader.read(pos, size);
                pos += data.length;
                toRead -= data.length;
                return data;
            })) {
                decompOffset = await processChunk(chunk, decompOffset);
            }
        }
    }

    async _decompressBlocks(sections, ncaSize, headerEnd, progressCallback, writeChunk) {
        const blockHeaderData = await this.reader.read(headerEnd, 24);
        const blockHeader = new NCZBlockHeader(blockHeaderData, 0);
        if (blockHeader.blockSizeExponent < 14 || blockHeader.blockSizeExponent > 32) {
            throw new Error(`Corrupted NCZBLOCK header: Block size must be between 14 and 32, got ${blockHeader.blockSizeExponent}`);
        }
        const sizeListSize = blockHeader.numberOfBlocks * 4;
        const sizeListData = await this.reader.read(headerEnd + 24, sizeListSize);
        const reader = new AsyncBlockDecompressorReader(
            this.reader, headerEnd,
            blockHeader.blockSizeExponent, blockHeader.numberOfBlocks,
            blockHeader.decompressedSize, sizeListData
        );

        let decompressedOffset = UNCOMPRESSABLE_HEADER_SIZE;
        let isFirstSection = true;
        for (const section of sections) {
            let i = section.offset;
            const end = section.offset + section.size;

            if (isFirstSection) {
                isFirstSection = false;
                const skip = UNCOMPRESSABLE_HEADER_SIZE - sections[0].offset;
                if (skip > 0) i += skip;
            }

            let aesCtr = null;
            if (section.cryptoType === 3 || section.cryptoType === 4) {
                aesCtr = new AesCtr(section.cryptoKey, section.cryptoCounter);
                aesCtr.seek(i);
            }

            while (i < end) {
                const chunkSize = Math.min(SECTION_CHUNK_SIZE, end - i);
                const chunk = await reader.read(chunkSize);
                if (!chunk || chunk.length === 0) break;

                let data = chunk;
                if (aesCtr) data = await aesCtr.decrypt(data);
                await writeChunk(data, i);

                i += chunk.length;
                decompressedOffset += chunk.length;
                if (progressCallback) progressCallback(decompressedOffset / ncaSize);
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
                decompressedSize = remainder;
            }
        }

        const compressedData = await this.reader.read(this.baseOffset + relOffset, compressedSize);

        if (compressedSize < decompressedSize) {
            this.currentBlock = await ZstdDecompressor.decompressBuffer(compressedData);
        } else {
            this.currentBlock = compressedData;
        }

        this.currentBlockId = blockId;
        return this.currentBlock;
    }

    async read(size) {
        const blockId = Math.floor(this.position / this.blockSize);
        if (blockId >= this.numberOfBlocks) return null;

        const blockOffset = this.position & (this.blockSize - 1);
        const block = await this.getBlock(blockId);
        const available = block.length - blockOffset;
        const toRead = Math.min(available, size);

        this.position += toRead;
        return sliceBytes(block, blockOffset, blockOffset + toRead);
    }

    close() {
        // No resources to release
    }
}

export { NCZDecompressor, DataReader, AdapterNCZReader, BufferReader, ChunkedBufferReader, FileDescriptorReader, READ_CHUNK_SIZE };
