import { AesCtr, aesBackend } from '../crypto/aes-ops.mjs';
import { decompressBlock, decompressStream } from '../crypto/zstd.js';
import { markPump } from './debug-trace.js';
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

async function parseNczSections(reader) {
    if (reader._nczParsed) return reader._nczParsed;

    const magicBytes = await reader.read(0, 8);
    const magic = bytesToAscii(magicBytes, 0, 8);
    console.log('[NCZ] magic at offset 0:', JSON.stringify(magic));

    let nczhdrOffset = 0;
    let ncaHeader = null;
    if (magic !== 'NCZSECTN') {
        const magicAt4000Bytes = await reader.read(UNCOMPRESSABLE_HEADER_SIZE, 8);
        const magicAt4000 = bytesToAscii(magicAt4000Bytes, 0, 8);
        console.log('[NCZ] magic at offset 0x4000:', JSON.stringify(magicAt4000));
        if (magicAt4000 === 'NCZSECTN') {
            console.log('[NCZ] NCA header detected at offset 0, NCZSECTN at 0x4000');
            ncaHeader = await reader.read(0, UNCOMPRESSABLE_HEADER_SIZE);
            nczhdrOffset = UNCOMPRESSABLE_HEADER_SIZE;
        } else {
            if (magic.startsWith('\x78') || magic.startsWith('N')) {
                console.log('[NCZ] Detected NCA file (not compressed NCZ)');
                const dataLen = reader.length;
                return { sections: [], ncaSize: dataLen, headerEnd: 0, ncaHeader: null };
            }
            throw new Error(`Invalid NCZ magic: ${magic} (at 0) / ${magicAt4000} (at 0x4000)`);
        }
    }

    let offset = nczhdrOffset + 8;
    const sectionCountBytes = await reader.read(offset, 8);
    const sectionCount = Number(readBigUInt64LE(sectionCountBytes, 0));
    console.log('[NCZ] sectionCount:', sectionCount);
    offset += 8;

    const sections = [];
    for (let i = 0; i < sectionCount; i++) {
        const sectionData = await reader.read(offset, 64);
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

    const result = { sections, ncaSize, headerEnd: offset, ncaHeader };
    reader._nczParsed = result;
    return result;
}

class NCZDecompressor {
    constructor(data) {
        if (data instanceof DataReader) {
            this.reader = data;
        } else {
            this.reader = new BufferReader(data);
        }
    }

    async decompress(progressCallback = null, writeChunk = null, parsed = null) {
        const { sections, ncaSize, headerEnd, ncaHeader } = parsed ?? await parseNczSections(this.reader);
        console.log('[NCZ] sections:', sections.length, 'ncaSize:', ncaSize, 'headerEnd:', headerEnd);

        let useBlock = false;
        if (headerEnd < this.reader.length) {
            const magicBytes = await this.reader.read(headerEnd, 8);
            const magic = bytesToAscii(magicBytes, 0, 8);
            useBlock = magic === 'NCZBLOCK';
            console.log('[NCZ] compression mode:', useBlock ? 'block' : 'streaming');
        }

        if (writeChunk) {
            if (ncaHeader) await writeChunk(ncaHeader, 0);
        } else {
            const output = allocByte(ncaSize);
            if (ncaHeader) output.set(ncaHeader, 0);
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
                sectionAesCtrs.set(s, new AesCtr(s.cryptoKey, s.cryptoCounter, 0, aesBackend()));
            }
        }

        let sectionIdx = 0;
        let lastAesCtr = null;
        let lastDecryptEnd = -1;
        const processChunk = async (chunk, decompOffset) => {
            // Capture before writeChunk: a plaintext section's chunk can be
            // transferred (detached) by the SW adapter, zeroing .length.
            const chunkLen = chunk.length;
            let offset = 0;
            while (offset < chunkLen) {
                const ncaPos = decompOffset + offset;
                while (sectionIdx < sortedSections.length - 1 &&
                       ncaPos >= sortedSections[sectionIdx].offset + sortedSections[sectionIdx].size) {
                    sectionIdx++;
                }
                let aesCtr = null;
                let boundary = chunkLen;
                if (sectionIdx < sortedSections.length) {
                    const s = sortedSections[sectionIdx];
                    aesCtr = sectionAesCtrs.get(s) || null;
                    boundary = Math.min(chunkLen, offset + (s.offset + s.size - ncaPos));
                }
                const subSize = boundary - offset;
                let data = chunk.subarray(offset, offset + subSize);
                if (aesCtr) {
                    if (aesCtr !== lastAesCtr || ncaPos !== lastDecryptEnd) {
                        aesCtr.seek(ncaPos);
                    }
                    markPump(`ncz: AES-CTR(${aesCtr._backend}) ${data.length}B @nca 0x${ncaPos.toString(16)}`);
                    data = await aesCtr.decrypt(data);
                    lastDecryptEnd = ncaPos + data.length;
                    lastAesCtr = aesCtr;
                }
                markPump(`ncz: writeChunk ${data.length}B @nca 0x${ncaPos.toString(16)}`);
                await writeChunk(data, ncaPos);
                offset += subSize;
                if (progressCallback) progressCallback((decompOffset + offset) / ncaSize);
            }
            return decompOffset + chunkLen;
        };

        let pos = headerEnd;
        let toRead = remaining;
        let decompOffset = UNCOMPRESSABLE_HEADER_SIZE;
        for await (const chunk of decompressStream(async () => {
            if (toRead <= 0) return null;
            const size = Math.min(toRead, READ_CHUNK_SIZE);
            markPump(`ncz: input read @0x${pos.toString(16)} len ${size}`);
            const data = await this.reader.read(pos, size);
            pos += data.length;
            toRead -= data.length;
            return data;
        }, (d) => { markPump(d); })) {
            decompOffset = await processChunk(chunk, decompOffset);
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
                aesCtr = new AesCtr(section.cryptoKey, section.cryptoCounter, 0, aesBackend());
                aesCtr.seek(i);
            }

            while (i < end) {
                const chunkSize = Math.min(SECTION_CHUNK_SIZE, end - i);
                markPump(`ncz[block]: read @nca 0x${i.toString(16)}`);
                const chunk = await reader.read(chunkSize);
                if (!chunk || chunk.length === 0) break;
                // Capture before writeChunk: for plaintext sections data === chunk,
                // and the SW adapter transfers it (detached .length would stall i).
                const chunkLen = chunk.length;

                if (aesCtr) markPump(`ncz[block]: AES-CTR ${chunkLen}B @nca 0x${i.toString(16)}`);
                const data = aesCtr ? await aesCtr.decrypt(chunk) : chunk;
                markPump(`ncz[block]: writeChunk ${data.length}B @nca 0x${i.toString(16)}`);
                await writeChunk(data, i);

                i += chunkLen;
                decompressedOffset += chunkLen;
                if (progressCallback) progressCallback(decompressedOffset / ncaSize);
            }
        }
    }


}

// Parse the NCZBLOCK size list into an independent block schedule: per-block
// relOffset (from baseOffset) and compressedSize in two parallel flat arrays,
// plus blockSize and the last (short) block's decompressedSize derived from
// decompressedSize % blockSize. Flat parallel arrays (not per-block objects)
// for cache locality and zero heap churn on huge NCZ. Pure — no I/O, no
// container globals — so a parallel block decoder can pair relOffsets[i] with
// sizes[i] as per-block jobs and run decompressBlock in workers.
function parseBlockSchedule(blockSizeExponent, numberOfBlocks, decompressedSize, sizeListData) {
    const blockSize = Math.pow(2, blockSizeExponent);
    const sizes = new Array(numberOfBlocks);
    const relOffsets = new Array(numberOfBlocks);
    let offset = 24 + numberOfBlocks * 4;
    for (let i = 0; i < numberOfBlocks; i++) {
        const compressedSize = readUInt32LE(sizeListData, i * 4);
        sizes[i] = compressedSize;
        relOffsets[i] = offset;
        offset += compressedSize;
    }
    const remainder = decompressedSize % blockSize;
    return { sizes, relOffsets, blockSize, remainder };
}

class AsyncBlockDecompressorReader {
    constructor(reader, baseOffset, blockSizeExponent, numberOfBlocks, decompressedSize, sizeListData) {
        this.reader = reader;
        this.baseOffset = baseOffset;
        this.currentBlock = null;
        this.currentBlockIndex = -1;

        this.schedule = parseBlockSchedule(blockSizeExponent, numberOfBlocks, decompressedSize, sizeListData);
    }

    async nextBlock() {
        const i = ++this.currentBlockIndex;
        const { sizes, relOffsets, blockSize, remainder } = this.schedule;
        if (i >= sizes.length) {
            this.currentBlock = null;
            return null;
        }

        const compressedSize = sizes[i];
        let decompressedSize = blockSize;
        if (i === sizes.length - 1 && remainder > 0) {
            decompressedSize = remainder;
        }

        const compressedData = await this.reader.read(this.baseOffset + relOffsets[i], compressedSize);

        // The raw/incompressible-vs-compressed decision is container knowledge:
        // a stored raw block fits in less space than the decompressed size, so
        // no zstd decode is needed. The raw fast path returns the bytes
        // directly (no Promise), so it stays free of a per-block microtask.
        if (compressedSize < decompressedSize) {
            this.currentBlock = await decompressBlock(compressedData);
        } else {
            this.currentBlock = compressedData;
        }

        return this.currentBlock;
    }

    async read(size) {
        if (!this.currentBlock) {
            await this.nextBlock();
        }
        if (!this.currentBlock) return null;

        const toRead = Math.min(this.currentBlock.length, size);
        const chunk = sliceBytes(this.currentBlock, 0, toRead);

        if (toRead < this.currentBlock.length) {
            this.currentBlock = this.currentBlock.subarray(toRead);
        } else {
            this.currentBlock = null;
        }

        return chunk;
    }

    close() {
        // No resources to release
    }
}

export { NCZDecompressor, DataReader, AdapterNCZReader, BufferReader, READ_CHUNK_SIZE, parseNczSections, parseBlockSchedule, AsyncBlockDecompressorReader };
