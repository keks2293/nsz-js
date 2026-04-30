import fs from 'fs';
import crypto from 'crypto';

export class PFS0 {
    constructor(buffer) {
        this.buffer = buffer instanceof Buffer ? buffer : Buffer.from(buffer);
        this.files = [];
        this.parse();
    }

    parse() {
        const magic = this.buffer.slice(0, 4).toString('ascii');
        if (magic !== 'PFS0') {
            throw new Error(`Invalid PFS0 magic: ${magic}`);
        }

        const fileCount = this.buffer.readUInt32LE(4);
        const stringTableSize = this.buffer.readUInt32LE(8);

        const headerSize = 0x10 + fileCount * 0x18 + stringTableSize;
        
        const stringTableOffset = 0x10 + fileCount * 0x18;
        const stringTable = this.buffer.slice(stringTableOffset, stringTableOffset + stringTableSize);

        let stringEndOffset = stringTableSize;

        for (let i = fileCount - 1; i >= 0; i--) {
            const entryOffset = 0x10 + i * 0x18;
            const offset = Number(this.buffer.readBigUInt64LE(entryOffset));
            const size = Number(this.buffer.readBigUInt64LE(entryOffset + 8));
            const nameOffset = this.buffer.readUInt32LE(entryOffset + 16);

            let name = '';
            for (let j = nameOffset; j < stringEndOffset && stringTable[j] !== 0; j++) {
                name += String.fromCharCode(stringTable[j]);
            }

            stringEndOffset = nameOffset;

            this.files.push({
                name,
                offset: offset + headerSize,
                size,
                data: this.buffer.slice(offset + headerSize, offset + headerSize + size)
            });
        }

        this.files.reverse();
    }

    getFiles() {
        return this.files;
    }

    getHeaderSize() {
        return 0x10 + this.files.length * 0x18 + this.buffer.readUInt32LE(8);
    }
}

export class PFS0Writer {
    constructor() {
        this.files = [];
    }

    add(name, data) {
        this.files.push({ name, data: data instanceof Buffer ? data : Buffer.from(data) });
    }

    build() {
        const stringTable = this.files.map(f => f.name).join('\0') + '\0';
        const headerSize = 0x10 + this.files.length * 0x18 + stringTable.length;
        const paddingSize = (16 - (headerSize % 16)) % 16;
        const paddedHeaderSize = headerSize + paddingSize;

        let fileOffset = paddedHeaderSize;
        const entries = this.files.map(f => {
            const entry = {
                name: f.name,
                offset: fileOffset,
                size: f.data.length
            };
            fileOffset += f.data.length;
            return entry;
        });

        const totalSize = fileOffset;
        const output = Buffer.alloc(totalSize);

        output.write('PFS0', 0);
        output.writeUInt32LE(this.files.length, 4);
        output.writeUInt32LE(stringTable.length + paddingSize, 8);
        output.writeUInt32LE(0, 12);

        const relativeOffsetBase = paddedHeaderSize;
        let stringOffset = 0;

        for (let i = 0; i < entries.length; i++) {
            const entry = entries[i];
            const pos = 0x10 + i * 0x18;
            
            output.writeBigUInt64LE(BigInt(entry.offset - relativeOffsetBase), pos);
            output.writeBigUInt64LE(BigInt(entry.size), pos + 8);
            output.writeUInt32LE(stringOffset, pos + 16);
            output.writeUInt32LE(0, pos + 20);
            
            output.write(entry.name, 0x10 + entries.length * 0x18 + stringOffset);
            stringOffset += Buffer.byteLength(entry.name) + 1;
        }

        for (const entry of entries) {
            entry.data.copy(output, entry.offset);
        }

        return output;
    }
}