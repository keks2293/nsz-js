import { PFS0Writer } from './pfs0.js';
import { NCZDecompressor, AdapterNCZReader } from './ncz.js';
import { sha256 } from '../crypto/sha256.js';

function verifyHash(hash, name, fileHashes, onLog) {
    const log = onLog || ((level, msg) => console.log(`  ${msg}`));
    if (fileHashes.size > 0) {
        if (fileHashes.has(hash)) {
            log('success', `[VERIFIED]   ${name} ${hash}`);
        } else {
            log('error', `[CORRUPTED]  ${name} ${hash}`);
            throw new Error(`Verification detected hash mismatch: ${name}`);
        }
    }
}

function verifyFileNameHash(hash, nczName, ncaName, onLog) {
    const log = onLog || ((level, msg) => console.log(`  ${msg}`));
    const fileNameHash = nczName.replace(/\.[^.]+$/, '').toLowerCase().slice(0, 32);
    if (hash.slice(0, 32) === fileNameHash) {
        log('success', `[VERIFIED]   ${ncaName} ${hash}`);
    } else {
        log('error', `[MISMATCH]   Filename starts with ${fileNameHash} but ${hash.slice(0, 32)} was expected`);
        throw new Error(`Verification detected hash mismatch: ${ncaName}`);
    }
}

export async function convertNSZStreaming(pfs0, keys, adapter, options, cnmtHashes = new Set()) {
    const { verify = false, fixPadding = false } = options;
    const files = pfs0.getFiles();

    const outputMeta = await collectOutputMeta(files, adapter, keys);

    const writer = new PFS0Writer(fixPadding, pfs0.stringTableSize);
    for (const m of outputMeta) {
        options.log('info', `[ADDING]     ${m.name} 0x${m.size.toString(16)} bytes to PFS0 at 0x${(writer.addpos || 0).toString(16)}`);
        writer.add(m.name, m.size);
    }
    const pfs0Header = writer.buildHeader();
    const header = pfs0Header.buffer;
    await adapter.write(0, header);

    let dataWritten = 0;
    const totalDataSize = outputMeta.reduce((s, m) => s + m.size, 0);
    const pct = (bytes) => bytes / totalDataSize;

    for (let idx = 0; idx < files.length; idx++) {
        const meta = outputMeta[idx];
        const f = files[idx];
        const writePos = pfs0Header.headerSize + writer.files[idx].offset;

        if (meta.isNcz) {
            options.log('info', `[EXISTS]     ${f.name}`);
            const hasher = verify ? options.createHash() : null;
            const nczReader = new AdapterNCZReader(adapter, meta.offset, meta.nczLen);
            const decomp = new NCZDecompressor(nczReader, keys);
            await decomp.decompress(
                (p) => options.progress(pct(dataWritten + meta.size * p), `Decompressing ${f.name}...`),
                async (chunk, offset) => {
                    if (hasher) hasher.update(chunk);
                    await adapter.write(writePos + offset, chunk);
                });
            if (hasher) {
                const hash = hasher.digest();
                options.log('info', `[NCA HASH]   ${hash}`);
                if (meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                    if (cnmtHashes.size > 0) {
                        verifyHash(hash, meta.name, cnmtHashes, options.log);
                    } else {
                        verifyFileNameHash(hash, f.name, meta.name, options.log);
                    }
                }
            }
        } else {
            options.log('info', `[EXISTS]     ${f.name}`);
            options.progress(pct(dataWritten), `Copying ${f.name}...`);
            const data = await adapter.read(meta.offset, meta.size);
            if (verify && meta.name.endsWith('.nca') && !meta.name.endsWith('.cnmt.nca')) {
                const hash = await sha256(data);
                options.log('info', `[NCA HASH]   ${hash}`);
                if (cnmtHashes.size > 0) {
                    verifyHash(hash, meta.name, cnmtHashes, options.log);
                } else {
                    verifyFileNameHash(hash, f.name, meta.name, options.log);
                }
            }
            await adapter.write(writePos, data);
        }

        dataWritten += meta.size;
        options.progress(pct(dataWritten), `File ${idx + 1}/${files.length} done`);
    }

    return { headerSize: pfs0Header.headerSize, totalDataSize };
}

async function collectOutputMeta(files, adapter, keys) {
    const outputMeta = [];
    for (const f of files) {
        const isNcz = f.name.toLowerCase().endsWith('.ncz');
        const outputName = isNcz ? f.name.slice(0, -4) + '.nca' : f.name;
        if (isNcz) {
            const headerReader = new AdapterNCZReader(adapter, f.offset, Math.min(f.size, 0x10000));
            const tmpDecomp = new NCZDecompressor(headerReader, keys);
            const { ncaSize } = await tmpDecomp.getSections();
            outputMeta.push({ name: outputName, size: ncaSize, isNcz: true, offset: f.offset, nczLen: f.size });
        } else {
            outputMeta.push({ name: outputName, size: f.size, isNcz: false, offset: f.offset });
        }
    }
    return outputMeta;
}

