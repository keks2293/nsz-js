import { PFS0Writer, PFS0 } from './pfs0.js';
import { buildAdapter, collectBlob } from './adapter.js';
import { collectFileMetas, writeFromReader } from './convert-common.js';

async function convertNSZStreaming(pfs0, adapter, options, cnmtHashes = new Map()) {
    const { verify = false, fixPadding = false } = options;
    const files = pfs0.getFiles();

    const outputMeta = await collectFileMetas(files, adapter);

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

        options.log('info', `[EXISTS]     ${f.name}`);
        await writeFromReader(adapter, writePos,
            { ...meta, reader: adapter, outLen: meta.size },
            (p) => options.progress(pct(dataWritten + meta.size * p), `${meta.kind === 'ncz' ? 'Decompressing' : 'Copying'} ${meta.inputName}...`),
            { verify, createHash: options.createHash, cnmtHashMap: cnmtHashes, log: options.log });

        dataWritten += meta.size;
        options.progress(pct(dataWritten), `File ${idx + 1}/${files.length} done`);
    }

    return { headerSize: pfs0Header.headerSize, totalDataSize };
}

export async function convertNSZ(reader, output, options = {}) {
    const { verify = false, fixPadding = false, log = () => {}, progress = () => {}, createHash, extractCnmtHashMap } = options;

    const pfs0 = await PFS0.open(reader);

    const cnmtHashMap = new Map();
    if (extractCnmtHashMap) {
        for (const f of pfs0.getFiles()) {
            if (f.name.toLowerCase().endsWith('.cnmt.nca')) {
                const data = await reader.read(f.offset, f.size);
                const m = await extractCnmtHashMap(data);
                for (const [ncaId, hash] of m) cnmtHashMap.set(ncaId, hash);
            }
        }
    }

    const read = (offset, size) => reader.read(offset, size);
    const adapter = await buildAdapter(output, read, { log, progress, createHash });
    const result = await convertNSZStreaming(pfs0, adapter, {
        verify, fixPadding, log, progress, createHash,
    }, cnmtHashMap);

    const totalSize = result.headerSize + result.totalDataSize;
    if (output.memory) return { size: totalSize, blob: collectBlob(adapter, totalSize) };
    return { size: totalSize };
}
