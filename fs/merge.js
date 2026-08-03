import { PFS0, PFS0Writer } from './pfs0.js';
import { buildAdapter, collectBlob, copyRange } from './adapter.js';
import { XCIReader } from './xci.js';

async function openContainer(r) {
    const magic = await r.reader.read(0, 4);
    const m = String.fromCharCode(magic[0], magic[1], magic[2], magic[3]);
    if (m === 'PFS0') {
        const pfs0 = await PFS0.open(r.reader);
        return { kind: 'pfs0', entries: pfs0.getFiles() };
    }
    let head = await r.reader.read(0x100, 4);
    let isHead = String.fromCharCode(head[0], head[1], head[2], head[3]) === 'HEAD';
    if (!isHead) {
        head = await r.reader.read(0x1100, 4);
        isHead = String.fromCharCode(head[0], head[1], head[2], head[3]) === 'HEAD';
    }
    if (isHead) {
        const xci = new XCIReader(r.reader);
        await xci.parse();
        const entries = await xci.getSecureFiles();
        if (entries.length === 0) {
            throw new Error(`mergeNSP: no secure partition files found in ${r.name}`);
        }
        return { kind: 'xci', entries };
    }
    throw new Error(`mergeNSP: unsupported container in ${r.name} (magic ${m})`);
}

export async function mergeNSP(readers, output, options = {}) {
    const { log = () => {}, progress = () => {} } = options;

    if (!Array.isArray(readers) || readers.length < 2) {
        throw new Error('mergeNSP: at least two NSP/XCI inputs are required');
    }

    const members = [];
    const seenNames = new Set();
    let totalDataSize = 0;

    for (let i = 0; i < readers.length; i++) {
        const r = readers[i];
        const { kind, entries } = await openContainer(r);
        log('info', `Reading ${r.name}: ${entries.length} entries (${kind})`);
        for (const f of entries) {
            if (seenNames.has(f.name)) continue;
            seenNames.add(f.name);
            members.push({ name: f.name, src: i, offset: f.offset, size: f.size });
            totalDataSize += f.size;
        }
    }

    if (members.length === 0) {
        throw new Error('mergeNSP: no files found in inputs');
    }

    const writer = new PFS0Writer();
    for (const m of members) writer.add(m.name, m.size);
    const header = writer.buildHeader();
    const headerSize = header.headerSize;

    const read = async () => {
        throw new Error('mergeNSP: source data is read from the source readers directly');
    };
    const adapter = await buildAdapter(output, read, { log, progress });
    await adapter.write(0, header.buffer);

    let written = 0;
    for (let i = 0; i < members.length; i++) {
        const m = members[i];
        const writePos = headerSize + writer.files[i].offset;
        await copyRange(
            readers[m.src].reader,
            m.offset,
            m.size,
            (pos, data) => adapter.write(writePos + pos, data),
            (n) => {
                written += n;
                progress(written / totalDataSize, `Copying ${m.name}...`);
            },
        );
    }

    const totalSize = headerSize + totalDataSize;
    if (output.memory) {
        return { size: totalSize, blob: collectBlob(adapter, totalSize), memberCount: members.length };
    }
    return { size: totalSize, memberCount: members.length };
}
