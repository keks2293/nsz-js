import { PFS0, PFS0Writer } from './pfs0.js';
import { buildAdapter, collectBlob, copyRange } from './adapter.js';
import { XCIReader } from './xci.js';
import { NCZDecompressor, AdapterNCZReader, parseNczSections } from './ncz.js';
import { decryptNcaHeader, readCnmtFromMeta, FsType } from './nca.js';

function stem(name) {
    const dot = name.lastIndexOf('.');
    return dot === -1 ? name : name.slice(0, dot);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

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
    const { log = () => {}, progress = () => {}, nodelta = false, keys = null } = options;

    if (!Array.isArray(readers) || readers.length < 2) {
        throw new Error('mergeNSP: at least two NSP/XCI inputs are required');
    }

    if (nodelta && !keys) {
        throw new Error('mergeNSP: nodelta requires keys (--keys / keys file) to read CNMT metadata');
    }

    // Collect delta fragment ncaIds when nodelta is enabled
    const deltaFrags = nodelta && keys ? new Set() : null;

    // Phase 1: parse CNMTs to collect delta fragments (if nodelta) and gather entries
    const allEntries = [];
    for (let i = 0; i < readers.length; i++) {
        const r = readers[i];
        const { kind, entries } = await openContainer(r);
        allEntries.push({ inputIndex: i, reader: r.reader, entries, kind });
        log('info', `Reading ${r.name}: ${entries.length} entries (${kind})`);

        if (!deltaFrags) continue;

        for (const e of entries) {
            const lower = e.name.toLowerCase();
            if (!lower.endsWith('.cnmt.nca')) continue;
            let header = null;
            try {
                const raw = await r.reader.read(e.offset, Math.min(e.size, 0xC00));
                header = decryptNcaHeader(raw, keys);
            } catch (_e) {}
            if (!header || header.contentType !== 1) continue;
            let cnmt = null;
            try {
                cnmt = await readCnmtFromMeta(r.reader, e, header);
            } catch (_e) {}
            if (!cnmt) continue;

            for (const content of cnmt.contentEntries) {
                if (content.type === 6) {
                    deltaFrags.add(content.ncaId);
                }
            }
        }
    }

    // Phase 2: build member list
    const members = [];
    const seenNames = new Set();
    let totalDataSize = 0;

    for (const inputInfo of allEntries) {
        const i = inputInfo.inputIndex;
        const rReader = inputInfo.reader;
        const entries = inputInfo.entries;

        for (const f of entries) {
            const isNcz = f.name.toLowerCase().endsWith('.ncz');
            const outputName = isNcz ? f.name.slice(0, -4) + '.nca' : f.name;
            const ncaStem = stem(outputName);

            if (seenNames.has(outputName)) continue;

            if (deltaFrags && deltaFrags.has(ncaStem)) {
                log('info', `[nodelta] excluding delta fragment ${outputName}`);
                continue;
            }

            seenNames.add(outputName);
            if (isNcz) {
                const nczReader = new AdapterNCZReader(rReader, f.offset, f.size);
                const parsed = await parseNczSections(nczReader);
                const { ncaSize, sections } = parsed;
                if (sections.length === 0) {
                    log('warn', `${f.name} is not compressed; copying as-is`);
                    members.push({ name: outputName, src: i, offset: f.offset, size: f.size, isNcz: false });
                    totalDataSize += f.size;
                } else {
                    log('info', `[DECOMPRESS] ${f.name} -> ${outputName} (${formatBytes(ncaSize)})`);
                    members.push({ name: outputName, src: i, offset: f.offset, size: ncaSize, isNcz: true, nczLen: f.size, parsed });
                    totalDataSize += ncaSize;
                }
            } else {
                members.push({ name: outputName, src: i, offset: f.offset, size: f.size, isNcz: false });
                totalDataSize += f.size;
            }
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
        const doneBefore = written;
        if (m.isNcz) {
            const nczReader = new AdapterNCZReader(readers[m.src].reader, m.offset, m.nczLen);
            const decomp = new NCZDecompressor(nczReader);
            await decomp.decompress(
                (p) => progress((doneBefore + m.size * p) / totalDataSize, `Decompressing ${m.name}...`),
                (chunk, offset) => adapter.write(writePos + offset, chunk),
                m.parsed,
            );
        } else {
            await copyRange(
                readers[m.src].reader,
                m.offset,
                m.size,
                (pos, data) => adapter.write(writePos + pos, data),
                (n) => progress((doneBefore + n) / totalDataSize, `Copying ${m.name}...`),
            );
        }
        written = doneBefore + m.size;
    }

    const totalSize = headerSize + totalDataSize;
    if (output.memory) {
        return { size: totalSize, blob: collectBlob(adapter, totalSize), memberCount: members.length };
    }
    return { size: totalSize, memberCount: members.length };
}
