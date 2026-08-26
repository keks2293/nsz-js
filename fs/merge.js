import { PFS0Writer } from './pfs0.js';
import { buildAdapter, collectBlob } from './adapter.js';
import { parseNczSections, AdapterNCZReader } from './ncz.js';
import { decryptNcaHeader, readCnmtFromMeta } from './nca.js';
import { openContainer } from './container.js';
import { writeFromReader } from './convert-common.js';

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
            const ncaStem = stem(f.outputName);

            if (seenNames.has(f.outputName)) continue;

            if (deltaFrags && deltaFrags.has(ncaStem)) {
                log('info', `[nodelta] excluding delta fragment ${f.outputName}`);
                continue;
            }

            seenNames.add(f.outputName);
            if (f.isNcz) {
                const nczReader = new AdapterNCZReader(rReader, f.offset, f.size);
                const parsed = await parseNczSections(nczReader);
                const { ncaSize, sections } = parsed;
                if (sections.length === 0) {
                    log('warn', `${f.name} is not compressed; copying as-is`);
                    members.push({ name: f.outputName, reader: rReader, src: i, offset: f.offset, size: f.size, isNcz: false });
                    totalDataSize += f.size;
                } else {
                    log('info', `[DECOMPRESS] ${f.name} -> ${f.outputName} (${formatBytes(ncaSize)})`);
                    members.push({ name: f.outputName, reader: rReader, src: i, offset: f.offset, size: ncaSize, isNcz: true, nczLen: f.size, parsed });
                    totalDataSize += ncaSize;
                }
            } else {
                members.push({ name: f.outputName, reader: rReader, src: i, offset: f.offset, size: f.size, isNcz: false });
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
        await writeFromReader(adapter, writePos, m,
            (p) => progress((doneBefore + m.size * p) / totalDataSize, `${m.isNcz ? 'Decompressing' : 'Copying'} ${m.name}...`));
        written = doneBefore + m.size;
    }

    const totalSize = headerSize + totalDataSize;
    log('info', `Merged NSP: ${members.length} members, ${totalSize} bytes`);
    if (output.memory) {
        return { size: totalSize, blob: collectBlob(adapter, totalSize), memberCount: members.length };
    }
    return { size: totalSize, memberCount: members.length };
}
