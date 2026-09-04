import { PFS0Writer } from './pfs0.js';
import { buildAdapter, collectBlob } from './adapter.js';
import { parseNczSections, AdapterNCZReader } from './ncz.js';
import { decryptNcaHeader, readCnmtFromMeta } from './nca.js';
import { CNMT_ENTRY_TYPE } from './cnmt.js';
import { openContainer } from './container.js';
import { writeFromReader } from './convert-common.js';
import { formatBytes } from './format.js';
import { isMetaNca } from './nca-utils.js';

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
            if (!isMetaNca(header)) continue;
            let cnmt = null;
            try {
                cnmt = await readCnmtFromMeta(r.reader, e, header);
            } catch (_e) {}
            if (!cnmt) continue;

            for (const content of cnmt.contentEntries) {
                if (content.type === CNMT_ENTRY_TYPE.DELTA_FRAGMENT) {
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
            const ncaStem = f.outputName.slice(0, f.outputName.lastIndexOf('.'));

            if (seenNames.has(f.outputName)) continue;

            if (deltaFrags && deltaFrags.has(ncaStem)) {
                log('info', `[nodelta] excluding delta fragment ${f.outputName}`);
                continue;
            }

            seenNames.add(f.outputName);
            if (f.name.toLowerCase().endsWith('.ncz')) {
                // A .ncz member must be a real NCZ (NCZSECTN at 0 or 0x4000);
                // anything else (plain NCA or corrupt) errors in parseNczSections
                // — matching python nsz, which raises "No NCZSECTN found".
                const nczReader = new AdapterNCZReader(rReader, f.offset, f.size);
                const parsed = await parseNczSections(nczReader);
                const { ncaSize } = parsed;
                log('info', `[DECOMPRESS] ${f.name} -> ${f.outputName} (${formatBytes(ncaSize)})`);
                members.push({ kind: 'ncz', name: f.outputName, reader: rReader, offset: f.offset, srcLen: f.size, outLen: ncaSize, parsed });
                totalDataSize += ncaSize;
            } else {
                members.push({ kind: 'copy', name: f.outputName, reader: rReader, offset: f.offset, outLen: f.size });
                totalDataSize += f.size;
            }
        }
    }

    if (members.length === 0) {
        throw new Error('mergeNSP: no files found in inputs');
    }

    const writer = new PFS0Writer();
    for (const m of members) writer.add(m.name, m.outLen);
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
            (p) => progress((doneBefore + m.outLen * p) / totalDataSize, `${m.kind === 'ncz' ? 'Decompressing' : 'Copying'} ${m.name}...`));
        written = doneBefore + m.outLen;
    }

    const totalSize = headerSize + totalDataSize;
    log('info', `Merged NSP: ${members.length} members, ${totalSize} bytes`);
    if (output.memory) {
        return { size: totalSize, blob: collectBlob(adapter, totalSize), memberCount: members.length };
    }
    return { size: totalSize, memberCount: members.length };
}
