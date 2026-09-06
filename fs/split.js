import { PFS0, PFS0Writer } from './pfs0.js';
import { decryptNcaHeader, readCnmtFromMeta } from './nca.js';
import { Ticket } from './ticket.js';
import { buildAdapter, collectBlob, copyRange } from './adapter.js';
import { isMetaNca } from './nca-utils.js';
import { CNMT_ENTRY_TYPE } from './cnmt.js';

const META_TYPE_LABELS = { 0x80: 'base', 0x81: 'update', 0x82: 'dlc' };

const ZERO_RIGHTS_ID = '0'.repeat(32);

function stem(name) {
    const dot = name.lastIndexOf('.');
    return dot === -1 ? name : name.slice(0, dot);
}

function resolveTicket(g, byRightsId, byTitleId) {
    let tik = null;
    if (g.rightsId) {
        tik = byRightsId.get(g.rightsId);
    }
    if (!tik) {
        tik = byTitleId.get(g.titleId.toLowerCase());
    }
    return tik;
}

async function collectTickets(reader, ticketEntries, log = () => {}) {
    const byRightsId = new Map();
    const byTitleId = new Map();
    for (const e of ticketEntries) {
        try {
            const data = (await reader.read(e.offset, e.size)).slice();
            const t = Ticket.parse(data.buffer);
            byRightsId.set(t.rightsId.toLowerCase(), e);
            byTitleId.set(t.titleId.toLowerCase(), e);
        } catch (err) {
            log('warn', `Skipping malformed ticket: ${e.name}`);
        }
    }
    return { byRightsId, byTitleId };
}

export async function splitNSP(reader, keys, outputFactory, options = {}) {
    if (!keys || !keys.header_key) {
        throw new Error('splitNSP: keys are required to read NCA headers and CNMT metadata');
    }
    const { log = () => {}, progress = () => {} } = options;

    const pfs0 = await PFS0.open(reader);

    const ncaEntries = new Map();
    const cnmtXmlEntries = new Map();
    const ticketEntries = [];
    const certEntries = [];

    for (const f of pfs0.getFiles()) {
        const lower = f.name.toLowerCase();
        if (lower.endsWith('.nca')) ncaEntries.set(stem(f.name), f);
        else if (lower.endsWith('.cnmt.xml')) cnmtXmlEntries.set(stem(f.name), f);
        else if (lower.endsWith('.tik')) ticketEntries.push(f);
        else if (lower.endsWith('.cert')) certEntries.push(f);
    }

    if (ncaEntries.size === 0) {
        throw new Error('splitNSP: no .nca files found in the input');
    }

    const { byRightsId, byTitleId } = await collectTickets(reader, ticketEntries, log);

    const parsedHeaders = new Map();
    for (const [name, entry] of ncaEntries) {
        const raw = await reader.read(entry.offset, Math.min(entry.size, 0xC00));
        const header = decryptNcaHeader(raw, keys);
        if (header) {
            parsedHeaders.set(entry, header);
        } else {
            log('warn', `Could not decrypt NCA header: ${entry.name}`);
        }
    }

    const titleGroups = [];
    for (const [name, metaEntry] of ncaEntries) {
        const header = parsedHeaders.get(metaEntry);
        if (!isMetaNca(header)) continue;

        let cnmt = null;
        try {
            cnmt = await readCnmtFromMeta(reader, metaEntry, header);
        } catch (e) {
            log('warn', `Failed to parse CNMT from ${metaEntry.name}: ${e.message}`);
            continue;
        }
        if (!cnmt) {
            log('warn', `No CNMT found in ${metaEntry.name}`);
            continue;
        }

        const members = [metaEntry];
        const cnmtXml = cnmtXmlEntries.get(stem(metaEntry.name));
        if (cnmtXml) members.push(cnmtXml);

        const missing = [];
        for (const content of cnmt.contentEntries) {
            if (content.type === CNMT_ENTRY_TYPE.META || content.type === CNMT_ENTRY_TYPE.DELTA_FRAGMENT) continue;
            const ref = ncaEntries.get(content.ncaId);
            if (ref) {
                if (!members.includes(ref)) members.push(ref);
            } else {
                missing.push(content.ncaId);
            }
        }

        let rightsId = null;
        for (const e of members) {
            const h = parsedHeaders.get(e);
            if (h && h.rightsId && h.rightsId !== ZERO_RIGHTS_ID) {
                rightsId = h.rightsId;
                break;
            }
        }

        titleGroups.push({
            titleId: cnmt.titleId,
            version: cnmt.version,
            titleType: cnmt.titleType,
            members,
            missing,
            rightsId,
        });
    }

    if (titleGroups.length === 0) {
        throw new Error('splitNSP: no meta (.cnmt.nca) titles found — is this a valid merged NSP?');
    }

    const resolved = titleGroups.map((g) => {
        const tik = resolveTicket(g, byRightsId, byTitleId);
        let total = 0;
        for (const e of g.members) total += e.size;
        if (tik) {
            total += tik.size;
            const tikStem = stem(tik.name);
            for (const cert of certEntries) {
                if (stem(cert.name) === tikStem) total += cert.size;
            }
        }
        return { tik, total };
    });
    const grandTotal = resolved.reduce((s, r) => s + r.total, 0);

    const results = [];
    let processed = 0;
    for (let i = 0; i < titleGroups.length; i++) {
        const g = titleGroups[i];
        const { tik, total } = resolved[i];
        const label = META_TYPE_LABELS[g.titleType] ?? `0x${g.titleType.toString(16)}`;
        const outputName = `${g.titleId.toLowerCase()}_${label}_v${g.version}.nsp`;

        const outputObj = await outputFactory(g, i, outputName);
        if (!outputObj) {
            processed += total;
            continue;
        }

        if (g.rightsId && !byRightsId.get(g.rightsId)) {
            log('warn', `Protected title ${g.titleId} (rightsId=${g.rightsId}): no matching ticket in input`);
        }

        const writer = new PFS0Writer();
        const fileList = [];
        for (const e of g.members) {
            writer.add(e.name, e.size);
            fileList.push(e);
        }

        if (tik) {
            writer.add(tik.name, tik.size);
            fileList.push(tik);
            const tikStem = stem(tik.name);
            for (const cert of certEntries) {
                if (stem(cert.name) === tikStem) {
                    writer.add(cert.name, cert.size);
                    fileList.push(cert);
                }
            }
        }

        const header = writer.buildHeader();
        const headerSize = header.headerSize;
        const adapter = await buildAdapter(outputObj, async () => {
            throw new Error('splitNSP: source data is read from the input reader directly');
        }, { log, progress });
        await adapter.write(0, header.buffer);

        for (let j = 0; j < fileList.length; j++) {
            const e = fileList[j];
            const writePos = headerSize + writer.files[j].offset;
            await copyRange(
                reader,
                e.offset,
                e.size,
                (pos, data) => adapter.write(writePos + pos, data),
                (n) => {
                    processed += n;
                    progress(processed / grandTotal, `Writing (${i + 1}/${titleGroups.length}) ${outputName}...`);
                },
            );
        }

        if (outputObj.writable && typeof outputObj.writable.close === 'function') {
            await outputObj.writable.close();
        } else if (typeof outputObj.close === 'function') {
            await outputObj.close();
        }

        const size = headerSize + total;
        results.push({
            name: outputName,
            titleId: g.titleId,
            version: g.version,
            titleType: g.titleType,
            missing: g.missing,
            size,
            outPath: outputObj.outPath || null,
            blob: outputObj.memory ? collectBlob(adapter, size) : null,
        });
    }

    return { outputs: results, sourceEntryCount: pfs0.getFiles().length };
}
