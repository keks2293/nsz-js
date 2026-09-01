// Container detection/opening: identify whether an input is an NSP/NSZ
// (PFS0) or an XCZ (XCI) and return its top-level file entries.

import { PFS0 } from './pfs0.js';
import { XCIReader } from './xci.js';

// Enrich a PFS0/XCI entry with its output member name (nsz/xcz → nca).
function enrichEntry(e) {
    return { ...e, outputName: e.name.toLowerCase().endsWith('.ncz') ? e.name.replace(/\.ncz$/i, '.nca') : e.name };
}

// r = { reader, name }. Returns { kind: 'pfs0'|'xci', entries }.
// Each entry has { name, offset, size, outputName }.
export async function openContainer(r) {
    const magic = await r.reader.read(0, 4);
    const m = String.fromCharCode(magic[0], magic[1], magic[2], magic[3]);
    if (m === 'PFS0') {
        const pfs0 = await PFS0.open(r.reader);
        return { kind: 'pfs0', entries: pfs0.getFiles().map(enrichEntry) };
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
            throw new Error(`no secure partition files found in ${r.name}`);
        }
        return { kind: 'xci', entries: entries.map(enrichEntry) };
    }
    throw new Error(`unsupported container in ${r.name} (magic ${m})`);
}
