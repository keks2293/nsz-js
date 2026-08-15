#!/usr/bin/env node

import fs from 'fs';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { decryptNcaHeader, readCnmtFromMeta } from '../fs/nca.js';

function stem(name) {
    const dot = name.lastIndexOf('.');
    return dot === -1 ? name : name.slice(0, dot);
}

function hex(b) {
    return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

class FdReader {
    constructor(fd, size) {
        this.fd = fd;
        this._length = size;
    }
    get length() { return this._length; }
    async read(offset, size) {
        const buf = Buffer.allocUnsafe(size);
        const n = fs.readSync(this.fd, buf, 0, size, offset);
        return new Uint8Array(buf.buffer, buf.byteOffset, n);
    }
}

const NCA_HEADER_TYPES = {
    0: 'Program', 1: 'Meta', 2: 'Control', 3: 'Manual', 4: 'Data', 5: 'PublicData',
};

const CNMT_CONTENT_TYPES = {
    0: 'Meta', 1: 'Program', 2: 'Data', 3: 'Control',
    4: 'HtmlDocument', 5: 'LegalInformation', 6: 'DeltaFragment',
};

async function inspectFile(filePath, keys) {
    const size = fs.statSync(filePath).size;
    const fd = fs.openSync(filePath, 'r');
    const reader = new FdReader(fd, size);
    console.log(`\n===== ${filePath} (${size} bytes) =====`);

    const magic = await reader.read(0, 4);
    const m = String.fromCharCode(magic[0], magic[1], magic[2], magic[3]);
    if (m !== 'PFS0') {
        console.log(`  magic ${m} - not a PFS0 container, skipping`);
        fs.closeSync(fd);
        return;
    }

    const pfs0 = await PFS0.open(reader);
    const files = pfs0.getFiles();
    console.log(`  ${files.length} entries`);

    let deltas = 0;
    for (const f of files) {
        const lower = f.name.toLowerCase();
        if (!lower.endsWith('.nca') && !lower.endsWith('.ncz')) continue;
        let header = null;
        try {
            header = decryptNcaHeader(await reader.read(f.offset, Math.min(f.size, 0xC00)), keys);
        } catch (e) { /* ignore */ }
        if (!header) {
            console.log(`  [!!] ${f.name}: header not decryptable (delta fragment or bad keys?)`);
            continue;
        }
        const isMeta = lower.endsWith('.cnmt.nca') || lower.endsWith('.cnmt.ncz');
        let cnmtInfo = '';
        if (isMeta && header.contentType === 1) {
            try {
                const cnmt = await readCnmtFromMeta(reader, f, header);
                if (cnmt) {
                    const entries = cnmt.contentEntries.map(c => {
                        const typeName = CNMT_CONTENT_TYPES[c.type] ?? `type${c.type}`;
                        if (c.type === 6) deltas++;
                        return `    ${c.ncaId} ${typeName} (${c.size} bytes)`;
                    }).join('\n');
                    cnmtInfo = ` v${cnmt.version} titleType=${cnmt.titleType}\n${entries}`;
                } else {
                    cnmtInfo = ' (CNMT parse failed)';
                }
            } catch (e) {
                cnmtInfo = ` (CNMT error: ${e.message})`;
            }
        }
        console.log(`  ${f.name}: titleId=${header.titleId} contentIndex=${header.contentIndex} contentType=${NCA_HEADER_TYPES[header.contentType] ?? header.contentType}${cnmtInfo}`);
    }
    fs.closeSync(fd);
    console.log(deltas > 0 ? `  >>> ${deltas} DELTA FRAGMENT content entries found` : '  no delta fragments');
}

async function main() {
    const args = process.argv.slice(2);
    if (args.length === 0) {
        console.log('Usage: node inspect_entries.mjs <file.nsp|file.nsz> [...]');
        process.exit(1);
    }
    const keyText = fs.readFileSync('../static/prod.keys', 'utf-8');
    const keys = KeysParser.parse(keyText);
    console.log('Keys loaded from ../static/prod.keys');
    for (const f of args) await inspectFile(f, keys);
}

main().catch(e => { console.error(e); process.exit(1); });
