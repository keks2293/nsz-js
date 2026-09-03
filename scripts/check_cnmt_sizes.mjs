#!/usr/bin/env node
// Check CNMT sizes vs actual NCA sizes
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { decryptNcaHeader, decryptNcaSection, parseCnmtFromDecryptedSection } from '../fs/nca.js';

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

function u32(b,o){return new DataView(b.buffer, b.byteOffset + o, 4).getUint32(0, true)}
function u64(b,o){return new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, true)}

const nspPath = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsp';
const yanuPath = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp';

async function readCnmt(nsp, label) {
    console.log(`\n=== ${label} ===`);
    const pfs0 = new PFS0(nsp);
    const files = pfs0.getFiles();
    
    // Find CNMT
    const cnmtFile = files.find(f => f.name.endsWith('.cnmt.nca'));
    if (!cnmtFile) { console.log('  No CNMT NCA'); return; }
    
    const cnmtRaw = nsp.subarray(cnmtFile.offset, cnmtFile.offset + cnmtFile.size);
    const header = decryptNcaHeader(cnmtRaw.subarray(0, 0xC00), keys);
    if (!header) { console.log('  Failed to decrypt CNMT header'); return; }
    
    const section = header.sections[0];
    if (!section) { console.log('  No section'); return; }
    
    const fsData = await decryptNcaSection(
        cnmtRaw.subarray(0xC00, 0xC00 + section.size),
        section
    );
    const cnmt = parseCnmtFromDecryptedSection(fsData, section);
    if (!cnmt) { console.log('  Failed to parse CNMT'); return; }
    
    console.log(`  titleId: ${cnmt.titleId} version: ${cnmt.version} type: 0x${cnmt.titleType.toString(16)}`);
    console.log(`  content entries: ${cnmt.contentEntries.length}`);
    
    for (const entry of cnmt.contentEntries) {
        const typeNames = {1:'Program', 2:'Data', 3:'Control', 4:'HtmlDocument', 5:'LegalInformation', 6:'DeltaFragment'};
        const sizeMB = (entry.size / 1048576).toFixed(1);
        console.log(`    ${typeNames[entry.type]||entry.type} ${entry.ncaId} size=${entry.size} (${sizeMB} MB)`);
    }
}

await readCnmt(fs.readFileSync(nspPath), 'BASE');
await readCnmt(fs.readFileSync(yanuPath), 'YANU');
