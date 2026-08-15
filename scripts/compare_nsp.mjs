import fs from 'node:fs';
import { PFS0 } from '../fs/pfs0.js';

function dumpPFS0(path) {
    const buf = fs.readFileSync(path);
    const pfs0 = new PFS0(buf);
    const files = pfs0.getFiles();
    console.log(`\n${path}`);
    console.log(`Total size: ${buf.length}`);
    for (const f of files) {
        console.log(`  ${f.name} (${f.size}, offset ${f.offset})`);
    }
}

dumpPFS0('/tmp/update_out/Stardew Valley [0100E65002BB8000][v0] (0.87 GB)_updated.nsp');
dumpPFS0('/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8000][v0] (0.87 GB) updated in yanu.nsp');
