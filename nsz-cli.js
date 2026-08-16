#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { DataReader } from './fs/ncz.js';
import { KeysParser } from './keys.js';
import { convertNSZ as convertNSZFile } from './fs/nsz-convert.js';
import { convertXCZ as convertXCZFile } from './fs/xcz-convert.js';
import { extractContentHashMap } from './fs/cnmt-hashes.js';
import { mergeNSP as mergeNSPFile } from './fs/merge.js';
import { splitNSP as splitNSPFile } from './fs/split.js';
import { update as updateFile } from './fs/update.js';

class FileDescriptorReader extends DataReader {
    constructor(fd, baseOffset = 0, totalLength = null) {
        super();
        this.fd = fd;
        this.baseOffset = baseOffset;
        this._length = totalLength;
    }

    get length() {
        return this._length;
    }

    async read(offset, size) {
        const buf = Buffer.allocUnsafe(size);
        const bytesRead = fs.readSync(this.fd, buf, 0, size, this.baseOffset + offset);
        if (bytesRead < size) {
            return new Uint8Array(buf.buffer, buf.byteOffset, bytesRead);
        }
        return new Uint8Array(buf.buffer, buf.byteOffset, size);
    }
}

function makeExtractCnmtHashMap(keys) {
    return (cnmtData) => extractContentHashMap(cnmtData, keys);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function main() {
    const args = process.argv.slice(2);
    let inputPath = null;
    let outputDir = null;
    let keysPath = null;
    let fixPadding = false;
    let verify = true;
    let overwrite = false;
    let rmSource = false;
    let mergeMode = false;
    let splitMode = false;
    let updateMode = false;
    let nodelta = false;
    let keepNpdmAcidSig = false;
    let keepNpdmAcidKey = false;
    const positionals = [];

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--fix-padding' || args[i] === '-p') {
            fixPadding = true;
        } else if (args[i] === '--no-verify' || args[i] === '-nv') {
            verify = false;
        } else if (args[i] === '--help' || args[i] === '-h') {
            printUsage();
            process.exit(0);
        } else if (args[i] === '--keys' && i + 1 < args.length) {
            keysPath = args[++i];
        } else if (args[i] === '--merge') {
            mergeMode = true;
        } else if (args[i] === '--split') {
            splitMode = true;
        } else if (args[i] === '--update') {
            updateMode = true;
        } else if (args[i] === '--nodelta' || args[i] === '-n') {
            nodelta = true;
        } else if (args[i] === '--overwrite' || args[i] === '-w') {
            overwrite = true;
        } else if (args[i] === '--rm-source') {
            rmSource = true;
        } else if (args[i] === '--keep-npdm-acid-sig') {
            keepNpdmAcidSig = true;
        } else if (args[i] === '--keep-npdm-acid-key') {
            keepNpdmAcidKey = true;
        } else if ((args[i] === '-o' || args[i] === '--output') && i + 1 < args.length) {
            outputDir = args[++i];
        } else if (!args[i].startsWith('-')) {
            positionals.push(args[i]);
        }
    }

    function printUsage() {
        console.log('NSZ to NSP Converter');
        console.log('');
        console.log('Usage:');
        console.log('  node nsz-cli.js <input> [keys.txt] [options]        convert .nsz -> .nsp, .xcz -> .xci');
        console.log('  node nsz-cli.js --merge <nsp|nsz|xci|xcz> <nsp|nsz|xci|xcz> [...] [options] merge NSPs/NSZs/XCIs/XCZs into one .nsp (base+update+dlc)');
        console.log('  node nsz-cli.js --update <base> <update> [options]   physically apply update to base: one patched program NCA, single .nsp (requires --keys)');
        console.log('  node nsz-cli.js --split <nsp> [keys.txt] [options]  split a merged NSP into one .nsp per title');
        console.log('');
        console.log('Input formats:');
        console.log('  .nsz   -> .nsp');
        console.log('  .xcz   -> .xci');
        console.log('');
        console.log('Options:');
        console.log('  -o, --output <dir>   Output directory');
        console.log('  -w, --overwrite      Overwrite existing output files');
        console.log('  --rm-source          Delete input file(s) after successful operation');
        console.log('  --no-verify, -nv     Skip SHA256 verification [convert]');
        console.log('  --fix-padding, -p    Re-pad PFS0 header to 0x20 boundary [convert] (default: reuse input string-table size, matching Python nsz)');
        console.log('  --keys <file>        Keys file [split] (required for --split CNMT parsing; used by convert --verify for CNMT hash checks)');
        console.log('  -n, --nodelta        Exclude delta-fragment NCAs [merge]: drop NCAs referenced as DeltaFragment (ContentInfo type 6) in CNMTs (requires --keys)');
        console.log('  --update             Apply update to base physically: output a single .nsp with one patched program NCA');
        console.log('  --keep-npdm-acid-sig Keep the original ACID signature in main.npdm [--update] (hacpack --nozeronpdmsig); zeroed by default');
        console.log('  --keep-npdm-acid-key Keep the original ACID key in main.npdm [--update] (hacpack --nozeroacidkey); zeroed by default');
        console.log('');
    }

    if (mergeMode && splitMode) {
        console.error('Error: --merge and --split are mutually exclusive.');
        process.exit(1);
    }
    if (updateMode && (mergeMode || splitMode)) {
        console.error('Error: --update is mutually exclusive with --merge and --split.');
        process.exit(1);
    }

    if (mergeMode) {
        if (positionals.length < 2) {
            console.error('Error: --merge requires at least two .nsp/.nsz/.xci/.xcz inputs.');
            printUsage();
            process.exit(1);
        }
        for (const p of positionals) {
            const ext = path.extname(p).toLowerCase();
            if (ext !== '.nsp' && ext !== '.nsz' && ext !== '.xci' && ext !== '.xcz') {
                console.error(`Error: --merge inputs must be .nsp/.nsz/.xci/.xcz files: ${p}`);
                process.exit(1);
            }
        }
        await mergeNSPs(positionals, outputDir, overwrite, rmSource, nodelta, keysPath);
        return;
    }

    if (updateMode) {
        if (positionals.length !== 2) {
            console.error('Error: --update requires exactly two inputs (base + update).');
            printUsage();
            process.exit(1);
        }
        for (const p of positionals) {
            const ext = path.extname(p).toLowerCase();
            if (ext !== '.nsp' && ext !== '.nsz' && ext !== '.xci' && ext !== '.xcz') {
                console.error(`Error: --update inputs must be .nsp/.nsz/.xci/.xcz files: ${p}`);
                process.exit(1);
            }
        }
        await updateNSPs(positionals, outputDir, overwrite, rmSource, keysPath, keepNpdmAcidSig, keepNpdmAcidKey);
        return;
    }

    if (splitMode) {
        inputPath = positionals[0];
        if (positionals.length > 1) keysPath = keysPath || positionals[1];
        if (!inputPath) {
            console.error('Error: --split requires an .nsp input.');
            printUsage();
            process.exit(1);
        }
        const keys = await loadKeys(keysPath);
        if (!keys) {
            console.error('Error: --split requires a keys file (--keys <path> or ./static/prod.keys) to read NCA headers and CNMT metadata.');
            process.exit(1);
        }
        const input = openInputReader(inputPath);
        try {
            await splitNSP(input, inputPath, outputDir, keys, overwrite, rmSource);
        } finally {
            fs.closeSync(input.fd);
        }
        return;
    }

    inputPath = positionals[0];
    if (positionals.length > 1) keysPath = keysPath || positionals[1];

    if (!inputPath) {
        printUsage();
        process.exit(1);
    }

    const keys = await loadKeys(keysPath);
    if (!keys) console.log('Warning: No keys loaded - convert --verify CNMT hash checks will be skipped');

    const isXcz = inputPath.toLowerCase().endsWith('.xcz');
    const inStat = fs.statSync(inputPath);
    const inputSize = inStat.size;
    console.log('=== NSZ to NSP Converter ===');
    console.log(`Input: ${inputPath} (${formatBytes(inputSize)})`);

    const inputFd = fs.openSync(inputPath, 'r');
    const inReader = new FileDescriptorReader(inputFd, 0, inputSize);

    try {
        if (isXcz) {
            await convertXCZ(inReader, inputFd, inputPath, outputDir, keys, verify, overwrite, rmSource);
        } else {
            await convertNSZ(inReader, inputFd, inputPath, outputDir, keys, fixPadding, verify, overwrite, rmSource);
        }
    } finally {
        fs.closeSync(inputFd);
    }
}

async function loadKeys(keysPath) {
    let keys = null;
    const keysLocations = [
        keysPath,
        './static/prod.keys'
    ].filter(Boolean);

    for (const loc of keysLocations) {
        try {
            const keyText = fs.readFileSync(loc, 'utf-8');
            keys = KeysParser.parse(keyText);
            console.log(`Keys loaded from ${loc}`);
            break;
        } catch(e) {}
    }

    return keys;
}

function openInputReader(inputPath) {
    const inStat = fs.statSync(inputPath);
    const inputSize = inStat.size;
    console.log(`Input: ${inputPath} (${formatBytes(inputSize)})`);
    const fd = fs.openSync(inputPath, 'r');
    return { reader: new FileDescriptorReader(fd, 0, inputSize), fd, inputSize };
}

async function mergeNSPs(inputPaths, outputDir, overwrite, rmSource, nodelta, keysPath) {
    console.log('=== MERGE NSPs ===');
    const stem = path.basename(inputPaths[0], path.extname(inputPaths[0]));
    const outName = `${stem}_merged.nsp`;
    const outPath = outputDir ? path.join(outputDir, outName) : path.join(path.dirname(inputPaths[0]), outName);

    if (!overwrite && fs.existsSync(outPath)) {
        console.error(`Error: ${outPath} already exists. Use -w/--overwrite to overwrite.`);
        process.exit(1);
    }

    let keys = null;
    if (nodelta) {
        keys = await loadKeys(keysPath);
        if (!keys) {
            console.error(`Error: --nodelta requires a keys file (--keys <path> or ./static/prod.keys) to read CNMT metadata.`);
            process.exit(1);
        }
    }

    const fds = [];
    try {
        const readers = [];
        for (const p of inputPaths) {
            const st = fs.statSync(p);
            const fd = fs.openSync(p, 'r');
            fds.push(fd);
            readers.push({ name: p, reader: new FileDescriptorReader(fd, 0, st.size) });
        }

        const outputFd = fs.openSync(outPath, 'w');
        fds.push(outputFd);
        let result;
        try {
            result = await mergeNSPFile(readers, { fd: outputFd }, {
                log: (level, msg) => console.log(msg),
                progress: () => {},
                nodelta,
                keys,
            });
        } catch (e) {
            fs.closeSync(outputFd);
            try { fs.unlinkSync(outPath); } catch {}
            throw e;
        }

        console.log('');
        console.log('=== DONE ===');
        console.log(`Output: ${outPath} (${formatBytes(result.size)})`);
        console.log(`Members: ${result.memberCount} (deduplicated by name)`);
        if (nodelta && keys) console.log('Delta fragments: excluded (--nodelta)');

        if (rmSource) {
            for (const p of inputPaths) {
                fs.unlinkSync(p);
                console.log(`Deleted source: ${p}`);
            }
        }
    } finally {
        for (const fd of fds) {
            try { fs.closeSync(fd); } catch {}
        }
    }
}
async function updateNSPs(inputPaths, outputDir, overwrite, rmSource, keysPath, keepNpdmAcidSig, keepNpdmAcidKey) {

    console.log('=== UPDATE ===');
    const baseStem = path.basename(inputPaths[0], path.extname(inputPaths[0]));
    const outName = `${baseStem}_updated.nsp`;
    const outPath = outputDir ? path.join(outputDir, outName) : path.join(path.dirname(inputPaths[0]), outName);

    if (!overwrite && fs.existsSync(outPath)) {
        console.error(`Error: ${outPath} already exists. Use -w/--overwrite to overwrite.`);
        process.exit(1);
    }

    const keys = await loadKeys(keysPath);
    if (!keys) {
        console.error('Error: --update requires a keys file (--keys <path> or ./static/prod.keys) to decrypt CNMT metadata.');
        process.exit(1);
    }

    const fds = [];
    try {
        const readers = [];
        for (const p of inputPaths) {
            const st = fs.statSync(p);
            const fd = fs.openSync(p, 'r');
            fds.push(fd);
            readers.push({ name: p, reader: new FileDescriptorReader(fd, 0, st.size) });
        }

        const outputFd = fs.openSync(outPath, 'w');
        fds.push(outputFd);
        let result;
        try {
            result = await updateFile(readers, { fd: outputFd }, {
                log: (level, msg) => console.log(msg),
                progress: (p, msg) => {},
                keys,
                keepNpdmAcidSig,
                keepNpdmAcidKey,
            });
        } catch (e) {
            fs.closeSync(outputFd);
            try { fs.unlinkSync(outPath); } catch {}
            throw e;
        }

        console.log('');
        console.log('=== DONE ===');
        console.log(`Output: ${outPath} (${formatBytes(result.size)})`);
        console.log(`Members: ${result.memberCount}`);

        if (rmSource) {
            for (const p of inputPaths) {
                fs.unlinkSync(p);
                console.log(`Deleted source: ${p}`);
            }
        }
    } finally {
        for (const fd of fds) {
            try { fs.closeSync(fd); } catch {}
        }
    }
}

async function splitNSP(inFdInfo, inputPath, outputDir, keys, overwrite, rmSource) {
    console.log('=== SPLIT NSP ===');
    const outDir = outputDir || path.dirname(inputPath);
    fs.mkdirSync(outDir, { recursive: true });

    const created = [];
    let result;
    try {
        result = await splitNSPFile(inFdInfo.reader, keys, async (group, index, name) => {
            const outPath = path.join(outDir, name);
            if (!overwrite && fs.existsSync(outPath)) {
                console.log(`Skipping existing: ${outPath}`);
                return null;
            }
            const fd = fs.openSync(outPath, 'w');
            created.push({ fd, outPath });
            return { fd, outPath };
        }, {
            log: (level, msg) => console.log(msg),
            progress: () => {},
        });
    } finally {
        for (const c of created) {
            try { fs.closeSync(c.fd); } catch {}
        }
    }

    console.log('');
    console.log('=== DONE ===');
    for (const out of result.outputs) {
        console.log(`Output: ${out.outPath || out.name} (${formatBytes(out.size)})`);
        if (out.missing.length > 0) {
            console.log(`  Warning: ${out.missing.length} NCA(s) referenced by CNMT not found in input`);
        }
    }

    if (rmSource) {
        fs.unlinkSync(inputPath);
        console.log(`Deleted source: ${inputPath}`);
    }
}

async function convertXCZ(inReader, inputFd, inputPath, outputDir, keys, verify, overwrite, rmSource) {
    console.log(`[VERIFY NSZ] ${inputPath}`);
    console.log('Detected XCZ file');
    const outPath = outputDir ? path.join(outputDir, path.basename(inputPath).replace(/\.xcz$/i, '.xci')) : inputPath.replace(/\.xcz$/i, '.xci');
    console.log(`Output: ${outPath}`);

    if (!overwrite && fs.existsSync(outPath)) {
        console.error(`Error: ${outPath} already exists. Use -w/--overwrite to overwrite.`);
        process.exit(1);
    }

    const outputFd = fs.openSync(outPath, 'w');
    try {
        await convertXCZFile(inReader, { fd: outputFd }, {
            verify,
            log: (level, msg) => console.log(msg),
            progress: () => {},
            createHash: () => {
                const h = crypto.createHash('sha256');
                return { update: (d) => h.update(d), hex: () => h.digest('hex') };
            },
            extractCnmtHashMap: makeExtractCnmtHashMap(keys),
        });
    } catch (e) {
        fs.closeSync(outputFd);
        try { fs.unlinkSync(outPath); } catch {}
        throw e;
    }
    fs.closeSync(outputFd);

    const outStat = fs.statSync(outPath);
    console.log('');
    console.log('=== DONE ===');
    console.log(`Output: ${outPath} (${formatBytes(outStat.size)})`);

    if (rmSource) {
        fs.unlinkSync(inputPath);
        console.log(`Deleted source: ${inputPath}`);
    }
}

async function convertNSZ(inReader, inputFd, inputPath, outputDir, keys, fixPadding, verify, overwrite, rmSource) {
    const outPath = outputDir ? path.join(outputDir, path.basename(inputPath).replace(/\.nsz$/i, '.nsp')) : inputPath.replace(/\.nsz$/i, '.nsp');
    console.log(`[VERIFY NSZ] ${inputPath}`);
    console.log(`Output: ${outPath}`);

    if (!overwrite && fs.existsSync(outPath)) {
        console.error(`Error: ${outPath} already exists. Use -w/--overwrite to overwrite.`);
        process.exit(1);
    }

    const outputFd = fs.openSync(outPath, 'w');
    try {
        await convertNSZFile(inReader, { fd: outputFd }, {
            verify, fixPadding,
            log: (level, msg) => console.log(msg),
            progress: () => {},
            createHash: () => {
                const h = crypto.createHash('sha256');
                return { update: (d) => h.update(d), hex: () => h.digest('hex') };
            },
            extractCnmtHashMap: makeExtractCnmtHashMap(keys),
        });
    } catch (e) {
        fs.closeSync(outputFd);
        try { fs.unlinkSync(outPath); } catch {}
        throw e;
    }
    fs.closeSync(outputFd);

    const outStat = fs.statSync(outPath);
    console.log('');
    console.log('=== DONE ===');
    console.log(`Output: ${outPath} (${formatBytes(outStat.size)})`);

    if (rmSource) {
        fs.unlinkSync(inputPath);
        console.log(`Deleted source: ${inputPath}`);
    }
}

main().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
