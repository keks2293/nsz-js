import { PFS0 } from './pfs0.js';
import { AesXts } from '../crypto/aesxts.mjs';
import { AesCtr } from '../crypto/aesctr.mjs';
import { AesEcb } from '../crypto/aes128.js';

const isNode = typeof process !== 'undefined' && process.versions?.node;

function hexToBytes(hex) {
    return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}



async function unwrapKeyBlock(keyBlockData, keys) {
    const kakHex = keys.keyAreaKeys[keys.masterKey]?.[0];
    if (!kakHex) throw new Error(`No key_area_key_application for masterKey ${keys.masterKey}`);

    const kak = hexToBytes(kakHex);
    if (isNode) {
        const { default: nodeCrypto } = await import('crypto');
        const ecb = nodeCrypto.createDecipheriv('aes-128-ecb', kak, null);
        ecb.setAutoPadding(false);
        return new Uint8Array(ecb.update(keyBlockData));
    }
    return new AesEcb(kak).decrypt(keyBlockData);
}

export class NCAHeader {
    static parse(buffer) {
        const arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        const view = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);

        const magic = String.fromCharCode(arr[0x200], arr[0x201], arr[0x202], arr[0x203]);
        if (magic !== 'NCA3' && magic !== 'NCA2') return null;

        const cryptoType = view.getUint8(0x206);
        const cryptoType2 = view.getUint8(0x220);
        const masterKey = Math.max(cryptoType, cryptoType2) - 1;

        const sectionTables = [];
        for (let i = 0; i < 4; i++) {
            const off = 0x240 + i * 0x10;
            sectionTables.push({
                offset: view.getUint32(off, true) * 0x200,
                endOffset: view.getUint32(off + 4, true) * 0x200
            });
        }

        return {
            magic,
            isGameCard: view.getUint8(0x204),
            contentType: view.getUint8(0x205),
            cryptoType,
            keyIndex: view.getUint8(0x207),
            size: Number(view.getBigUint64(0x208, true)),
            titleId: Array.from(arr.slice(0x210, 0x218)).reverse().map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase(),
            contentIndex: view.getUint32(0x218, true),
            sdkVersion: view.getUint32(0x21C, true),
            cryptoType2,
            rightsId: Array.from(arr.slice(0x230, 0x240)).map(b => b.toString(16).padStart(2, '0')).join(''),
            sectionTables,
            keyBlock: arr.slice(0x300, 0x340),
            masterKey: masterKey < 0 ? 0 : masterKey
        };
    }

    static getContentTypeName(type) {
        return ['PROGRAM', 'META', 'CONTROL', 'MANUAL', 'DATA', 'PUBLICDATA'][type] || 'UNKNOWN';
    }

    static getFsTypeName(type) {
        return { 0: 'NONE', 2: 'PFS0', 3: 'ROMFS' }[type] || 'UNKNOWN';
    }

    static getCryptoTypeName(type) {
        return ['ERROR', 'NONE', 'XTS', 'CTR', 'BKTR'][type] || 'UNKNOWN';
    }
}

export class BKTR {
    static parseSection(buffer, ncaOffset) {
        const arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        if (arr.length < 0x30) return null;
        const view = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
        const magic = String.fromCharCode(arr[16], arr[17], arr[18], arr[19]);
        if (magic !== 'BKTR') return null;
        return {
            bktrOffset: Number(view.getBigUint64(0, true)),
            bktrSize: Number(view.getBigUint64(8, true)),
            version: view.getUint32(20, true),
            entryCount: view.getUint32(24, true),
            ncaOffset
        };
    }
}

export class NCA {
    constructor(header, sections, sectionFilesystems, keys) {
        this.header = header;
        this.sections = sections;
        this.sectionFilesystems = sectionFilesystems;
        this.keys = keys;
    }

    [Symbol.iterator]() {
        return this.sectionFilesystems[Symbol.iterator]();
    }

    static async open(data, keys) {
        const arr = data instanceof Uint8Array ? data : new Uint8Array(data);

        if (!keys?.header_key) return null;

        const hdrKey = typeof keys.header_key === 'string' ? hexToBytes(keys.header_key) : keys.header_key;
        const hdr = new AesXts(hdrKey).decrypt(arr.subarray(0, Math.min(0xC00, arr.length)), 0);
        const header = NCAHeader.parse(hdr);
        if (!header) return null;

        const keyBlock = await unwrapKeyBlock(hdr.subarray(0x300, 0x340), { ...keys, masterKey: header.masterKey });

        const sections = [];
        const sectionFilesystems = [];

        for (let i = 0; i < 4; i++) {
            const st = header.sectionTables[i];
            const fsSize = st.endOffset - st.offset;
            if (fsSize <= 0) continue;

            const secKey = keyBlock.subarray(i * 16, (i + 1) * 16);
            if (secKey.every(b => b === 0)) continue;

            const secHdr = hdr.subarray(0x400 + i * 0x200, 0x600 + i * 0x200);
            const ivBytes = secHdr.subarray(0x140, 0x148);
            const counter = new Uint8Array(16);
            counter.set(ivBytes, 8);
            counter.reverse();

            const fsType = secHdr[0x3];
            const secStart = Number(new DataView(secHdr.buffer, secHdr.byteOffset).getBigUint64(0x40, true));

            const decrypted = await new AesCtr(secKey, counter)
                .decrypt(arr.subarray(st.offset, st.offset + fsSize));

            let pfs0 = null;
            if (fsType === 2) {
                try { pfs0 = new PFS0(decrypted.subarray(secStart)); } catch {}
            }

            sections.push({
                index: i,
                offset: st.offset,
                size: fsSize,
                fsType,
                cryptoType: secHdr[0x4],
                cryptoCounter: counter
            });

            if (pfs0) sectionFilesystems.push({ index: i, pfs0, decrypted });
        }

        return new NCA(header, sections, sectionFilesystems, keys);
    }

    getBuildId() {
        if (this.header.contentType !== 0) return null;
        try {
            const main = this.sectionFilesystems[0]?.pfs0;
            if (!main) return null;
            for (const f of main.getFiles()) {
                if (f.name === 'main') {
                    return Array.from(main._data.subarray(f.offset + 0x40, f.offset + 0x60))
                        .map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
                }
            }
        } catch {}
        return null;
    }

    async printInfo(out, maxDepth, indent = 0) {
        const tabs = '\t'.repeat(indent);
        const lvl = indent + 1;

        out(`${tabs}NCA Archive`);
        out(`${tabs}magic = ${this.header.magic}`);
        out(`${tabs}titleId = ${this.header.titleId}`);
        out(`${tabs}rightsId = ${this.header.rightsId}`);
        out(`${tabs}isGameCard = 0x${this.header.isGameCard.toString(16)}`);
        out(`${tabs}contentType = ${this.header.contentType} (${NCAHeader.getContentTypeName(this.header.contentType)})`);
        out(`${tabs}cryptoType = 1 (NONE)`);
        out(`${tabs}Size: ${this.header.size}`);
        out(`${tabs}crypto master key: ${this.header.cryptoType}`);
        out(`${tabs}crypto master key2: ${this.header.cryptoType2}`);
        out(`${tabs}key Index: ${this.header.keyIndex}`);
        if (this.header.keyBlock) {
            for (let i = 0; i < 4; i++) {
                const key = this.header.keyBlock.subarray(i * 16, (i + 1) * 16);
                if (key.some(b => b !== 0)) {
                    out(`${tabs}key Block: ${Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('')}`);
                }
            }
        }

        if (lvl < maxDepth && this.sections.length > 0) {
            out(`${tabs}Partitions:`);
        }

        for (const sf of this.sectionFilesystems) {
            const s = this.sections.find(x => x.index === sf.index);
            if (!s || lvl >= maxDepth) continue;

            out(`${tabs}\t${NCAHeader.getFsTypeName(s.fsType)}`);
            out(`${tabs}\tmagic = b'${s.fsType === 2 ? 'PFS0' : ''}'`);
            out(`${tabs}\tfsType = ${s.fsType}`);
            out(`${tabs}\tcryptoType = ${s.cryptoType} (${NCAHeader.getCryptoTypeName(s.cryptoType)})`);
            out(`${tabs}\tsize = 0x${s.size.toString(16)}`);
            out(`${tabs}\theaderSize = ${sf.pfs0.getHeaderSize()}`);
            out(`${tabs}\toffset = 0x${s.offset.toString(16)}`);
            out(`${tabs}\tcryptoCounter = ${Array.from(s.cryptoCounter).map(b => b.toString(16).padStart(2, '0')).join('')}`);
            out(`${tabs}\t\tFiles:`);
            for (const f of sf.pfs0.getFiles()) {
                out(`${tabs}\t\t${f.name}  0x${f.size.toString(16)} at 0x${f.offset.toString(16)}`);
                if (lvl + 2 < maxDepth && f.name.toLowerCase().endsWith('.nca')) {
                    const inner = await NCA.open(sf.pfs0._data.subarray(f.offset, f.offset + f.size), this.keys);
                    if (inner) {
                        out('');
                        await inner.printInfo(out, maxDepth, lvl + 1);
                    }
                }
            }
            out('');
        }

        const buildId = this.getBuildId();
        if (buildId) out(`${tabs}build Id: ${buildId}`);
    }
}

export function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export async function extractNCA(ncaData, ncaName, outputDir, keys, remainingDepth, extractRegex, adapter) {
    const a = adapter || {};
    const log = a.log || ((msg) => console.log(msg));
    const writeFile = a.writeFile || (() => { throw new Error('writeFile not implemented'); });
    const mkdir = a.mkdir || (() => { throw new Error('mkdir not implemented'); });
    const pathJoin = a.pathJoin || ((...p) => p.join('/'));
    const basename = a.basename || ((p, e) => { const n = p.split('/').pop(); return e ? n.replace(new RegExp(e.replace('.', '\\.') + '$'), '') : n; });
    const exists = a.exists || (() => false);

    const nca = await NCA.open(ncaData, keys);
    if (!nca) {
        log(`  [WARN] Could not extract NCA contents for ${ncaName}`);
        return;
    }

    const baseName = basename(ncaName, '.nca');

    for (const sf of nca.sectionFilesystems) {
        const sectionDir = pathJoin(outputDir, `${baseName}_section${sf.index}`);
        if (!exists(sectionDir)) mkdir(sectionDir);

        for (const f of sf.pfs0.getFiles()) {
            if (extractRegex && !f.name.match(extractRegex)) continue;
            log(`    [EXTRACT]  ${f.name}  ${formatBytes(f.size)}`);
            writeFile(pathJoin(sectionDir, f.name), sf.pfs0._data.subarray(f.offset, f.offset + f.size));

            if (remainingDepth > 2 && f.name.toLowerCase().endsWith('.nca')) {
                await extractNCA(sf.pfs0._data.subarray(f.offset, f.offset + f.size), f.name, sectionDir, keys, remainingDepth - 1, extractRegex, a);
            }
        }
    }
}
