// Re-probe: BKTR patch tables use NORMAL crypto (zero nonce), layout is
// {u32 pad, u32 bucketCount, u64 totalSize, u64[] baseOffsets, ...buckets}
// section key for cryptoType 4 = AES-ECB-Decrypt(TitleKey, KeyArea[KeyIndex])
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { AesCtr, AesXts } from '../crypto/aes-ops.mjs';
import { AesEcb } from '../crypto/aes128.js';

const NCA = '/tmp/bktr_probe.nca';
const NSZ = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz';
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

const data = new Uint8Array(fs.readFileSync(NCA));
const header = decryptNcaHeader(data, keys);
const sec = header.sections.find(s => s.cryptoType === 4);
const secIdx = header.sections.indexOf(sec);
const hdrKey = typeof keys.header_key === 'string' ? Buffer.from(keys.header_key, 'hex') : keys.header_key;
const decHeader = new AesXts(hdrKey).decrypt(data.subarray(0, 0xC00), 0);
const fsHdr = decHeader.subarray(0x400 + secIdx * 0x200, 0x400 + secIdx * 0x200 + 0x200);
const dv = new DataView(fsHdr.buffer, fsHdr.byteOffset, fsHdr.byteLength);
const indirectAbs = sec.offset + Number(dv.getBigUint64(0x100, true));
const aesCtrExAbs = sec.offset + Number(dv.getBigUint64(0x120, true));

// key: titlekey from ticket -> AES-ECB decrypt raw KeyArea[KeyIndex]
let titlekey = null;
const nsz = fs.readFileSync(NSZ);
const fileCount = nsz.readUInt32LE(4);
const headerSize = 0x10 + fileCount * 0x18 + nsz.readUInt32LE(8);
const st = nsz.subarray(0x10 + fileCount * 0x18, headerSize);
for (let i = 0; i < fileCount; i++) {
    const nameOff = nsz.readUInt32LE(0x10 + i * 0x18 + 16);
    let n = ''; let j = nameOff;
    while (st[j] !== 0) n += String.fromCharCode(st[j++]);
    if (!n.toLowerCase().endsWith('.tik')) continue;
    const off = Number(nsz.readBigUInt64LE(0x10 + i * 0x18)) + headerSize;
    const size = Number(nsz.readBigUInt64LE(0x10 + i * 0x18 + 8));
    const tik = nsz.subarray(off, off + size);
    const kek = Buffer.from(keys.titlekek_02 || keys.titleKeks[2], 'hex');
    titlekey = new AesEcb(kek).decrypt(Buffer.from(tik.subarray(0x180, 0x190)));
    break;
}
const keyArea = data.subarray(0x300, 0x340);
const keysToTry = {
    'AesEcb(titlekey).dec(keyArea[0])': new AesEcb(titlekey).decrypt(keyArea.subarray(0, 0x10)),
    'AesEcb(titlekey).dec(keyArea[1])': new AesEcb(titlekey).decrypt(keyArea.subarray(0x10, 0x20)),
    'AesEcb(titlekey).dec(keyArea[2])': new AesEcb(titlekey).decrypt(keyArea.subarray(0x20, 0x30)),
    'titleKeyDec(nca.js)': header.titleKeyDec,
};
const noncesToTry = {
    'zeros(normal)': new Uint8Array(8),
    'raw': new Uint8Array(fsHdr.subarray(0x140, 0x148)),
    'reversed': new Uint8Array(fsHdr.subarray(0x140, 0x148)).reverse(),
};

function looksSane(name, dec, abs) {
    const bv = new DataView(dec.buffer, dec.byteOffset, dec.byteLength);
    const nBuckets = bv.getUint32(4, true);
    const totalSize = bv.getBigUint64(8, true);
    const firstBase = bv.getBigUint64(0x10, true);
    const sane = nBuckets > 0 && nBuckets < 0x10000 && totalSize > 0n && totalSize < 0x1000000000n;
    console.log(`${name}: nBuckets=${nBuckets} totalSize=${totalSize} firstBase=${firstBase} ${sane ? '*** SANE ***' : ''}`);
    return sane;
}

for (const [kn, key] of Object.entries(keysToTry)) {
    for (const [nn, nonce] of Object.entries(noncesToTry)) {
        const aes = new AesCtr(key, nonce);
        aes.seek(indirectAbs);
        const dec = await aes.decrypt(data.subarray(indirectAbs, indirectAbs + 0x8000));
        const ok = looksSane(`INDIRECT key=${kn} nonce=${nn}`, dec, indirectAbs);
        if (ok) {
            console.log('  key hex:', Buffer.from(key).toString('hex'), 'nonce hex:', Buffer.from(nonce).toString('hex'));
            const bv = new DataView(dec.buffer, dec.byteOffset, dec.byteLength);
            for (let b = 0; b < Math.min(bv.getUint32(4, true), 2); b++) {
                const bo = 0x4000 + b * 0x4000;
                const bd = dec.subarray(bo, bo + 0x40);
                const rdv = new DataView(bd.buffer, bd.byteOffset, bd.byteLength);
                console.log(`  bucket ${b}: nEntries=${rdv.getUint32(4, true)} endOffset=${rdv.getBigUint64(8, true)}`);
                for (let i = 0; i < 3; i++) {
                    const e = 0x10 + i * 0x18;
                    console.log(`    entry ${i}: patched=${rdv.getBigUint64(e, true)} source=${rdv.getBigUint64(e + 8, true)} fromPatch=${rdv.getUint32(e + 0x10, true)}`);
                }
            }
        }
    }
}
