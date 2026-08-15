// Verify the IVFC hash tree of a packed Program NCA against the stored update hashes.
//
// Reference (source-first): the hash chain layout follows hacPack's ivfc.c
// `ivfc_create_level()` (sources/hacPack/ivfc.c): each level hashes ceil(prev/BS)
// 0x4000-byte blocks into the next level; hash_data_size = blockSize*numBlocks for
// hash levels. Last partial block must be zero-padded to BS before hashing — Nintendo
// and yanu both store sha256(padded) for a partial block (verified: update lvl4[37011]
// = 40baee67…, yanu = f04eec97…). hacPack itself feeds only read bytes to sha_update,
// so the packer (fs/nca-pack.js buildIvfcHashTree) pads inline. Master hash = SHA-256
// of the raw level-0 hash table (hacPack ivfc.c: sha256(master_hash, level0)).

import fs from 'fs';
import { createHash } from 'crypto';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesXts } from '../crypto/aes-ops.mjs';

const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const keyBuf = Buffer.from(keys.header_key, 'hex');
const sh = b => createHash('sha256').update(b).digest('hex');
const BS = 0x4000;

function readNsp(path) {
    const buf = fs.readFileSync(path);
    const files = new PFS0(buf).getFiles();
    return { buf, files };
}
function progNca(nsp) {
    const e = nsp.files.find(f => f.name.endsWith('.nca') && !f.name.endsWith('.cnmt.nca') && f.size > 100000000);
    const data = nsp.buf.subarray(e.offset, e.offset + e.size);
    const hdr = Buffer.from(new AesXts(keyBuf).decrypt(data.subarray(0, 0xC00), 0));
    return { e, data, hdr };
}
// Hashes ceil(len/BS) blocks; the last partial block is zero-padded to BS
// (matches Nintendo/yanu: stored level-4 hash of a partial block == sha256(padded)).
function hashLevel(src) {
    const nBlocks = src.length === 0 ? 0 : Math.floor((src.length - 1) / BS) + 1;
    const out = Buffer.alloc(nBlocks * 32);
    const block = Buffer.alloc(BS);
    for (let i = 0; i < nBlocks; i++) {
        block.fill(0);
        const start = i * BS;
        const end = Math.min(start + BS, src.length);
        src.copy(block, 0, start, end);
        out.set(createHash('sha256').update(block).digest(), i * 32);
    }
    return out;
}

const input = process.argv[2] || '/tmp/update_e2e_out.nsp';
const expectedMaster = process.argv[3];
const nsp = readNsp(input);
const n = progNca(nsp);
const si = n.hdr.readUInt32LE(0x240 + 1 * 0x10) * 0x200;
const fh = n.hdr.subarray(0x600, 0x800);
const levels = [];
for (let i = 0; i < 6; i++) levels.push({ lo: Number(fh.readBigUInt64LE(0x18 + i * 0x18)), hds: Number(fh.readBigUInt64LE(0x18 + i * 0x18 + 8)) });

console.log(`nca: ${n.e.name} (${n.e.size})`);
console.log(`levels (size): ${levels.map(l => '0x' + l.hds.toString(16)).join(', ')}`);
console.log('');

let allOk = true;
for (let i = 4; i >= 0; i--) {
    const stored = Buffer.from(n.data.subarray(si + levels[i].lo, si + levels[i].lo + levels[i].hds));
    const src = i === 4
        ? Buffer.from(n.data.subarray(si + levels[5].lo, si + levels[5].lo + levels[5].hds))
        : Buffer.from(n.data.subarray(si + levels[i + 1].lo, si + levels[i + 1].lo + levels[i + 1].hds));
    const h = hashLevel(src);
    const realLen = h.length;
    const storedReal = stored.subarray(0, realLen);
    const tailZeros = stored.subarray(realLen).every(b => b === 0);
    const ok = h.equals(storedReal) && tailZeros;
    allOk = allOk && ok;
    console.log(`lvl${i}: hashes ${realLen / 32} of stored ${stored.length / 32} | real==stored: ${h.equals(storedReal)}, tail zeros: ${tailZeros} => ${ok ? 'OK' : 'FAIL'}`);
}

const master = sh(Buffer.from(n.data.subarray(si + levels[0].lo, si + levels[0].lo + levels[0].hds)));
console.log(`\nsha256(lvl0 full file) = ${master}`);
if (expectedMaster) console.log(`master match: ${master === expectedMaster}`);
console.log(`\nALL CHECKS: ${allOk ? 'PASS' : 'FAIL'}`);
