// Verify the CNMT-NCA rebuild recipe against real base+update NSZ files.
//
// Usage:
//   node verify_update.mjs <base.nsz> <update.nsz> [keys.txt]
//
// Checks (all must be MATCH on the ORIGINAL NCAs, then round-trips the rebuilt CNMT):
//   1. hblock @0x280 == sha256(decrypted header[0x400:0x600])
//   2. htable_hash @0x408 == sha256(decrypted media[0 : htableSize])
//   3. per-block htable[i] == sha256(dec[po + i*0x1000 : min(po+(i+1)*0x1000, po+pfs0Size)])  (truncated, NO padding)
//   4. rebuilt CNMT NCA: decrypt -> parse CNMT -> re-encrypt round trip, hashes valid
//
// This is the recipe implemented in fs/update.js.

import fs from 'fs';
import crypto from 'crypto';
import { KeysParser } from '../keys.js';
import { PFS0, PFS0Writer } from '../fs/pfs0.js';
import { AesXts as createAesXts, AesCtr } from '../crypto/aes-ops.mjs';
import { Cnmt } from '../fs/cnmt.js';
import { decryptNcaHeader } from '../fs/nca.js';

function hex(b, start = 0, end = b.length) { let s = ''; for (let i = start; i < end; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
function sha256(buf) { return crypto.createHash('sha256').update(Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength)).digest('hex'); }
class FdReader { constructor(fd) { this.fd = fd; } async read(offset, size) { const buf = Buffer.allocUnsafe(size); const n = fs.readSync(this.fd, buf, 0, size, offset); return new Uint8Array(buf.buffer, buf.byteOffset, n); } }

function tidBytesBE(tid) { const b = new Uint8Array(8); for (let i = 0; i < 8; i++) b[i] = parseInt(tid.substr(2 * (7 - i), 2), 16); return b; }
function u32le(v) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v, true); return b; }
function u16le(v) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, v, true); return b; }
function buildCnmt(tid, version, type, extHdr, entries, digest) {
    const cnmt = new Uint8Array(0x20 + extHdr.length + entries.length * 0x38 + digest);
    let o = 0;
    cnmt.set(tidBytesBE(tid), o); o += 8;
    cnmt.set(u32le(version), o); o += 4;
    cnmt[o++] = type;
    cnmt[o++] = 0x00;
    cnmt.set(u16le(extHdr.length), o); o += 2;
    cnmt.set(u16le(entries.length), o); o += 2;
    cnmt.set(u16le(0), o); o += 2;
    cnmt[o++] = 0x00;
    o += 3; o += 4; o += 4;
    cnmt.set(extHdr, o); o += extHdr.length;
    for (const ci of entries) { cnmt.set(ci, o); o += 0x38; }
    if (digest) cnmt.set(Buffer.from(sha256(cnmt.subarray(0, o)), 'hex'), o);
    return cnmt;
}
function contentInfo(hashHex, type, size) {
    const ci = new Uint8Array(0x38);
    ci.set(Buffer.from(hashHex, 'hex'), 0);
    ci.set(Buffer.from(hashHex.slice(0, 32), 'hex'), 0x20);
    const sz = new Uint8Array(8); new DataView(sz.buffer).setBigUint64(0, BigInt(size), true);
    ci.set(sz.subarray(0, 5), 0x30);
    ci[0x36] = type;
    return ci;
}

const [P_BASE, P_UPD, P_KEYS] = process.argv.slice(2);
if (!P_BASE || !P_UPD) {
    console.error('Usage: node verify_update.mjs <base.nsz> <update.nsz> [keys.txt]');
    process.exit(1);
}
const keys = KeysParser.parse(fs.readFileSync(P_KEYS || '../static/prod.keys', 'utf-8'));
const XTS_KEY = KeysParser.hexToBytes(keys.header_key);

// ---- 1. open base CNMT NCA ----
const fd = fs.openSync(P_BASE, 'r');
const reader = new FdReader(fd);
const pfs0 = await PFS0.open(reader);
const cf = pfs0.getFiles().find(x => x.name.endsWith('.cnmt.nca'));
if (!cf) { console.error('no .cnmt.nca in base'); process.exit(1); }
const rawNca = await reader.read(cf.offset, cf.size);
fs.closeSync(fd);
const header = decryptNcaHeader(rawNca.subarray(0, 0xC00), keys);
if (!header) { console.error('cannot decrypt base NCA header (keys?)'); process.exit(1); }
const section = header.sections[0];
console.log('base CNMT NCA size', rawNca.length, 'section media offset', section.offset, 'size', section.size);
console.log('pfs0Offset', section.sectionStart, 'pfs0Size', section.sectionSize);

const aesCtr = new AesCtr(header.titleKeyDec, section.cryptoCounter);
aesCtr.seek(section.offset);
const secDec = await aesCtr.decrypt(rawNca.subarray(section.offset, section.offset + section.size));
const dec = createAesXts(XTS_KEY).decrypt(rawNca.subarray(0, 0xC00), 0);

let allOk = true;
const po = section.sectionStart, ps = section.sectionSize;
const nblk = Math.ceil(ps / 0x1000);
for (let i = 0; i < nblk; i++) {
    const a = po + i * 0x1000, b = Math.min(a + 0x1000, po + ps);
    const stored = hex(secDec, i * 0x20, i * 0x20 + 0x20);
    const calc = sha256(secDec.subarray(a, b));
    if (calc !== stored) allOk = false;
    console.log('ORIG htable[' + i + ']', calc === stored ? 'MATCH' : 'MISMATCH', stored.slice(0, 16));
}
console.log('ORIG htable_hash@408 == sha256(media[0:0x20*nblk])?', sha256(secDec.subarray(0, 0x20 * nblk)) === hex(dec, 0x408, 0x428));
console.log('ORIG hblock@280 == sha256(dec[0x400:0x600])?', sha256(dec.subarray(0x400, 0x600)) === hex(dec, 0x280, 0x2A0));

// ---- 2. read update CNMT content entries ----
const updFd = fs.openSync(P_UPD, 'r');
const updReader = new FdReader(updFd);
const updPfs0 = await PFS0.open(updReader);
const updCf = updPfs0.getFiles().find(x => x.name.endsWith('.cnmt.nca'));
if (!updCf) { console.error('no .cnmt.nca in update'); process.exit(1); }
const updRaw = await updReader.read(updCf.offset, updCf.size);
const updHeader = decryptNcaHeader(updRaw.subarray(0, 0xC00), keys);
const updSection = updHeader.sections[0];
const upCtr = new AesCtr(updHeader.titleKeyDec, updSection.cryptoCounter);
upCtr.seek(updSection.offset);
const updDec = await upCtr.decrypt(updRaw.subarray(updSection.offset, updSection.offset + updSection.size));
const updCnmt = Cnmt.parse(updDec.subarray(updSection.sectionStart + 0x60));
fs.closeSync(updFd);
console.log('\nupdate CNMT: tid', updCnmt.titleId, 'ver', updCnmt.version, 'type 0x' + updCnmt.titleType.toString(16), 'entries', updCnmt.contentEntryCount);

// ---- 3. build new CNMT + PFS0 + media (recipe under test) ----
const BASE_TID = header.titleId;
const PATCH_TID = updCnmt.titleId;
const VERSION = updCnmt.version;
const appExt = new Uint8Array(0x10);
appExt.set(tidBytesBE(PATCH_TID), 0);
appExt.set(u32le(0x0C010000), 4);
const entries = [];
for (const e of updCnmt.contentEntries) {
    if (e.type === 6) continue;
    entries.push(contentInfo(e.hash, e.type, e.size));
}
const cnmt = buildCnmt(BASE_TID, VERSION, 0x80, appExt, entries, 0x20);
console.log('new CNMT size', cnmt.length, 'parsed back:', Cnmt.parse(cnmt).titleId, 'v' + Cnmt.parse(cnmt).version, 'entries', Cnmt.parse(cnmt).contentEntryCount);

const pw = new PFS0Writer(true);
pw.add('Application_' + BASE_TID.toLowerCase() + '.cnmt', cnmt.length);
const pfs0Header = pw.buildHeader();
const newPfs0 = new Uint8Array(pfs0Header.headerSize + cnmt.length);
newPfs0.set(pfs0Header.buffer, 0);
newPfs0.set(cnmt, pfs0Header.headerSize);

const newSecDec = new Uint8Array(section.size);
for (let i = 0; i < nblk; i++) {
    const a = i * 0x1000, b = Math.min(a + 0x1000, newPfs0.length);
    newSecDec.set(Buffer.from(sha256(newPfs0.subarray(a, b)), 'hex'), i * 0x20);
}
newSecDec.set(newPfs0, po);
const htableSize = nblk * 0x20;
const htableHash = sha256(newSecDec.subarray(0, htableSize));

const newDec = new Uint8Array(dec);
newDec.set(Buffer.from(htableHash, 'hex'), 0x408);
newDec.set(Buffer.from(sha256(newDec.subarray(0x400, 0x600)), 'hex'), 0x280);

// ---- 4. re-encrypt, round-trip verify ----
const xtsEnc = createAesXts(XTS_KEY);
const encHeader = xtsEnc.encrypt(newDec);
const ctrEnc = new AesCtr(header.titleKeyDec, section.cryptoCounter);
ctrEnc.seek(section.offset);
const encSec = await ctrEnc.encrypt(newSecDec);
const newNca = new Uint8Array(rawNca.length);
newNca.set(encHeader, 0);
newNca.set(encSec, section.offset);
console.log('\nnew NCA size', newNca.length, 'sha256', sha256(newNca));

const hdr2 = decryptNcaHeader(newNca.subarray(0, 0xC00), keys);
const s2 = hdr2.sections[0];
const c2 = new AesCtr(hdr2.titleKeyDec, s2.cryptoCounter);
c2.seek(s2.offset);
const sd2 = await c2.decrypt(newNca.subarray(s2.offset, s2.offset + s2.size));
const dec2 = createAesXts(XTS_KEY).decrypt(newNca.subarray(0, 0xC00), 0);
const p2 = new PFS0(sd2.subarray(s2.sectionStart));
const cf2 = p2.getFiles()[0];
console.log('\nVERIFY PFS0 file:', cf2.name, cf2.size, '(expect 248)');
const cn2 = Cnmt.parse(sd2.subarray(s2.sectionStart + cf2.offset, s2.sectionStart + cf2.offset + cf2.size));
console.log('VERIFY cnmt: type 0x' + cn2.titleType.toString(16), 'version', cn2.version, 'tid', cn2.titleId, 'entries', cn2.contentEntryCount);
for (const e of cn2.contentEntries) console.log('  type', e.type, 'id', e.ncaId.slice(0, 16), 'size', e.size, 'hash', e.hash.slice(0, 16));
console.log('VERIFY hblock@280 ok?', sha256(dec2.subarray(0x400, 0x600)) === hex(dec2, 0x280, 0x2A0));
console.log('VERIFY htable_hash@408 ok?', sha256(sd2.subarray(0, htableSize)) === hex(dec2, 0x408, 0x428));
let hok = true;
for (let i = 0; i < nblk; i++) {
    const a = po + i * 0x1000, b = Math.min(a + 0x1000, po + newPfs0.length);
    if (sha256(sd2.subarray(a, b)) !== hex(sd2, i * 0x20, i * 0x20 + 0x20)) hok = false;
}
console.log('VERIFY htable[0..n] ok?', hok);
console.log(allOk ? '\nALL ORIGINAL FORMULAS MATCH' : '\nSOME FORMULA MISMATCH');
