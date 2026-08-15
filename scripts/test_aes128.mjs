import { AesEcb, AesCtrJS, AesXts } from '../crypto/aes128.js';

// Regression vectors for the software AES-128 primitives (js-fallback AES-CTR
// keystream, ECB block ops, XTS sector decrypt). Run: node test_aes128.mjs
//
// Fixed vectors are byte-identical to the prior reference implementation,
// captured before the allocation-free rewrite of aes128.js.

let pass = 0;
let fail = 0;
function check(name, got, expected) {
    const ok = Buffer.from(got).toString('hex') === expected;
    if (ok) { pass++; console.log('✅', name); }
    else {
        fail++;
        console.log('❌', name);
        console.log('   got     :', Buffer.from(got).toString('hex'));
        console.log('   expected:', expected);
    }
}
function assert(name, cond) {
    if (cond) { pass++; console.log('✅', name); }
    else { fail++; console.log('❌', name); }
}

const key16 = new Uint8Array(16);
for (let i = 0; i < 16; i++) key16[i] = (i * 13 + 7) & 0xff;
const key32 = new Uint8Array(32);
for (let i = 0; i < 32; i++) key32[i] = (i * 13 + 7) & 0xff;
const pt16 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

// 1. ECB single block (frontline encryptBlock path).
check('AesEcb.encrypt 16B', new AesEcb(key16).encrypt(pt16),
    '6392feebdb6e88538221a0964bc0ab6d');

// 2. encryptBlock must accept a caller-provided out buffer and return it.
{
    const e = new AesEcb(key16);
    const out = new Uint8Array(16).fill(0xee);
    const ret = e.encryptBlock(new Uint8Array(pt16), out);
    check('AesEcb.encryptBlock in-place out', out,
        '6392feebdb6e88538221a0964bc0ab6d');
    assert('encryptBlock returns passed out', ret === out);
}

// 3. encryptBlock without out allocates a fresh 16B buffer.
check('AesEcb.encryptBlock no-out alloc', new AesEcb(key16).encryptBlock(pt16),
    '6392feebdb6e88538221a0964bc0ab6d');

// 4. AesCtrJS keystream XOR at counter=0 (byte-identical to reference).
check('AesCtrJS(0, 32B 0xaa)', AesCtrJS(new AesEcb(key16), new Uint8Array(16),
    new Uint8Array(32).fill(0xaa)),
    '03a185311c2b11388a38731a1b3301ae9d4e35bf2d8d47fc1aa388534f83041e');

// 5. AesXts sector-0 decrypt of a 32-byte (sub-sector) unit.
{
    const xtsIn = new Uint8Array(32);
    for (let i = 0; i < 32; i++) xtsIn[i] = (i * 31 + 9) & 0xff;
    check('AesXts.decrypt(sector 0, 32B)', new AesXts(key32).decrypt(xtsIn, 0),
        'b99b8078b11f0f5dcd57c43fce7427965cff1a22483a496ae6eb72c38a78971a');
}

// 6. XTS streaming invariant: decrypting a whole buffer at once must equal the
//    concatenation of decrypting sector-aligned chunks (startSector advancing).
{
    const data = new Uint8Array(0x800);
    for (let i = 0; i < data.length; i++) data[i] = (i * 7 + 3) & 0xff;
    const x = new AesXts(key32);
    const full = Buffer.from(x.decrypt(data, 0));
    const parts = [];
    for (let s = 0; s < data.length / 0x200; s++) {
        parts.push(Buffer.from(x.decrypt(data.subarray(s * 0x200, (s + 1) * 0x200), s)));
    }
    assert('XTS sector-aligned chunks == whole', Buffer.concat(parts).equals(full));
}

// 7. Determinism within one instance (same params → same output).
{
    const x = new AesXts(key32);
    const data = new Uint8Array(0x400).fill(0x42);
    assert('AesXts deterministic',
        Buffer.from(x.decrypt(data, 0)).equals(Buffer.from(x.decrypt(data, 0))));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);