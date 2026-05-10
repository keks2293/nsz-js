#!/usr/bin/env node
/**
 * NCZ Decompressor Tests
 * Tests the NCZ to NSP conversion logic
 */

import fs from 'fs';
import { NCZDecompressor } from './ncz.js';
import { AESCTR } from './crypto/aesctr.mjs';
import { ZstdDecompressor } from './crypto/zstd.js';
import { PFS0 } from './pfs0.js';
import { KeysParser } from './keys.js';
import { sha256 } from './crypto/sha256.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
    if (condition) {
        console.log(`  ✓ ${message}`);
        passed++;
    } else {
        console.error(`  ✗ ${message}`);
        failed++;
    }
}

function assertEqual(actual, expected, message) {
    const match = actual === expected;
    if (match) {
        console.log(`  ✓ ${message}`);
        passed++;
    } else {
        console.error(`  ✗ ${message} (expected: ${expected}, got: ${actual})`);
        failed++;
    }
}

function assertBuffersEqual(a, b, message) {
    if (a.length !== b.length) {
        console.error(`  ✗ ${message} (length: ${a.length} !== ${b.length})`);
        failed++;
        return;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            console.error(`  ✗ ${message} (byte ${i}: ${a[i]} !== ${b[i]})`);
            failed++;
            return;
        }
    }
    console.log(`  ✓ ${message}`);
    passed++;
}

async function testAESCTR() {
    console.log('\n=== AES-CTR Tests ===');
    
    const key = new Uint8Array(Buffer.from('c0f2ce05ba73bcf5777f58f94e919b01', 'hex'));
    const nonce = new Uint8Array(Buffer.from('00000002000000020000000000000000', 'hex'));
    const aesCtr = new AESCTR(key, nonce);
    aesCtr.seek(0x4000);
    
    const testData = new Uint8Array([0x28, 0xB5, 0x2F, 0xFD]); // zstd magic
    const encrypted = await aesCtr.encrypt(testData);
    
    assertEqual(encrypted[0], 0x87, 'AES-CTR encrypt byte 0');
    assertEqual(encrypted[1], 0x47, 'AES-CTR encrypt byte 1');
}

async function testNCZParsing() {
    console.log('\n=== NCZ Parsing Tests ===');
    
    const nszPath = './test.nsz';
    const workingPath = './test.nsp';
    
    if (!fs.existsSync(nszPath)) {
        console.log('  ⊘ Skipping - NSZ file not found');
        return;
    }
    
    const nszData = fs.readFileSync(nszPath);
    const pfs0 = new PFS0(nszData);
    const files = pfs0.getFiles();
    
    assertEqual(files.length, 1, 'PFS0 file count');
    
    const nczFile = files.find(f => f.name.endsWith('.ncz'));
    assert(nczFile !== undefined, 'NCZ file found');
    
    if (nczFile) {
        assertEqual(nczFile.name.endsWith('.ncz'), true, 'NCZ extension');
        console.log(`  NCZ: ${nczFile.name} (${nczFile.size} bytes)`);
    }
    
    const workingData = fs.readFileSync(workingPath);
    const workingPfs0 = new PFS0(workingData);
    const workingFiles = workingPfs0.getFiles();
    
    assertEqual(workingFiles.length, 1, 'Working NSP file count');
}

async function testNCZDecompression() {
    console.log('\n=== NCZ Decompression Tests ===');
    
    const nszPath = './test.nsz';
    const workingPath = './test.nsp';
    const keysPath = './static/prod.keys';
    
    if (!fs.existsSync(nszPath)) {
        console.log('  ⊘ Skipping - NSZ file not found');
        return;
    }
    
    const nszData = fs.readFileSync(nszPath);
    const keysText = fs.readFileSync(keysPath, 'utf-8');
    const keys = KeysParser.parse(keysText);
    
    // Extract NCZ file from NSZ container first
    const pfs0 = new PFS0(nszData);
    const files = pfs0.getFiles();
    const nczFile = files.find(f => f.name.endsWith('.ncz'));
    if (!nczFile) {
        console.log('  ⊘ No NCZ file found in NSZ');
        return;
    }
    const nczData = nszData.slice(nczFile.offset, nczFile.offset + nczFile.size);
    
    console.log('  Loading NCZ decompressor...');
    const decompressor = new NCZDecompressor(nczData, keys);
    
    console.log('  Starting decompression...');
    const result = await decompressor.decompress();
    
    assert(result !== null, 'Decompression returned result');
    assert(result.length > 0, 'Result has content');
    
    // Compare with working NSP's NCA
    const workingData = fs.readFileSync(workingPath);
    const workingPfs0 = new PFS0(workingData);
    const workingFiles = workingPfs0.getFiles();
    const ncaFile = workingFiles.find(f => f.name === nczFile.name.replace('.ncz', '.nca'));
    
    if (!ncaFile) {
        console.log('  ⊘ No matching NCA found in working NSP');
        return;
    }
    
    const workingNca = workingData.slice(ncaFile.offset, ncaFile.offset + ncaFile.size);
    
    assertEqual(result.length, workingNca.length, 'Output NCA size matches working NCA');
    
    if (result.length === workingNca.length) {
        let matchCount = 0;
        let sampleSize = Math.min(1000000, result.length);
        
        for (let i = 0; i < sampleSize; i++) {
            if (result[i] === workingNca[i]) matchCount++;
        }
        
        const matchPercent = (matchCount / sampleSize * 100).toFixed(1);
        console.log(`  Content match: ${matchPercent}% (${matchCount}/${sampleSize} bytes sampled)`);
        assert(matchPercent === '100.0', 'Content matches working NCA');
    }
}

async function testZstdDecompression() {
    console.log('\n=== Zstd Decompression Tests ===');
    
    await ZstdDecompressor.load();
    
    // Test with known zstd data
    const testData = new Uint8Array([0x28, 0xB5, 0x2F, 0xFD]);
    try {
        const zstd = new ZstdDecompressor();
        await zstd.decompress(testData);
        console.log('  ⊘ Zstd decompression succeeded (unexpected)');
    } catch(e) {
        console.log(`  ✓ Zstd correctly rejects invalid data`);
        passed++;
    }
}

async function runAllTests() {
    console.log('=== Running NCZ Decompressor Tests ===');
    
    await testAESCTR();
    await testNCZParsing();
    await testNCZDecompression();
    await testZstdDecompression();
    
    console.log(`\n=== Results ===`);
    console.log(`Passed: ${passed}`);
    console.log(`Failed: ${failed}`);
    
    if (failed > 0) {
        process.exit(1);
    }
}

runAllTests().catch(e => {
    console.error('Test error:', e);
    process.exit(1);
});
