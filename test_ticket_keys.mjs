#!/usr/bin/env node
import fs from 'fs';
import { PFS0Reader } from './pfs0.js';
import { AESCTR } from './crypto/aesctr.mjs';

const args = process.argv.slice(2);
const NSZ_PATH = args[0];
const WORKING_NSP_PATH = args[1] || null;

if (!NSZ_PATH) {
    console.log('Analyze ticket keys and AES-CTR decryption in NSZ files.');
    console.log('');
    console.log('Usage: node test_ticket_keys.mjs <input.nsz> [working.nsp]');
    process.exit(1);
}

function readBytes(data, offset, length) {
    return data.slice(offset, offset + length);
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
}

async function test() {
    console.log('=== Parsing NSZ ===');
    if (!fs.existsSync(NSZ_PATH)) {
        console.error(`File not found: ${NSZ_PATH}`);
        process.exit(1);
    }
    const nszData = new Uint8Array(fs.readFileSync(NSZ_PATH));
    const nszPfs0 = new PFS0Reader(nszData);
    const nszFiles = nszPfs0.getFiles();

    const nszNczFile = nszFiles.find(f => f.name.endsWith('.ncz'));
    if (!nszNczFile) {
        console.error('No NCZ file found in NSZ');
        process.exit(1);
    }
    const nszNczData = nszData.slice(nszNczFile.offset, nszNczFile.offset + nszNczFile.size);

    // Find NCZSECTN
    let nczHdrPos = -1;
    for (let i = 0; i < nszNczData.length - 8; i++) {
        if (nszNczData[i] === 0x4E && nszNczData[i+1] === 0x43 && 
            nszNczData[i+2] === 0x5A && nszNczData[i+3] === 0x53 &&
            nszNczData[i+4] === 0x45 && nszNczData[i+5] === 0x43 &&
            nszNczData[i+6] === 0x54 && nszNczData[i+7] === 0x4E) {
            nczHdrPos = i;
            break;
        }
    }

    if (nczHdrPos < 0) {
        console.error('NCZSECTN magic not found');
        process.exit(1);
    }

    let sectionCount = 0n;
    for (let i = 0; i < 8; i++) {
        sectionCount |= BigInt(nszNczData[nczHdrPos + 8 + i]) << BigInt(i * 8);
    }
    const secHdrOff = nczHdrPos + 16;

    // Section 0
    let sec0Off = 0n, sec0Sz = 0n, sec0Crypt = 0n;
    for (let i = 0; i < 8; i++) {
        sec0Off |= BigInt(nszNczData[secHdrOff + i]) << BigInt(i * 8);
        sec0Sz |= BigInt(nszNczData[secHdrOff + 8 + i]) << BigInt(i * 8);
        sec0Crypt |= BigInt(nszNczData[secHdrOff + 16 + i]) << BigInt(i * 8);
    }
    const sec0Key = readBytes(nszNczData, secHdrOff + 32, 16);
    const sec0Ctr = readBytes(nszNczData, secHdrOff + 48, 16);

    console.log(`Section count: ${sectionCount}`);
    console.log(`Section 0 offset: ${sec0Off}, size: ${sec0Sz}, cryptoType: ${sec0Crypt}`);
    console.log(`Section 0 key: ${bytesToHex(sec0Key)}`);
    console.log(`Section 0 counter: ${bytesToHex(sec0Ctr)}`);

    // Parse NSZ ticket
    const nszTicket = nszFiles.find(f => f.name.endsWith('.tik'));
    if (nszTicket) {
        const nszTicketData = nszData.slice(nszTicket.offset, nszTicket.offset + nszTicket.size);
        console.log(`\nNSZ ticket (first 256 bytes):`);
        for (let i = 0; i < Math.min(256, nszTicketData.length); i += 16) {
            const hex = Array.from(nszTicketData.slice(i, i + 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
            console.log(`  0x${i.toString(16).padStart(4, '0')}: ${hex}`);
        }
    } else {
        console.log('\nNo ticket (.tik) file found in NSZ');
    }

    // Compare with working NSP if provided
    if (!WORKING_NSP_PATH) {
        console.log('\nNo working NSP provided — skipping ticket comparison');
        return;
    }

    if (!fs.existsSync(WORKING_NSP_PATH)) {
        console.error(`Working NSP not found: ${WORKING_NSP_PATH}`);
        process.exit(1);
    }

    const workingData = new Uint8Array(fs.readFileSync(WORKING_NSP_PATH));
    const workingPfs0 = new PFS0Reader(workingData);
    const workingFiles = workingPfs0.getFiles();
    const workingTicket = workingFiles.find(f => f.name.endsWith('.tik'));

    if (!workingTicket) {
        console.log('No ticket found in working NSP');
        return;
    }

    const workingTicketData = workingData.slice(workingTicket.offset, workingTicket.offset + workingTicket.size);

    console.log(`\nWorking ticket (first 256 bytes):`);
    for (let i = 0; i < Math.min(256, workingTicketData.length); i += 16) {
        const hex = Array.from(workingTicketData.slice(i, i + 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        console.log(`  0x${i.toString(16).padStart(4, '0')}: ${hex}`);
    }

    const nszTicketData = nszData.slice(nszTicket.offset, nszTicket.offset + nszTicket.size);
    const ticketsMatch = bytesToHex(nszTicketData) === bytesToHex(workingTicketData);
    console.log(`\nTickets identical: ${ticketsMatch}`);

    // Title key analysis
    const titleKeyOffset = 0x130;
    const nszTitleKey = readBytes(nszTicketData, titleKeyOffset, 16);
    const workingTitleKey = readBytes(workingTicketData, titleKeyOffset, 16);
    console.log(`\nNSZ title key at 0x${titleKeyOffset.toString(16)}: ${bytesToHex(nszTitleKey)}`);
    console.log(`Working title key at 0x${titleKeyOffset.toString(16)}: ${bytesToHex(workingTitleKey)}`);

    // Check key at alternative offset
    const keyAt180 = readBytes(nszTicketData, 0x180, 16);
    console.log(`\nKey at 0x180 in NSZ ticket: ${bytesToHex(keyAt180)}`);

    // Try decrypt with various keys
    const headerEnd = nczHdrPos + 16 + Number(sectionCount) * 64;
    const compressedData = nszNczData.slice(headerEnd);
    const firstChunk = compressedData.slice(0, Math.min(0x10000, compressedData.length));
    const zstdMagic = [0x28, 0xB5, 0x2F, 0xFD];

    console.log(`\n=== Trying decryption with various keys ===`);

    for (const [label, keyData] of [
        ['Section key', sec0Key],
        ['Title key (0x130)', nszTitleKey],
        ['Key at 0x180', keyAt180],
        ['Working title key (0x130)', workingTitleKey],
    ]) {
        const aesCtr = new AESCTR(keyData, sec0Ctr);
        const decrypted = aesCtr.decrypt(new Uint8Array(firstChunk), headerEnd + 0x4000);
        const hasMagic = decrypted[0] === zstdMagic[0] && decrypted[1] === zstdMagic[1] &&
                         decrypted[2] === zstdMagic[2] && decrypted[3] === zstdMagic[3];
        console.log(`  ${label}: first 16 bytes = ${bytesToHex(decrypted.slice(0, 16))} ${hasMagic ? '✅ zstd magic' : ''}`);
    }
}

test().catch(e => console.error(e));
