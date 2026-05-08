#!/usr/bin/env node
import fs from 'fs';
import { PFS0Reader } from './pfs0.js';
import { AESCTR } from './crypto/aesctr.mjs';

const NSZ_PATH = './test.nsz';
const WORKING_NSP_PATH = './test.nsp';

function readBytes(data, offset, length) {
    return data.slice(offset, offset + length);
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
}

async function test() {
    console.log('=== Parsing NSZ ===');
    const nszData = new Uint8Array(fs.readFileSync(NSZ_PATH));
    const nszPfs0 = new PFS0Reader(nszData);
    const nszFiles = nszPfs0.getFiles();
    
    const nszNczFile = nszFiles.find(f => f.name.endsWith('.ncz'));
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
    
    console.log(`Section 0 key: ${bytesToHex(sec0Key)}`);
    console.log(`Section 0 counter: ${bytesToHex(sec0Ctr)}`);
    
    // Parse NSZ ticket
    const nszTicket = nszFiles.find(f => f.name.endsWith('.tik'));
    const nszTicketData = nszData.slice(nszTicket.offset, nszTicket.offset + nszTicket.size);
    console.log(`\nNSZ ticket (first 256 bytes):`);
    for (let i = 0; i < Math.min(256, nszTicketData.length); i += 16) {
        const hex = Array.from(nszTicketData.slice(i, i + 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        console.log(`  0x${i.toString(16).padStart(4, '0')}: ${hex}`);
    }
    
    // Parse working NSP ticket
    const workingData = new Uint8Array(fs.readFileSync(WORKING_NSP_PATH));
    const workingPfs0 = new PFS0Reader(workingData);
    const workingFiles = workingPfs0.getFiles();
    const workingTicket = workingFiles.find(f => f.name.endsWith('.tik'));
    const workingTicketData = workingData.slice(workingTicket.offset, workingTicket.offset + workingTicket.size);
    
    console.log(`\nWorking ticket (first 256 bytes):`);
    for (let i = 0; i < Math.min(256, workingTicketData.length); i += 16) {
        const hex = Array.from(workingTicketData.slice(i, i + 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        console.log(`  0x${i.toString(16).padStart(4, '0')}: ${hex}`);
    }
    
    // Compare tickets
    console.log(`\nTickets identical: ${bytesToHex(nszTicketData) === bytesToHex(workingTicketData)}`);
    
    // Find title key in ticket
    // Title key is typically at offset 0x130 in the ticket
    const titleKeyOffset = 0x130;
    const nszTitleKey = readBytes(nszTicketData, titleKeyOffset, 16);
    const workingTitleKey = readBytes(workingTicketData, titleKeyOffset, 16);
    console.log(`\nNSZ title key at 0x${titleKeyOffset.toString(16)}: ${bytesToHex(nszTitleKey)}`);
    console.log(`Working title key at 0x${titleKeyOffset.toString(16)}: ${bytesToHex(workingTitleKey)}`);
    
    // Now let's check the NCA header in the working file
    // The first 0x4000 bytes of the NCA are stored uncompressed
    const workingNca = workingFiles.find(f => f.name === nszNczFile.name.replace('.ncz', '.nca'));
    const workingNcaData = workingData.slice(workingNca.offset, workingNca.offset + workingNca.size);
    
    // Check what's at offset 0x4000 in the working NCA (start of compressed region)
    console.log(`\nWorking NCA at 0x4000 (should be start of section data):`);
    console.log(`  ${bytesToHex(workingNcaData.slice(0x4000, 0x4010))}`);
    
    // Check the magic in the working NCA
    console.log(`\nWorking NCA magic at 0x0: ${bytesToHex(workingNcaData.slice(0, 8))}`);
    console.log(`Working NCA magic at 0x4000: ${bytesToHex(workingNcaData.slice(0x4000, 0x4008))}`);
    
    // Check if the working NCA also has NCZSECTN at 0x4000
    const ncaMagic = String.fromCharCode(...workingNcaData.slice(0x4000, 0x4008));
    console.log(`Working NCA text at 0x4000: "${ncaMagic}"`);
    
    // Now let's look at the NSZ structure more carefully
    // The NSZ file has the NCA header (0x4000 bytes) stored uncompressed
    // Then the NCZ section header
    // Then compressed data
    
    // Let's check what's at the start of the NSZ NCZ file
    console.log(`\nNSZ NCZ file structure:`);
    console.log(`  Bytes 0x0-0xF: ${bytesToHex(nszNczData.slice(0, 0x10))}`);
    console.log(`  Bytes 0x3FF0-0x3FFF: ${bytesToHex(nszNczData.slice(0x3FF0, 0x4000))}`);
    console.log(`  Bytes 0x4000-0x4007: ${bytesToHex(nszNczData.slice(0x4000, 0x4008))}`);
    console.log(`  Text at 0x4000: "${String.fromCharCode(...nszNczData.slice(0x4000, 0x4008))}"`);
    
    // The NSZ NCZ file starts with the NCA header (0x4000 bytes) stored uncompressed
    // Then NCZSECTN at 0x4000
    // Then section count and section entries
    // Then compressed data
    
    // Now let's check the working file's NCA at the same position
    console.log(`\nWorking NCA at 0x4000+ (where NCZ header should be):`);
    console.log(`  Bytes 0x4000-0x4007: ${bytesToHex(workingNcaData.slice(0x4000, 0x4008))}`);
    console.log(`  Text at 0x4000: "${String.fromCharCode(...workingNcaData.slice(0x4000, 0x4008))}"`);
    
    // The working NCA doesn't have NCZSECTN - it's the raw NCA format
    // The NSZ has the NCA header + NCZ header + compressed data
    
    // So the section offsets in the NCZ are relative to the start of the NCZ file (which includes the NCA header)
    // Section 0 offset = 0x4000 means the decompressed data for section 0 starts at file position 0x4000
    // And the compressed data for section 0 starts at... section[0].offset in the file? That would be 0x4000
    
    // But wait, section[0].offset = 0x4000 and headerEnd = 0x2eb50
    // If the offset is the FILE position of the COMPRESSED data, then section[0].offset < headerEnd
    // which means the compressed data starts BEFORE the sliced buffer!
    
    // This means the offset is NOT the file position of compressed data
    // It must be the FILE POSITION OF THE DECOMPRESSED DATA
    
    // So section[0].offset = 0x4000 means decompressed data starts at file position 0x4000
    // And the compressed data for section 0 starts at... where?
    
    // Looking at the FakeSection logic again:
    // FakeSection has offset = UNCOMPRESSABLE_HEADER_SIZE = 0x4000
    // FakeSection has size = sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE = 0x4000 - 0x4000 = 0
    
    // Since FakeSection size is 0, no FakeSection is created
    // The compressed data for section 0 starts at headerEnd (where the sliced buffer starts)
    
    // So the section offset is the FILE POSITION where the DECOMPRESSED data starts
    // And the compressed data position is tracked by iterating through sections
    
    // The offset for decryption = file_position_of_compressed_data + UNCOMPRESSABLE_HEADER_SIZE
    // For section 0, compressed data starts at headerEnd (0x2eb50)
    // offset = 0x2eb50 + 0x4000 = 0x32b50 = 207696
    
    // But wait, that's what I tested and it didn't have zstd magic!
    
    // Let me re-examine the section structure
    // The section entry format is:
    // offset (8 bytes) - FILE offset of COMPRESSED data
    // size (8 bytes) - size of COMPRESSED data
    // crypto type (8 bytes)
    // crypto key (16 bytes)
    // crypto counter (16 bytes)
    
    // If section[0].offset = 0x4000 is the FILE offset of compressed data
    // Then the compressed data starts at 0x4000 in the NCZ file
    // But 0x4000 is where the NCZSECTN header is!
    
    // This means the section offset is relative to the NCZ section header start
    // So the actual file position = nczHdrOffset + section[0].offset = 0x4000 + 0x4000 = 0x8000
    
    // But 0x8000 is still before headerEnd (0x2eb50)!
    
    // Hmm, maybe the section offset is relative to the start of the section table
    // Section table starts at nczHdrOffset + 16 (after magic + section count)
    // So actual file position = (nczHdrOffset + 16) + section[0].offset = 0x4010 + 0x4000 = 0x8010
    
    // Still before headerEnd!
    
    // OK let me try a different interpretation:
    // The section offset is the FILE offset of the DECOMPRESSED data
    // And the compressed data is stored sequentially after the headerEnd
    
    // So section 0 compressed data starts at headerEnd and has size sec0Sz
    // Section 1 compressed data starts at headerEnd + sec0Sz and has size sec1Sz
    // etc.
    
    // The offset for decryption of section 0 first chunk:
    // = (file position of compressed data) + UNCOMPRESSABLE_HEADER_SIZE
    // = headerEnd + 0x4000 = 207696
    
    // But that didn't have zstd magic! So either:
    // 1. The crypto key is wrong
    // 2. The counter is wrong
    // 3. The offset calculation is still wrong
    
    // Let me try using the ticket's title key as the crypto key
    console.log(`\n=== Trying with title key as crypto key ===`);
    const aesCtrTitleKey = new AESCTR(nszTitleKey, sec0Ctr);
    const headerEnd = nczHdrPos + 16 + Number(sectionCount) * 64;
    const compressedData = nszNczData.slice(headerEnd);
    const firstChunk = compressedData.slice(0, Math.min(0x10000, compressedData.length));
    const decryptedWithTitleKey = aesCtrTitleKey.decrypt(firstChunk, headerEnd + 0x4000);
    console.log(`Decrypted with title key: ${bytesToHex(decryptedWithTitleKey.slice(0, 16))}`);
    
    const zstdMagic = [0x28, 0xB5, 0x2F, 0xFD];
    const hasZstdMagic = decryptedWithTitleKey[0] === zstdMagic[0] &&
                         decryptedWithTitleKey[1] === zstdMagic[1] &&
                         decryptedWithTitleKey[2] === zstdMagic[2] &&
                         decryptedWithTitleKey[3] === zstdMagic[3];
    console.log(`Has zstd magic: ${hasZstdMagic}`);
    
    // Let me also try reading the key from the ticket differently
    // The ticket has a "title_key" field that's the encrypted title key
    // It's encrypted with the console key and wrapped with the FB key
    
    // Let me check the key_index in the section
    let keyIndex = 0n;
    for (let i = 0; i < 8; i++) {
        keyIndex |= BigInt(nszNczData[secHdrOff + 20 + i]) << BigInt(i * 8);
    }
    console.log(`\nSection 0 key_index: ${keyIndex}`);
    
    // In the NSZ format, the key_index tells which key from the ticket to use
    // The ticket has multiple keys, and the key_index selects one
    
    // Let me check the working file's NCA header to see if there's any key info
    console.log(`\nWorking NCA header (first 0x100 bytes):`);
    for (let i = 0; i < Math.min(0x100, workingNcaData.length); i += 16) {
        const hex = Array.from(workingNcaData.slice(i, i + 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        console.log(`  0x${i.toString(16).padStart(4, '0')}: ${hex}`);
    }
    
    // Let me also check the NSZ ticket for the key_index mapping
    // The ticket has a "key_version" field and a "title_key" field
    // The key_index in the section tells which key to use
    
    // Let me try key_index = 0 (first key in ticket)
    // The first key in the ticket is typically at offset 0x130 (title key)
    // But the key_index might point to a different offset
    
    // Let me check the NSZ ticket structure more carefully
    console.log(`\nNSZ ticket full structure:`);
    for (let i = 0; i < Math.min(0x200, nszTicketData.length); i += 16) {
        const hex = Array.from(nszTicketData.slice(i, i + 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        console.log(`  0x${i.toString(16).padStart(4, '0')}: ${hex}`);
    }
    
    // Let me also try the key at offset 0x180 (another common key location)
    const keyAt180 = readBytes(nszTicketData, 0x180, 16);
    console.log(`\nKey at 0x180 in NSZ ticket: ${bytesToHex(keyAt180)}`);
    
    const aesCtr180 = new AESCTR(keyAt180, sec0Ctr);
    const decrypted180 = aesCtr180.decrypt(firstChunk, headerEnd + 0x4000);
    console.log(`Decrypted with key at 0x180: ${bytesToHex(decrypted180.slice(0, 16))}`);
    const hasZstd180 = decrypted180[0] === zstdMagic[0] && decrypted180[1] === zstdMagic[1] && 
                        decrypted180[2] === zstdMagic[2] && decrypted180[3] === zstdMagic[3];
    console.log(`Has zstd magic: ${hasZstd180}`);
    
    // Let me also try the key at offset 0x130 in the working ticket
    const workingKeyAt130 = readBytes(workingTicketData, 0x130, 16);
    console.log(`\nKey at 0x130 in working ticket: ${bytesToHex(workingKeyAt130)}`);
    
    const aesCtrWorking130 = new AESCTR(workingKeyAt130, sec0Ctr);
    const decryptedWorking130 = aesCtrWorking130.decrypt(firstChunk, headerEnd + 0x4000);
    console.log(`Decrypted with working key at 0x130: ${bytesToHex(decryptedWorking130.slice(0, 16))}`);
    const hasZstdWorking130 = decryptedWorking130[0] === zstdMagic[0] && decryptedWorking130[1] === zstdMagic[1] && 
                               decryptedWorking130[2] === zstdMagic[2] && decryptedWorking130[3] === zstdMagic[3];
    console.log(`Has zstd magic: ${hasZstdWorking130}`);
}

test().catch(e => console.error(e));
