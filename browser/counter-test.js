// Test different counter formats to match PyCryptodome output
// Reference keystream at position 131072: 4d101641764aa9f1ca218af9da18cc26

function testCounterFormats() {
    const key = [0x3c, 0x83, 0x58, 0xe3, 0x7c, 0x54, 0xac, 0xa5, 
                 0xbb, 0x20, 0xfc, 0x36, 0x74, 0x1c, 0x17, 0x27];
    const nonce = [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00];
    const blockOffset = 131072;
    const blockIdx = Math.floor(blockOffset / 16);
    
    const expected = [0x4d, 0x10, 0x16, 0x41, 0x76, 0x4a, 0xa9, 0xf1,
                      0xca, 0x21, 0x8a, 0xf9, 0xda, 0x18, 0xcc, 0x26];
    
    console.log('Testing blockIdx:', blockIdx);
    
    // Format 1: nonce[0:8] + blockIdx as BE at bytes 8-15 (current)
    let counter1 = new Uint8Array(16);
    for (let j = 0; j < 8; j++) counter1[j] = nonce[j];
    let idx = blockIdx;
    for (let j = 7; j >= 0; j--) { counter1[8 + j] = idx & 0xff; idx = Math.floor(idx / 256); }
    
    // Format 2: blockIdx as LE at bytes 0-7, nonce at 8-15  
    let counter2 = new Uint8Array(16);
    for (let j = 0; j < 8; j++) counter2[j] = (blockIdx >> (j * 8)) & 0xff;
    for (let j = 0; j < 8; j++) counter2[8 + j] = nonce[j];
    
    // Format 3: XOR nonce[0:4] with blockIdx at bytes 0-3
    let counter3 = new Uint8Array(16);
    for (let j = 0; j < 4; j++) counter3[j] = nonce[j] ^ ((blockIdx >> (j * 8)) & 0xff);
    for (let j = 0; j < 4; j++) counter3[4 + j] = nonce[4 + j];
    for (let j = 0; j < 8; j++) counter3[8 + j] = nonce[j];
    
    // Format 4: nonce at bytes 4-11, blockIdx LE at bytes 12-13
    let counter4 = new Uint8Array(16);
    for (let j = 0; j < 16; j++) counter4[j] = 0;
    for (let j = 0; j < 8; j++) counter4[4 + j] = nonce[j];
    counter4[12] = blockIdx & 0xff;
    counter4[13] = (blockIdx >> 8) & 0xff;
    
    // Format 5: nonce[0:4] as prefix, blockIdx LE at bytes 4-7
    let counter5 = new Uint8Array(16);
    for (let j = 0; j < 4; j++) counter5[j] = nonce[j];
    for (let j = 0; j < 4; j++) counter5[4 + j] = (blockIdx >> (j * 8)) & 0xff;
    for (let j = 0; j < 8; j++) counter5[8 + j] = nonce[j];
    
    // Format 6: Just nonce, no block index (testing if counter needs increment)
    let counter6 = new Uint8Array(nonce);
    
    console.log('Format 1:', counter1.slice(0,8).toString());
    console.log('Format 2:', counter2.slice(0,8).toString());  
    console.log('Format 3:', counter3.slice(0,8).toString());
    console.log('Format 4:', counter4.slice(0,8).toString());
    console.log('Format 5:', counter5.slice(0,8).toString());
    console.log('Format 6:', counter6.slice(0,8).toString());
    
    // Need to test with actual AES to find match
    return 'Run test in browser console with AES-ECB';
}

console.log(testCounterFormats());