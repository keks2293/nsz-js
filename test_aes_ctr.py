#!/usr/bin/env python3
"""Test AES-CTR keystream generation to compare with JS implementation"""
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

def generate_keystream(key_hex, nonce_hex, offset, length=48):
    """
    Generate keystream using PyCryptodome AES-CTR
    This matches what NSZ uses
    """
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    
    # Create counter like NSZ does: Counter.new(64, prefix=nonce[0:8], initial_value=(offset >> 4))
    block_index = offset >> 4  # offset / 16
    ctr = Counter.new(64, prefix=nonce[0:8], initial_value=block_index)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    
    # Encrypt zeros to get keystream
    plaintext = b'\x00' * length
    keystream = cipher.encrypt(plaintext)
    
    return keystream.hex()

def generate_counter_block(nonce_hex, block_index):
    """Show what the counter block looks like for a given block index"""
    nonce = bytes.fromhex(nonce_hex)
    counter_block = bytearray(16)
    
    # First 8 bytes: nonce[0:8]
    counter_block[0:8] = nonce[0:8]
    
    # Last 8 bytes: block_index as little-endian uint64
    for i in range(8):
        counter_block[8 + i] = (block_index >> (i * 8)) & 0xff
    
    return bytes(counter_block).hex()

if __name__ == '__main__':
    # Test with the key and nonce from the debug output
    key_hex = '3c8358e37c54aca5bb20fc36741c1727'
    nonce_hex = '00000002000000000000000000000000'  # 16 bytes
    
    print("Testing AES-CTR keystream generation")
    print(f"Key: {key_hex}")
    print(f"Nonce: {nonce_hex}")
    print()
    
    # Generate keystream for offset 131072 (0x20000)
    offset = 131072
    print(f"Offset: {offset} (0x{offset:x})")
    print(f"Block index (offset >> 4): {offset >> 4}")
    print()
    
    # Show counter block for first few blocks
    for block_idx in range(3):
        counter_hex = generate_counter_block(nonce_hex, block_idx)
        print(f"Counter block {block_idx}: {counter_hex}")
    
    print()
    keystream = generate_keystream(key_hex, nonce_hex, offset, 48)
    print(f"Keystream at offset {offset}:")
    print(f"  {keystream}")
    print()
    
    # Also test with offset 0
    keystream0 = generate_keystream(key_hex, nonce_hex, 0, 48)
    print(f"Keystream at offset 0:")
    print(f"  {keystream0}")
