#!/usr/bin/env python3
"""
NSZ to NSP Converter - Pure Python Reference Implementation

This is the reference that works. Use this to understand the format,
then port to JavaScript.
"""

import sys
import os
import struct
import hashlib
from zstandard import ZstdDecompressor
from Crypto.Cipher import AES
from Crypto.Util import Counter

def read_int64(f, byteorder='little'):
    return int.from_bytes(f.read(8), byteorder=byteorder)

def read_int32(f, byteorder='little'):
    return int.from_bytes(f.read(4), byteorder=byteorder)

def read_int8(f, byteorder='little'):
    return int.from_bytes(f.read(1), byteorder=byteorder)

class NSZConverter:
    def __init__(self, input_path, output_path):
        self.input_path = input_path
        self.output_path = output_path
        self.ncz_files = []
        
    def convert(self):
        """Main conversion"""
        print(f"Converting {self.input_path}...")
        
        # Read entire NSZ
        with open(self.input_path, 'rb') as f:
            nsx_data = f.read()
        
        # Parse PFS0 header
        pfs0 = self.parse_pfs0(nsx_data)
        print(f"  Files: {pfs0['file_count']}")
        
        # Find NCZ files
        ncz_files = [f for f in pfs0['files'] if f['name'].lower().endswith('.ncz')]
        print(f"  NCZ files: {len(ncz_files)}")
        
        # Build output NSP
        output_data = self.build_nsp(nsx_data, pfs0, ncz_files)
        
        # Write output
        with open(self.output_path, 'wb') as f:
            f.write(output_data)
        
        print(f"  Written: {len(output_data)} bytes")
        print(f"  Output: {self.output_path}")
        
    def parse_pfs0(self, data):
        """Parse PFS0 container"""
        # Check magic "PFS0"
        magic = struct.unpack('<I', data[0:4])[0]
        if magic != 0x30534650:  # PFS0
            raise ValueError(f"Invalid PFS0 magic: {magic}")
        
        file_count = struct.unpack('<I', data[8:12])[0]
        string_table_size = struct.unpack('<I', data[12:16])[0]
        
        files = []
        header_size = 16 + file_count * 16 + string_table_size
        
        for i in range(file_count):
            offset = 16 + i * 16
            data_offset = struct.unpack('<I', data[offset:offset+4])[0]
            data_size = struct.unpack('<I', data[offset+8:offset+12])[0]
            name_offset = struct.unpack('<I', data[offset+12:offset+16])[0]
            
            # Read filename
            name_start = 16 + file_count * 16 + name_offset
            name_end = name_start
            while data[name_end] != 0:
                name_end += 1
            name = data[name_start:name_end].decode('utf-8')
            
            files.append({
                'name': name,
                'data_offset': data_offset,
                'data_size': data_size
            })
        
        return {
            'file_count': file_count,
            'string_table_size': string_table_size,
            'header_size': header_size,
            'files': files
        }
    
    def build_nsp(self, nsx_data, pfs0, ncz_files):
        """Build output NSP from input NSZ"""
        
        # Calculate output size
        output_size = pfs0['header_size']
        for f in pfs0['files']:
            ncz = next((n for n in ncz_files if n['name'] == f['name']), None)
            if ncz:
                # Need to decompress to get actual size
                ncz_data = nsx_data[f['data_offset']:f['data_offset'] + f['data_size']]
                dec_size = self.decompress_ncz(ncz_data)
                ncz['decompressed_size'] = dec_size
                output_size += dec_size
            else:
                output_size += f['data_size']
        
        output = bytearray(output_size)
        
        # Write PFS0 header
        output[0:4] = b'PFS0'
        struct.pack_into('<I', output, 4, 0x700)  # version
        struct.pack_into('<I', output, 8, pfs0['file_count'])
        struct.pack_into('<I', output, 12, pfs0['string_table_size'])
        
        # Write filenames
        string_pos = 16 + pfs0['file_count'] * 16
        for f in pfs0['files']:
            name_bytes = f['name'].encode('utf-8')
            output[string_pos:string_pos + len(name_bytes)] = name_bytes
            string_pos += len(name_bytes) + 1
        
        # Write file data
        data_offset = pfs0['header_size']
        
        for i, f in enumerate(pfs0['files']):
            ncz = next((n for n in ncz_files if n['name'] == f['name']), None)
            
            if ncz:
                # Decompress NCZ
                ncz_data = nsx_data[f['data_offset']:f['data_offset'] + f['data_size']]
                decompressed = self.decompress_ncz(ncz_data)
                output[data_offset:data_offset + len(decompressed)] = decompressed
                
                # Update file size in header
                struct.pack_into('<I', output, 16 + i * 16 + 8, len(decompressed))
                data_offset += len(decompressed)
            else:
                # Copy original data
                src_start = f['data_offset']
                src_end = src_start + f['data_size']
                output[data_offset:data_offset + f['data_size']] = nsx_data[src_start:src_end]
                data_offset += f['data_size']
            
            # Update data offset in header
            struct.pack_into('<I', output, 16 + i * 16, data_offset - f['data_size'])
        
        return bytes(output)
    
    def decompress_ncz(self, ncz_data):
        """Decompress a single NCZ file"""
        # NCZ format:
        # 0x0000: NCA header (0x4000 bytes)
        # 0x4000: NCZSECTN + sections + (optional NCZBLOCK) + zstd stream
        
        # Skip first 0x4000 (NCA header)
        pos = 0x4000
        
        # Check for NCZSECTN
        if ncz_data[pos:pos+8] != b'NCZSECTN':
            raise ValueError(f"Expected NCZSECTN at {pos}, got {ncz_data[pos:pos+8]}")
        
        pos += 8  # Skip 'NCZSECTN'
        
        # Read section count
        section_count = read_int64(type('f', (file,), {'read': lambda self: ncz_data[pos:pos+8]})(
            type('f', (bytearray,), {'__getitem__': lambda s, i: ncz_data[s._pos+i]})(
                _pos=pos
            )
        ), pos)
        
        # Actually just use struct for simplicity
        section_count = int.from_bytes(ncz_data[pos:pos+8], 'little')
        pos += 8
        
        # Read sections (each 0x40 bytes)
        sections = []
        for _ in range(section_count):
            section_data = ncz_data[pos:pos+0x40]
            sections.append(section_data)
            pos += 0x40
        
        # Check for NCZBLOCK
        block_magic = ncz_data[pos:pos+8]
        use_block_compression = (block_magic == b'NCZBLOCK')
        
        if use_block_compression:
            pos += 8 + 1 + 1 + 1 + 1 + 4 + 8  # Skip block header
            num_blocks = int.from_bytes(ncz_data[pos:pos+4], 'little')
            pos += 4 + num_blocks * 4
        
        # Remaining data is zstd compressed
        compressed = ncz_data[pos:]
        
        # Decompress
        dctx = ZstdDecompressor()
        decompressed = dctx.decompress(compressed)
        
        return decompressed

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 nsz-convert.py <input.nsz> [output.nsp]")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else input_path.replace('.nsz', '.nsp')
    
    converter = NSZConverter(input_path, output_path)
    converter.convert()
    print("Done!")

if __name__ == '__main__':
    main()