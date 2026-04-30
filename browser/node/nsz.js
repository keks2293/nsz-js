import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { NSZDecompressor } from './decompressor.js';
import { parseArguments } from './parseArguments.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
    const args = parseArguments();
    
    if (args.file) {
        for (const filePath of args.file) {
            console.log(`Decompressing ${filePath}...`);
            try {
                const decompressor = new NSZDecompressor(filePath, args.output);
                await decompressor.decompress();
                console.log(`Successfully decompressed to ${decompressor.outputPath}`);
            } catch (error) {
                console.error(`Error decompressing ${filePath}: ${error.message}`);
            }
        }
    } else {
        console.log('Usage: node nsz.js -d <file.nsz> [-o <output_dir>]');
    }
}

main().catch(console.error);