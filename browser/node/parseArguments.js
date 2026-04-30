export function parseArguments() {
    const args = process.argv.slice(2);
    const result = {
        file: null,
        output: null,
        verify: false,
        fixPadding: false,
        extractHashes: false
    };

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];

        switch (arg) {
            case '-d':
            case '--decompress':
                if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
                    result.file = [args[++i]];
                }
                break;
            case '-o':
            case '--output':
                if (i + 1 < args.length) {
                    result.output = args[++i];
                }
                break;
            case '-v':
            case '--verify':
                result.verify = true;
                break;
            case '-f':
            case '--fix-padding':
                result.fixPadding = true;
                break;
            case '--extract-hashes':
                result.extractHashes = true;
                break;
            default:
                if (!arg.startsWith('-')) {
                    result.file = result.file || [];
                    result.file.push(arg);
                }
                break;
        }
    }

    return result;
}