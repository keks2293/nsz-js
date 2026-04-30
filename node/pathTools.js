import path from 'path';

export function expandFiles(dirPath) {
    return [];
}

export function isGame(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return ['.nsp', '.xci', '.nsz', '.xcz'].includes(ext);
}

export function isUncompressedGame(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return ['.nsp', '.xci'].includes(ext);
}

export function isCompressedGame(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return ['.nsz', '.xcz'].includes(ext);
}

export function isCompressedGameFile(filePath) {
    return path.extname(filePath).toLowerCase() === '.ncz';
}

export function isNspNsz(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return ['.nsp', '.nsz'].includes(ext);
}

export function isXciXcz(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return ['.xci', '.xcz'].includes(ext);
}

export function changeExtension(filePath, newExtension) {
    const parsed = path.parse(filePath);
    return path.join(parsed.dir, parsed.name + newExtension);
}

export function targetExtension(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const newExt = {
        '.nsp': '.nsz',
        '.xci': '.xcz',
        '.nca': '.ncz',
        '.nsz': '.nsp',
        '.xcz': '.xci',
        '.ncz': '.nca'
    }[ext] || ext;
    
    return changeExtension(filePath, newExt);
}

export function getExtensionName(filePath) {
    return path.extname(filePath).slice(1).toUpperCase();
}