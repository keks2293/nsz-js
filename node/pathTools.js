import path from 'path';

export function changeExtension(filePath, newExtension) {
    const parsed = path.parse(filePath);
    return path.join(parsed.dir, parsed.name + newExtension);
}
