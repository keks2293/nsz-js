import { NCA } from './nca.js';
import { Pfs0 } from './pfs0.js';

export function extractHashes(container) {
    const fileHashes = new Set();
    
    for (const file of container.files || container) {
        if (file instanceof NCA && file.header && file.header.contentType === 1) {
            for (const section of file.sectionFilesystems || []) {
                if (section instanceof Pfs0) {
                    const cnmt = section.getCnmt();
                    if (cnmt && cnmt.contentEntries) {
                        for (const entry of cnmt.contentEntries) {
                            if (entry.hash) {
                                fileHashes.add(entry.hash);
                            }
                        }
                    }
                }
            }
        }
    }
    
    return fileHashes;
}

export function extractTitleIdAndVersion(gamePath, args = null) {
    return null;
}

export function createTargetDict(targetFolder, args, extension, filesAtTarget = {}, alreadyExists = {}) {
    return { filesAtTarget, alreadyExists };
}

export function allowedToWriteOutfile(filePath, targetFileExtension, targetDict, args) {
    return true;
}

export function fileNameCheck(filePath, targetFileExtension, filesAtTarget, removeOld, overwrite) {
    return true;
}

export function deleteSourceFile(sourceFilePath, outFolder) {
    
}