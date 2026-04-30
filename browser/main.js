import { NSZConverter } from './converter.js';

window.addEventListener('error', (e) => {
    console.error('Global error:', e.error);
});

window.addEventListener('unhandledrejection', (e) => {
    console.error('Unhandled rejection:', e.reason);
});

window.addEventListener('DOMContentLoaded', async () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileList = document.getElementById('fileList');
    const fileInfo = document.getElementById('fileInfo');
    const fileDetails = document.getElementById('fileDetails');
    const progressContainer = document.getElementById('progressContainer');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const logContainer = document.getElementById('logContainer');
    const convertBtn = document.getElementById('convertBtn');
    const clearBtn = document.getElementById('clearBtn');
    const fixPaddingBtn = document.getElementById('fixPaddingBtn');
    const status = document.getElementById('status');

    let fixPadding = false;

    const converter = new NSZConverter();
    const files = [];

    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function addLog(type, message) {
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        const time = new Date().toLocaleTimeString();
        entry.textContent = `[${time}] ${message}`;
        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;
    }

    function updateProgress(progress, text) {
        const percent = Math.round(progress * 100);
        progressFill.style.width = `${percent}%`;
        progressFill.textContent = `${percent}%`;
        progressText.textContent = text;
    }

    function updateFileList() {
        fileList.innerHTML = '';
        
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const item = document.createElement('div');
            item.className = 'file-item';
            
            item.innerHTML = `
                <div>
                    <div class="file-item-name">${escapeHtml(file.name)}</div>
                    <div class="file-item-size">${formatBytes(file.size)}</div>
                </div>
                <button class="remove-btn" data-index="${i}">Remove</button>
            `;
            
            fileList.appendChild(item);
        }

        fileList.querySelectorAll('.remove-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = parseInt(e.target.dataset.index);
                files.splice(index, 1);
                updateFileList();
                updateFileInfo();
            });
        });

        fileList.style.display = files.length > 0 ? 'block' : 'none';
        clearBtn.style.display = files.length > 0 ? 'block' : 'none';
        convertBtn.disabled = files.length === 0;
    }

    function updateFileInfo() {
        if (files.length === 0) {
            fileInfo.classList.remove('visible');
            return;
        }

        const file = files[0];
        fileDetails.innerHTML = `
            <div class="file-detail">
                <div class="file-detail-label">Name</div>
                <div class="file-detail-value">${escapeHtml(file.name)}</div>
            </div>
            <div class="file-detail">
                <div class="file-detail-label">Size</div>
                <div class="file-detail-value">${formatBytes(file.size)}</div>
            </div>
        `;
        
        if (files.length > 1) {
            const totalSize = files.reduce((sum, f) => sum + f.size, 0);
            fileDetails.innerHTML += `
                <div class="file-detail" style="grid-column: span 2;">
                    <div class="file-detail-label">Total Files</div>
                    <div class="file-detail-value">${files.length} files (${formatBytes(totalSize)} total)</div>
                </div>
            `;
        }

        fileInfo.classList.add('visible');
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    async function loadDefaultKeys() {
        try {
            const response = await fetch('https://raw.githubusercontent.com/AfterHrs/prodkeys/main/prod.keys');
            if (response.ok) {
                const keyText = await response.text();
                converter.setKeys(keyText);
                addLog('success', 'Keys loaded');
                return true;
            }
        } catch (error) {
            addLog('warning', 'Keys not available, proceeding without');
        }
        return false;
    }

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => { dropZone.classList.remove('dragover'); });

    dropZone.addEventListener('drop', async (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        await converter.init();
        for (const file of e.dataTransfer.files) {
            if (file.name.toLowerCase().endsWith('.nsz')) files.push(file);
        }
        updateFileList();
        updateFileInfo();
    });

    fileInput.addEventListener('change', async (e) => {
        await converter.init();
        for (const file of e.target.files) {
            if (file.name.toLowerCase().endsWith('.nsz')) files.push(file);
        }
        updateFileList();
        updateFileInfo();
    });

    clearBtn.addEventListener('click', () => {
        files.length = 0;
        updateFileList();
        updateFileInfo();
    });

    fixPaddingBtn.addEventListener('click', () => {
        fixPadding = !fixPadding;
        fixPaddingBtn.textContent = `Fix Padding: ${fixPadding ? 'ON' : 'OFF'}`;
        fixPaddingBtn.style.background = fixPadding ? 'linear-gradient(135deg, #27ae60, #2ecc71)' : 'linear-gradient(135deg, #95a5a6, #7f8c8d)';
        addLog('info', `Fix Padding ${fixPadding ? 'enabled' : 'disabled'}`);
    });

    convertBtn.addEventListener('click', async () => {
        if (files.length === 0) return;

        progressContainer.classList.add('visible');
        logContainer.classList.add('visible');
        convertBtn.disabled = true;
        status.textContent = '';
        status.className = 'status';

        addLog('info', 'Starting conversion...');
        await loadDefaultKeys();

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            addLog('info', `Processing ${i + 1}/${files.length}: ${file.name}`);

            try {
                const outputName = file.name.replace(/\.nsz$/i, '.nsp');
                
                let writable = null;
                
                if ('showSaveFilePicker' in window) {
                    try {
                        const handle = await window.showSaveFilePicker({
                            suggestedName: outputName,
                            types: [{
                                description: 'Nintendo Submission Package',
                                accept: { 'application/octet-stream': ['.nsp'] }
                            }]
                        });
                        writable = await handle.createWritable();
                        addLog('info', 'Using File System Access API for direct write');
                    } catch (e) {
                        if (e.name === 'AbortError') {
                            addLog('info', 'Save cancelled, using memory download');
                        } else {
                            addLog('warning', 'File System Access not available: ' + e.message);
                        }
                    }
                }

                const result = await converter.decompressNSZtoNSP(file, {
                    onProgress: (progress, text) => {
                        const overall = (i / files.length) + (1 / files.length) * progress;
                        updateProgress(overall, text);
                    },
                    onLog: addLog,
                    writable,
                    fixPadding
                });

                if (writable) {
                    await writable.close();
                    addLog('success', `Done: ${result.name} (${result.size ? formatBytes(result.size) : 'unknown'})`);
                } else {
                    const url = URL.createObjectURL(result.blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = result.name;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    addLog('success', `Done: ${result.name}`);
                }
            } catch (error) {
                addLog('error', `Failed: ${error.message}`);
            }
        }

        status.textContent = 'Conversion complete!';
        status.className = 'status success';
        convertBtn.disabled = false;
    });

    await converter.init().catch(e => {
        addLog('warning', 'Zstd init failed: ' + e.message);
    });
    addLog('info', 'Ready. Drop NSZ files to begin.');
});