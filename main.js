import { NSZConverter } from './converter.js';

class SWDownloader {
    constructor(outputName) {
        const base = location.pathname.substring(0, location.pathname.lastIndexOf('/') + 1) || '/';
        this.streamUrl = (base + 'download/' + crypto.randomUUID()).replace(/\/+/g, '/');
        this.outputName = outputName;
        this.sw = null;
    }

    async start() {
        const reg = await navigator.serviceWorker.ready;
        this.sw = reg.active;
        if (!this.sw) throw new Error('No active service worker');

        // Ensure this page is controlled by the SW so fetch events are intercepted
        if (!navigator.serviceWorker.controller) {
            await new Promise(resolve => {
                navigator.serviceWorker.addEventListener('controllerchange', resolve, { once: true });
            });
        }

        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                navigator.serviceWorker.removeEventListener('message', onMessage);
                reject(new Error('SW download start timed out'));
            }, 5000);

            const onMessage = (e) => {
                if (e.data.type === 'ready' && e.data.url === this.streamUrl) {
                    clearTimeout(timeout);
                    navigator.serviceWorker.removeEventListener('message', onMessage);
                    resolve();
                }
            };

            navigator.serviceWorker.addEventListener('message', onMessage);
            this.sw.postMessage({ type: 'start', url: this.streamUrl, fileName: this.outputName });
        });
    }

    triggerDownload() {
        const url = this.streamUrl + '?name=' + encodeURIComponent(this.outputName);
        if (!window.open(url, '_blank')) {
            const a = document.createElement('a');
            a.href = url;
            a.target = '_blank';
            a.rel = 'noopener';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }
    }

    async write({ type, position, data }) {
        if (type !== 'write' || !this.sw) return;
        const view = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
        const copy = view.slice(0);
        this.sw.postMessage({ type: 'data', url: this.streamUrl, chunk: copy.buffer }, [copy.buffer]);
    }

    async close() {
        if (this.sw) this.sw.postMessage({ type: 'end', url: this.streamUrl });
    }
}

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
    const progressContainer = document.getElementById('progressContainer');
        const progressFill = document.getElementById('progressFill');
        const progressPercent = document.getElementById('progressPercent');
        const progressText = document.getElementById('progressText');
    const logContainer = document.getElementById('logContainer');
    const convertBtn = document.getElementById('convertBtn');
    const clearBtn = document.getElementById('clearBtn');
    const fixPaddingBtn = document.getElementById('fixPaddingBtn');
    const status = document.getElementById('status');

    let fixPadding = false;
    let downloadMode = 'auto';

    const converter = new NSZConverter();
    const files = [];

    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function isCompressedGame(name) {
        const lower = name.toLowerCase();
        return lower.endsWith('.nsz') || lower.endsWith('.ncz') || lower.endsWith('.xcz');
    }

    function detectFileType(name) {
        const lower = name.toLowerCase();
        if (lower.endsWith('.ncz')) return 'ncz';
        if (lower.endsWith('.xcz')) return 'xcz';
        return 'nsp';
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
        progressPercent.textContent = `${percent}%`;
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
            });
        });

        fileList.style.display = files.length > 0 ? 'block' : 'none';
        clearBtn.style.display = files.length > 0 ? 'block' : 'none';
        convertBtn.disabled = files.length === 0;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    async function loadDefaultKeys() {
        try {
            const response = await fetch('./static/prod.keys');
            if (response.ok) {
                const keyText = await response.text();
                converter.setKeys(keyText);
                addLog('success', 'Keys loaded from static/prod.keys');
                return true;
            }
        } catch (error) {
            addLog('info', 'No static/prod.keys found, using keys from textarea if provided');
        }
        return false;
    }

    dropZone.addEventListener('click', () => { fileInput.value = ''; fileInput.click(); });
    dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => { dropZone.classList.remove('dragover'); });

    dropZone.addEventListener('drop', async (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        await converter.init();
        for (const file of e.dataTransfer.files) {
            if (isCompressedGame(file.name)) files.push(file);
        }
        updateFileList();
    });

    fileInput.addEventListener('change', async (e) => {
        await converter.init();
        for (const file of e.target.files) {
            if (isCompressedGame(file.name)) files.push(file);
        }
        updateFileList();
    });

    clearBtn.addEventListener('click', () => {
        files.length = 0;
        updateFileList();
    });

    fixPaddingBtn.addEventListener('click', () => {
        fixPadding = !fixPadding;
        fixPaddingBtn.textContent = `Fix Padding: ${fixPadding ? 'ON' : 'OFF'}`;
        fixPaddingBtn.style.background = fixPadding ? 'linear-gradient(135deg, #27ae60, #2ecc71)' : 'linear-gradient(135deg, #95a5a6, #7f8c8d)';
        addLog('info', `Fix Padding ${fixPadding ? 'enabled' : 'disabled'}`);
    });

    document.getElementById('modeOptions').addEventListener('click', (e) => {
        const label = e.target.closest('.mode-btn');
        if (!label) return;
        const radio = label.querySelector('input');
        if (!radio) return;
        radio.checked = true;
        document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
        label.classList.add('active');
        downloadMode = radio.value;
        addLog('info', `Download mode: ${radio.value}`);
    });

    convertBtn.addEventListener('click', async () => {
        if (files.length === 0) return;

        progressContainer.classList.add('visible');
        logContainer.classList.add('visible');
        convertBtn.disabled = true;
        status.textContent = '';
        status.className = 'status';

        updateProgress(0, 'Starting...');
        addLog('info', 'Starting conversion...');
        await loadDefaultKeys();

        // Android Chrome: createWritable() has a known bug ("cached state changed"),
        // so skip directory picker entirely and use SW streaming or Blob download
        const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);

        let directoryHandle = null;

        if ('showDirectoryPicker' in window && (downloadMode === 'fsa' || (downloadMode === 'auto' && !isMobile))) {
            try {
                directoryHandle = await window.showDirectoryPicker({
                    startIn: 'downloads'
                });
                addLog('info', 'Using File System Access API - saving to selected directory');
            } catch (e) {
                if (e.name !== 'AbortError') {
                    addLog('warning', 'File System Access not available: ' + e.message);
                }
            }
        }

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            addLog('info', `Processing ${i + 1}/${files.length}: ${file.name}`);

            updateProgress(i / files.length, 'Starting...');
            
            try {
                const fileType = detectFileType(file.name);
                const outputName = fileType === 'ncz'
                    ? file.name.replace(/\.ncz$/i, '.nca')
                    : fileType === 'xcz'
                        ? file.name.replace(/\.xcz$/i, '.xci')
                        : file.name.replace(/\.nsz$/i, '.nsp');

                let writable = null;
                if (downloadMode === 'blob') {
                    // Blob only — skip FSA and SW
                } else if (directoryHandle && (downloadMode === 'auto' || downloadMode === 'fsa')) {
                    try {
                        const fileHandle = await directoryHandle.getFileHandle(outputName, { create: true });
                        writable = await fileHandle.createWritable();
                    } catch (e) {
                        addLog('warning', 'Failed to create file: ' + e.message);
                    }
                }

                // Try Service Worker streaming (modes: auto, sw)
                if (!writable && (downloadMode === 'auto' || downloadMode === 'sw') && 'serviceWorker' in navigator && location.protocol !== 'file:') {
                    try {
                        const dl = new SWDownloader(outputName);
                        await dl.start();
                        dl.triggerDownload();
                        writable = dl;
                        addLog('info', 'Using Service Worker streaming download');
                    } catch (e) {
                        addLog('info', 'SW download not available: ' + e.message);
                    }
                }

                let result;
                if (fileType === 'ncz') {
                    result = await converter.decompressNCZtoNCA(file, {
                        onProgress: (progress, text) => {
                            updateProgress((i + progress) / files.length, text);
                        },
                        onLog: addLog,
                        writable
                    });
                } else if (fileType === 'xcz') {
                    result = await converter.decompressXCZtoXCI(file, {
                        onProgress: (progress, text) => {
                            updateProgress((i + progress) / files.length, text);
                        },
                        onLog: addLog,
                        writable
                    });
                } else {
                    result = await converter.decompressNSZtoNSP(file, {
                        onProgress: (progress, text) => {
                            const normalizedProgress = Math.max(0, Math.min(1, (progress - 0.05) / 0.85));
                            const overall = (i + normalizedProgress) / files.length;
                            updateProgress(overall, text);
                        },
                        onLog: addLog,
                        writable,
                        fixPadding
                    });
                }

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

                files.splice(i, 1);
                i--;
                updateFileList();
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

    if ('serviceWorker' in navigator && location.protocol !== 'file:') {
        try {
            await navigator.serviceWorker.register('sw.js');
            await navigator.serviceWorker.ready;
            addLog('info', 'Service Worker ready for streaming download');
        } catch (e) {
            addLog('info', 'Service Worker not available: ' + e.message);
        }
    }

    addLog('info', 'Ready. Drop NSZ files to begin.');
});