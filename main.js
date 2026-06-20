import { NSZConverter } from './converter.js';

class SWDownloader {
    constructor(outputName, iframe) {
        const base = location.pathname.substring(0, location.pathname.lastIndexOf('/') + 1) || '/';
        this.streamUrl = (base + 'download/' + crypto.randomUUID()).replace(/\/+/g, '/');
        this.outputName = outputName;
        this.sw = null;
        this.iframe = iframe || null;
    }

    async start() {
        const reg = await navigator.serviceWorker.ready;
        this.sw = reg.active;
        if (!this.sw) throw new Error('No active service worker');

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
        if (/iPhone|iPad|iPod/i.test(navigator.userAgent)) {
            window.open(url, '_blank');
            return;
        }
        this.iframe.src = url;
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
    if (window.addLog) window.addLog('error', 'Error: ' + (e.error && e.error.message || e.message || e));
});

window.addEventListener('unhandledrejection', (e) => {
    console.error('Unhandled rejection:', e.reason);
    if (window.addLog) window.addLog('error', 'Unhandled: ' + (e.reason && e.reason.message || e.reason));
});

async function main() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileListScroll = document.getElementById('fileListScroll');
    const progressContainer = document.getElementById('progressContainer');
    const progressFill = document.getElementById('progressFill');
    const progressPercent = document.getElementById('progressPercent');
    const logContainer = document.getElementById('logContainer');
    const convertBtn = document.getElementById('convertBtn');
    const fixPaddingBtn = document.getElementById('fixPaddingBtn');
    const overwriteBtn = document.getElementById('overwriteBtn');
    const progressTitle = document.getElementById('progressTitle');
    const verifyBtn = document.getElementById('verifyBtn');
    const status = document.getElementById('status');
    const progressSpeed = document.getElementById('progressSpeed');
    const progressTime = document.getElementById('progressTime');

    let fixPadding = false;
    let overwrite = false;
    let verify = false;
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    let downloadMode = isMobile ? 'sw' : 'fsa';

    // on mobile, switch active pill to Stream
    if (isMobile) {
        document.querySelectorAll('.pill[data-mode]').forEach(b => b.classList.remove('on'));
        const swPill = document.querySelector('.pill[data-mode="sw"]');
        if (swPill) {
            swPill.classList.add('on');
            const radio = swPill.querySelector('input');
            if (radio) radio.checked = true;
        }
    }

    overwriteBtn.classList.toggle('hidden', downloadMode !== 'fsa');

    const converter = new NSZConverter();
    const files = [];
    const fileStatus = [];

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function isCompressedGame(name) {
        const lower = name.toLowerCase();
        return lower.endsWith('.nsz') || lower.endsWith('.xcz');
    }

    function detectFileType(name) {
        const lower = name.toLowerCase();
        if (lower.endsWith('.xcz')) return 'xcz';
        return 'nsp';
    }

    function addLog(type, message) {
        window.addLog(type, message);
    }

    let lastPercent = -1;
    function updateProgress(progress) {
        const percent = Math.round(progress * 100);
        if (percent !== lastPercent) {
            lastPercent = percent;
            progressFill.style.width = `${percent}%`;
            progressPercent.textContent = `${percent}%`;
        }
    }

    function updateFileList() {
        fileListScroll.innerHTML = '';

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const ext = file.name.split('.').pop().toLowerCase();
            const st = fileStatus[i] || '';

            const item = document.createElement('div');
            item.className = 'file' + (st === 'ok' ? ' file-ok' : st === 'err' ? ' file-err' : st === 'skip' ? ' file-skip' : '');

            const badgeClass = ['nsz'].includes(ext) ? 'nsz' : ext;

            const statusIcon = st === 'ok' ? '✓' : st === 'err' ? '✗' : st === 'skip' ? '–' : '';

            item.innerHTML = `
                <div class="file-badge ${badgeClass}">${ext.toUpperCase()}</div>
                <div class="file-meta">
                    <div class="file-name">${escapeHtml(file.name)}</div>
                    <div class="file-size">${formatBytes(file.size)}</div>
                    <div class="file-pprogress" id="fp${i}"><div class="file-pprogress-fill" id="fpf${i}"></div></div>
                </div>
                <div class="file-status-icon">${statusIcon}</div>
                <button class="file-x" data-index="${i}">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                </button>
            `;

            fileListScroll.appendChild(item);
        }

        fileListScroll.querySelectorAll('.file-x').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = parseInt(e.currentTarget.dataset.index);
                files.splice(index, 1);
                fileStatus.splice(index, 1);
                updateFileList();
            });
        });

        const hasFiles = files.length > 0;
        dropZone.classList.toggle('has-files', hasFiles);
        convertBtn.disabled = !hasFiles;
        if (!hasFiles) {
            progressTitle.textContent = 'Ready';
            updateProgress(0);
        }
    }

    function updateFileProgress(index, pct) {
        const fill = document.getElementById(`fpf${index}`);
        if (fill) fill.style.width = `${pct}%`;
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
                addLog('success', 'Keys loaded');
                return true;
            }
        } catch (error) {
            addLog('info', 'No static/prod.keys found');
        }
        return false;
    }

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => { dropZone.classList.remove('dragover'); });

    dropZone.addEventListener('drop', async (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        for (const file of e.dataTransfer.files) {
            if (isCompressedGame(file.name)) files.push(file);
        }
        updateFileList();
    });

    fileInput.addEventListener('change', async (e) => {
        for (const file of e.target.files) {
            if (isCompressedGame(file.name)) files.push(file);
        }
        updateFileList();
    });

    fixPaddingBtn.addEventListener('click', () => {
        fixPadding = !fixPadding;
        fixPaddingBtn.classList.toggle('on', fixPadding);
    });

    overwriteBtn.addEventListener('click', () => {
        overwrite = !overwrite;
        overwriteBtn.classList.toggle('on', overwrite);
    });

    verifyBtn.addEventListener('click', () => {
        verify = !verify;
        verifyBtn.classList.toggle('on', verify);
    });

    document.querySelectorAll('.pill[data-mode]').forEach(btn => {
        btn.addEventListener('click', () => {
            const radio = btn.querySelector('input');
            if (!radio) return;
            radio.checked = true;
            document.querySelectorAll('.pill[data-mode]').forEach(b => b.classList.remove('on'));
            btn.classList.add('on');
            downloadMode = radio.value;
            overwriteBtn.classList.toggle('hidden', downloadMode !== 'fsa');
        });
    });

    convertBtn.addEventListener('click', async () => {
        if (files.length === 0) return;

        progressContainer.classList.add('visible');
        logContainer.classList.add('visible');
        convertBtn.disabled = true;
        progressSpeed.textContent = '';
        progressTime.textContent = '';
        status.textContent = '';
        status.className = 'status';

        updateProgress(0);
        addLog('info', `Starting conversion (${downloadMode})...`);
        await loadDefaultKeys();

        const totalBytes = files.reduce((s, f) => s + f.size, 0);
        const startTime = Date.now();

        const speedSamples = [];
        function updateStats(overallProgress) {
            const now = Date.now();
            const bytesDone = totalBytes * Math.min(1, Math.max(0, overallProgress));

            speedSamples.push({ t: now, b: bytesDone });
            while (speedSamples.length > 1 && speedSamples[speedSamples.length - 1].t - speedSamples[0].t > 5000) {
                speedSamples.shift();
            }

            progressSpeed.textContent = '';

            const elapsed = (now - startTime) / 1000;
            const elapsedStr = elapsed >= 60
                ? `${Math.floor(elapsed / 60)}m ${Math.floor(elapsed % 60)}s`
                : `${Math.floor(elapsed)}s`;

            if (speedSamples.length >= 3 && bytesDone > totalBytes * 0.02) {
                const first = speedSamples[0];
                const last = speedSamples[speedSamples.length - 1];
                const dur = (last.t - first.t) / 1000;
                const speed = (last.b - first.b) / dur;
                if (isFinite(speed) && speed > 0) {
                    progressSpeed.textContent = `${(speed / 1048576).toFixed(1)} MB/s`;
                    const remaining = (totalBytes - bytesDone) / speed;
                    const remainingStr = remaining >= 60
                        ? `${Math.floor(remaining / 60)}m ${Math.floor(remaining % 60)}s`
                        : `${Math.floor(remaining)}s`;
                    progressTime.textContent = `${elapsedStr} / ${remainingStr}`;
                    return;
                }
            }
            progressTime.textContent = elapsedStr;
        }

        let directoryHandle = null;

        if ('showDirectoryPicker' in window && downloadMode === 'fsa') {
            try {
                directoryHandle = await window.showDirectoryPicker({ startIn: 'downloads' });
                addLog('info', 'Saving to selected directory');
            } catch (e) {
                if (e.name === 'AbortError') {
                    addLog('err', 'Save location rejected');
                    convertBtn.disabled = false;
                    return;
                } else {
                    addLog('warn', 'FSA not available: ' + e.message);
                }
            }
        }

        const fileIframes = files.map(() => {
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            document.body.appendChild(iframe);
            return iframe;
        });

        let accumulatedBytes = 0;
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            if (fileStatus[i] === 'ok' || fileStatus[i] === 'skip' || fileStatus[i] === 'err') continue;
            addLog('info', `Processing ${i + 1}/${files.length}: ${file.name}`);
            progressTitle.textContent = file.name;

            try {
                const fileType = detectFileType(file.name);
                const outputName = fileType === 'xcz'
                    ? file.name.replace(/\.xcz$/i, '.xci')
                    : file.name.replace(/\.nsz$/i, '.nsp');

                let writable = null;
                if (downloadMode === 'blob') {
                } else if (directoryHandle && downloadMode === 'fsa') {
                    try {
                        let fileHandle;
                        if (overwrite) {
                            fileHandle = await directoryHandle.getFileHandle(outputName, { create: true });
                        } else {
                            try {
                                fileHandle = await directoryHandle.getFileHandle(outputName);
                                addLog('warn', `Exists, skipping: ${outputName}`);
                                fileStatus[i] = 'skip';
                                updateFileList();
                                accumulatedBytes += file.size;
                                continue;
                            } catch {
                                fileHandle = await directoryHandle.getFileHandle(outputName, { create: true });
                            }
                        }
                        writable = await fileHandle.createWritable();
                    } catch (e) {
                        addLog('warn', 'Failed to create file: ' + e.message);
                    }
                }

                if (!writable && (downloadMode === 'sw' || downloadMode === 'fsa') && 'serviceWorker' in navigator && location.protocol !== 'file:') {
                    try {
                        if (!window._swRegistered) {
                            await navigator.serviceWorker.register('download-worker.js');
                            await navigator.serviceWorker.ready;
                            window._swRegistered = true;
                            addLog('info', 'SW ready');
                        }
                        const dl = new SWDownloader(outputName, fileIframes[i]);
                        await dl.start();
                        dl.triggerDownload();
                        writable = dl;
                        addLog('info', 'Using SW streaming');
                    } catch (e) {
                        addLog('info', 'SW not available: ' + e.message);
                    }
                }

                let result;
                updateFileProgress(i, 0);
                const onProgress = (p, t) => {
                    const overall = (accumulatedBytes + file.size * p) / totalBytes;
                    updateProgress(overall);
                    updateFileProgress(i, p * 100);
                    updateStats(overall);
                };
                if (fileType === 'xcz') {
                    result = await converter.decompressXCZtoXCI(file, {
                        onProgress,
                        onLog: addLog,
                        writable,
                        verify
                    });
                } else {
                    result = await converter.decompressNSZtoNSP(file, {
                        onProgress,
                        onLog: addLog,
                        writable,
                        fixPadding,
                        verify
                    });
                }

                if (writable) {
                    await writable.close();
                    addLog('ok', `${result.name} (${result.size ? formatBytes(result.size) : '?'})`);
                } else {
                    const url = URL.createObjectURL(result.blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = result.name;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    addLog('ok', `${result.name}`);
                }

                fileStatus[i] = 'ok';
                updateFileList();
                accumulatedBytes += file.size;
            } catch (error) {
                addLog('err', `Failed: ${error.message}`);
                fileStatus[i] = 'err';
                updateFileList();
            }
        }

        status.textContent = 'Done!';
        status.className = 'status ok';
        convertBtn.disabled = false;
        progressTitle.textContent = 'Done';
        updateProgress(1);
    });

    var sp = document.getElementById('loadingSpinner');
    try {
        await converter.init();
    } catch (e) {
        if (sp) sp.style.display = 'none';
        document.getElementById('progressContainer').style.display = 'none';
        document.querySelector('.section').style.display = 'none';
        document.getElementById('dropZone').classList.add('has-error');
        return;
    }
    if (sp) sp.style.display = 'none';

    progressTitle.textContent = 'Ready';
    addLog('info', 'Ready');
}

main();
