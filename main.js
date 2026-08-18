import { NSZConverter } from './converter.js';
import { ZstdDecompressor } from './crypto/zstd.js';

class SWDownloader {
    #streamError = '';
    #swMsgHandler = null;
    #pos = 0; // absolute byte position of the next byte in the stream

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

        this.#swMsgHandler = e => this.#onSWMsg(e);
        navigator.serviceWorker.addEventListener('message', this.#swMsgHandler);

        return new Promise((resolve) => {
            const onMessage = (e) => {
                if (e.data.type === 'ready' && e.data.url === this.streamUrl) {
                    navigator.serviceWorker.removeEventListener('message', onMessage);
                    resolve();
                }
            };

            navigator.serviceWorker.addEventListener('message', onMessage);
            this.sw.postMessage({ type: 'start', url: this.streamUrl, fileName: this.outputName });
        });
    }

    #onSWMsg(e) {
        if (e.data.type === 'error' && e.data.url === this.streamUrl) {
            this.#streamError = e.data.message;
        }
    }

    triggerDownload() {
        const url = this.streamUrl + '?name=' + encodeURIComponent(this.outputName);
        if (/iPhone|iPad|iPod/i.test(navigator.userAgent)) {
            window.open(url, '_blank');
            return;
        }
        this.iframe.src = url;
    }

    get bytesWritten() { return this.#pos; }

    #postChunk(bytes) {
        this.sw.postMessage({ type: 'data', url: this.streamUrl, chunk: bytes.buffer }, [bytes.buffer]);
    }

    async write({ type, position, data }) {
        if (type !== 'write' || !this.sw) return;
        if (this.#streamError) throw new Error('SW stream lost (' + this.#streamError + ')');
        // Fill any gap with zeros (alignment padding, < 16 KB).
        const gap = position - this.#pos;
        if (gap > 0) this.#postChunk(new Uint8Array(gap));
        const view = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
        // If `view` is a subarray of a larger buffer, `view.buffer` is that larger
        // buffer — posting it would send the wrong bytes. Copy to a fresh buffer so
        // `chunk.buffer` is exactly the view's bytes (covers wasm-memory views too).
        const chunk = (view.byteLength !== view.buffer.byteLength)
            ? view.slice(0) : view;
        // Capture byteLength BEFORE #postChunk — the transfer detaches chunk.buffer,
        // which causes chunk.byteLength to return 0 in Chrome (V8) per ES spec.
        const len = chunk.byteLength;
        this.#postChunk(chunk);
        this.#pos = position + len;
    }

    async close() {
        if (this.#swMsgHandler) {
            navigator.serviceWorker.removeEventListener('message', this.#swMsgHandler);
            this.#swMsgHandler = null;
        }
        if (this.sw) this.sw.postMessage({ type: 'end', url: this.streamUrl });
    }
}

// The SW stream is sequential and the main thread never observes the actual
// delivered byte count — the success log shows the *expected* size. Compare the
// SW's tracked position against the expected size to catch a dropped gap or a
// mis-ordered write (a seekable FSA has no bytesWritten, so this is SW-only).
function checkSwDelivered(writable, expectedSize) {
    if (writable && typeof writable.bytesWritten === 'number' && typeof expectedSize === 'number' && writable.bytesWritten !== expectedSize) {
        if (window.addLog) window.addLog('warn', `SW delivered ${writable.bytesWritten} bytes, expected ${expectedSize} — output may be corrupt`);
        return false;
    }
    return true;
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
    const progressSpeed = document.getElementById('progressSpeed');
    const progressTime = document.getElementById('progressTime');
    const noDeltaBtn = document.getElementById('noDeltaBtn');
    const keepAcidSigBtn = document.getElementById('keepAcidSigBtn');
    const keepAcidKeyBtn = document.getElementById('keepAcidKeyBtn');

    let fixPadding = false;
    let overwrite = false;
    let verify = false;
    let noDeltas = false;
    let keepAcidSig = false;
    let keepAcidKey = false;
    let mode = 'convert';
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

    function updateOptionsVisibility() {
        const fixVisible = mode === 'convert';
        const verifyVisible = mode === 'convert';
        const overwriteVisible = downloadMode === 'fsa';
        const noDeltaVisible = mode === 'merge';
        const keepAcidVisible = mode === 'update';
        fixPaddingBtn.classList.toggle('hidden', !fixVisible);
        verifyBtn.classList.toggle('hidden', !verifyVisible);
        overwriteBtn.classList.toggle('hidden', !overwriteVisible);
        noDeltaBtn.classList.toggle('hidden', !noDeltaVisible);
        keepAcidSigBtn.classList.toggle('hidden', !keepAcidVisible);
        keepAcidKeyBtn.classList.toggle('hidden', !keepAcidVisible);
    }

    updateOptionsVisibility();

    const converter = new NSZConverter();
    const files = [];
    const fileStatus = [];
    let converting = false;

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

    function acceptFile(name) {
        if (mode === 'convert') return isCompressedGame(name);
        if (mode === 'merge' || mode === 'update') {
            const lower = name.toLowerCase();
            return lower.endsWith('.nsp') || lower.endsWith('.nsz') || lower.endsWith('.xci') || lower.endsWith('.xcz');
        }
        return name.toLowerCase().endsWith('.nsp');
    }

    function updateButtonLabel() {
        convertBtn.textContent = mode === 'merge' ? 'Merge' : mode === 'update' ? 'Update' : mode === 'split' ? 'Split' : 'Convert';
        if (converting) return;
        convertBtn.disabled = mode === 'merge' ? files.length < 2 : mode === 'update' ? files.length !== 2 : mode === 'split' ? files.length !== 1 : files.length === 0;
    }

    function setMode(m) {
        mode = m;
        document.querySelectorAll('.pill[data-op]').forEach(b => b.classList.toggle('on', b.dataset.op === m));
        updateOptionsVisibility();
        const keep = [];
        const keepStatus = [];
        for (let i = 0; i < files.length; i++) {
            if (acceptFile(files[i].name)) {
                keep.push(files[i]);
                keepStatus.push(fileStatus[i] || '');
            }
        }
        files.length = 0;
        files.push(...keep);
        fileStatus.length = 0;
        fileStatus.push(...keepStatus);
        updateFileList();
        updateButtonLabel();
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
                <div class="file-badge ${badgeClass}">${statusIcon || ext.toUpperCase()}</div>
                <div class="file-meta">
                    <div class="file-name">${escapeHtml(file.name)}</div>
                    <div class="file-size">${formatBytes(file.size)}</div>
                    <div class="file-pprogress" id="fp${i}"><div class="file-pprogress-fill" id="fpf${i}"></div></div>
                </div>
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
                e.stopPropagation();
                const index = parseInt(e.currentTarget.dataset.index);
                files.splice(index, 1);
                fileStatus.splice(index, 1);
                updateFileList();
            });
        });

        const hasFiles = files.length > 0;
        dropZone.classList.toggle('has-files', hasFiles);
        if (!converting) updateButtonLabel();
        if (!hasFiles) {
            progressTitle.textContent = 'Ready';
            updateProgress(0);
        }

        snapFileListHeight();
    }

    let itemHeight = 0;

    function measureItemHeight() {
        if (itemHeight) return itemHeight;
        const d = document.createElement('div');
        d.className = 'file';
        d.style.position = 'absolute';
        d.style.visibility = 'hidden';
        d.style.pointerEvents = 'none';
        d.innerHTML = '<div class="file-badge nsz">NSZ</div><div class="file-meta"><div class="file-name">x</div><div class="file-size">0 B</div><div class="file-pprogress"><div class="file-pprogress-fill"></div></div></div><button class="file-x"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>';
        dropZone.appendChild(d);
        itemHeight = d.getBoundingClientRect().height;
        dropZone.removeChild(d);
        return itemHeight;
    }

    function snapFileListHeight() {
        const h = measureItemHeight();
        if (!h) return;

        const border = 4;
        const minSlotHeight = 3 * h + border;

        if (files.length > 0) {
            const totalHeight = Math.max(window.innerWidth * 0.22, minSlotHeight);
            const maxFit = Math.max(1, Math.floor((totalHeight - border) / h));
            const visibleCount = Math.min(files.length, maxFit);
            dropZone.style.height = `${Math.max(visibleCount * h + border, minSlotHeight)}px`;
            fileListScroll.classList.toggle('is-full', files.length > maxFit);
        } else {
            dropZone.style.height = '';
            fileListScroll.classList.remove('is-full');
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
            if (!acceptFile(file.name)) continue;
            if (files.some(f => f.name === file.name)) {
                addLog('warn', `Skipped duplicate: ${file.name}`);
                continue;
            }
            files.push(file);
        }
        updateFileList();
    });

    fileInput.addEventListener('change', async (e) => {
        for (const file of e.target.files) {
            if (!acceptFile(file.name)) continue;
            if (files.some(f => f.name === file.name)) {
                addLog('warn', `Skipped duplicate: ${file.name}`);
                continue;
            }
            files.push(file);
        }
        fileInput.value = '';
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

    noDeltaBtn.addEventListener('click', () => {
        noDeltas = !noDeltas;
        noDeltaBtn.classList.toggle('on', noDeltas);
    });

    keepAcidSigBtn.addEventListener('click', () => {
        keepAcidSig = !keepAcidSig;
        keepAcidSigBtn.classList.toggle('on', keepAcidSig);
    });

    keepAcidKeyBtn.addEventListener('click', () => {
        keepAcidKey = !keepAcidKey;
        keepAcidKeyBtn.classList.toggle('on', keepAcidKey);
    });

    document.querySelectorAll('.pill[data-mode]').forEach(btn => {
        btn.addEventListener('click', () => {
            const radio = btn.querySelector('input');
            if (!radio) return;
            radio.checked = true;
            document.querySelectorAll('.pill[data-mode]').forEach(b => b.classList.remove('on'));
            btn.classList.add('on');
            downloadMode = radio.value;
            updateOptionsVisibility();
        });
    });

    document.querySelectorAll('.pill[data-op]').forEach(btn => {
        btn.addEventListener('click', () => setMode(btn.dataset.op));
    });

    function makeUpdateStats(totalBytes, startTime) {
        const speedSamples = [];
        return function updateStats(overallProgress) {
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
        };
    }

    async function pickDirectory() {
        if (!('showDirectoryPicker' in window) || downloadMode !== 'fsa') return null;
        try {
            const h = await window.showDirectoryPicker({ startIn: 'downloads' });
            addLog('info', 'Saving to selected directory');
            return h;
        } catch (e) {
            if (e.name === 'AbortError') return 'ABORT';
            addLog('warn', 'FSA not available: ' + e.message);
            return null;
        }
    }

    async function ensureSW() {
        if (!('serviceWorker' in navigator) || location.protocol === 'file:') return false;
        try {
            if (!window._swRegistered) {
                addLog('info', 'Starting SW...');
                let reg = await navigator.serviceWorker.getRegistration();
                if (!reg || reg.installing || reg.waiting) {
                    if (reg) await reg.unregister();
                    reg = await navigator.serviceWorker.register('download-worker.js');
                }
                if (!reg.active) {
                    await navigator.serviceWorker.ready;
                }
                window._swRegistered = true;
                addLog('info', 'SW active');
            }
            return true;
        } catch (e) {
            addLog('info', 'SW not available: ' + e.message);
            return false;
        }
    }

    async function createSWWritable(outputName, iframe) {
        const dl = new SWDownloader(outputName, iframe);
        addLog('info', 'Connecting to SW...');
        await dl.start();
        dl.triggerDownload();
        addLog('info', 'Stream ready');
        return dl;
    }

    function downloadBlob(blob, name) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    async function runConvert() {
        if (files.length === 0) return;

        progressContainer.classList.add('visible');
        logContainer.classList.add('visible');
        convertBtn.disabled = true;
        converting = true;
        progressSpeed.textContent = '';
        progressTime.textContent = '';

        updateProgress(0);
        addLog('info', `Starting conversion (${downloadMode})...`);

        const convertOptions = [];
        if (fixPadding) convertOptions.push('fix-padding');
        if (verify) convertOptions.push('verify');
        addLog('info', `Options: ${convertOptions.join(', ') || 'none'}`);

        const totalBytes = files.reduce((s, f) => s + f.size, 0);
        const startTime = Date.now();
        const updateStats = makeUpdateStats(totalBytes, startTime);

        const directoryHandle = await pickDirectory();
        if (directoryHandle === 'ABORT') {
            addLog('error', 'Save location rejected');
            converting = false;
            updateButtonLabel();
            return;
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

            let outputName;
            let writable = null;
            try {
                const fileType = detectFileType(file.name);
                outputName = fileType === 'xcz'
                    ? file.name.replace(/\.xcz$/i, '.xci')
                    : file.name.replace(/\.nsz$/i, '.nsp');

                if (downloadMode !== 'blob' && directoryHandle) {
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

                if (!writable && (downloadMode === 'sw' || downloadMode === 'fsa') && await ensureSW()) {
                    try {
                        writable = await createSWWritable(outputName, fileIframes[i]);
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
                checkSwDelivered(writable, result.size);

                if (writable) {
                    await writable.close();
                    addLog('success', `${result.name} (${result.size ? formatBytes(result.size) : '?'})`);
                } else {
                    downloadBlob(result.blob, result.name);
                    addLog('success', `${result.name}`);
                }

                fileStatus[i] = 'ok';
                updateFileList();
                accumulatedBytes += file.size;
            } catch (error) {
                addLog('error', `Failed: ${error.message}`);
                if (writable) {
                    try { await writable.close(); } catch (_) {}
                    if (directoryHandle && outputName) {
                        try { await directoryHandle.removeEntry(outputName); } catch (_) {}
                    }
                }
                fileStatus[i] = 'err';
                updateFileList();
            }
        }

        converting = false;
        updateButtonLabel();
        progressTitle.textContent = 'Done';
        updateProgress(1);
    }

    async function runMerge() {
        if (files.length < 2) return;

        progressContainer.classList.add('visible');
        logContainer.classList.add('visible');
        convertBtn.disabled = true;
        converting = true;
        progressSpeed.textContent = '';
        progressTime.textContent = '';

        updateProgress(0);
        addLog('info', `Starting merge (${downloadMode})...`);

        const mergeOptions = [];
        if (noDeltas) mergeOptions.push('nodelta');
        addLog('info', `Options: ${mergeOptions.join(', ') || 'none'}`);

        const totalBytes = files.reduce((s, f) => s + f.size, 0);
        const startTime = Date.now();
        const updateStats = makeUpdateStats(totalBytes, startTime);

        const directoryHandle = await pickDirectory();
        if (directoryHandle === 'ABORT') {
            addLog('error', 'Save location rejected');
            converting = false;
            updateButtonLabel();
            return;
        }

        const iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        document.body.appendChild(iframe);

        const outputName = files[0].name.replace(/\.(nsp|nsz|xci|xcz)$/i, '') + '_merged.nsp';
        let writable = null;
        if (downloadMode !== 'blob' && directoryHandle) {
            try {
                let fileHandle;
                if (overwrite) {
                    fileHandle = await directoryHandle.getFileHandle(outputName, { create: true });
                } else {
                    try {
                        fileHandle = await directoryHandle.getFileHandle(outputName);
                        addLog('warn', `Exists, skipping: ${outputName}`);
                        converting = false;
                        updateButtonLabel();
                        return;
                    } catch {
                        fileHandle = await directoryHandle.getFileHandle(outputName, { create: true });
                    }
                }
                writable = await fileHandle.createWritable();
            } catch (e) {
                addLog('warn', 'Failed to create file: ' + e.message);
            }
        }
        if (!writable && (downloadMode === 'sw' || downloadMode === 'fsa') && await ensureSW()) {
            try {
                writable = await createSWWritable(outputName, iframe);
            } catch (e) {
                addLog('info', 'SW not available: ' + e.message);
            }
        }

        const onProgress = (p) => { updateProgress(p); updateStats(p); };

        try {
            const result = await converter.mergeNSPs(files, {
                onProgress,
                onLog: addLog,
                writable,
                nodelta: noDeltas,
            });
            checkSwDelivered(writable, result.size);
            if (writable) {
                await writable.close();
            } else {
                downloadBlob(result.blob, result.name);
            }
            addLog('success', `${result.name} (${formatBytes(result.size)}), ${result.memberCount} members`);
            for (let i = 0; i < files.length; i++) fileStatus[i] = 'ok';
            updateFileList();
        } catch (error) {
            addLog('error', `Merge failed: ${error.message}`);
            if (writable) {
                try { await writable.close(); } catch (_) {}
                if (directoryHandle) {
                    try { await directoryHandle.removeEntry(outputName); } catch (_) {}
                }
            }
            fileStatus[0] = 'err';
            updateFileList();
        }

        converting = false;
        updateButtonLabel();
        progressTitle.textContent = 'Done';
        updateProgress(1);
    }

    async function runUpdate() {
        if (files.length !== 2) return;

        progressContainer.classList.add('visible');
        logContainer.classList.add('visible');
        convertBtn.disabled = true;
        converting = true;
        progressSpeed.textContent = '';
        progressTime.textContent = '';

        updateProgress(0);
        addLog('info', `Starting update (${downloadMode})...`);
        addLog('info', 'Options: keys required (decrypt CNMT metadata)');

        const totalBytes = files.reduce((s, f) => s + f.size, 0);
        const startTime = Date.now();
        const updateStats = makeUpdateStats(totalBytes, startTime);

        const directoryHandle = await pickDirectory();
        if (directoryHandle === 'ABORT') {
            addLog('error', 'Save location rejected');
            converting = false;
            updateButtonLabel();
            return;
        }

        const iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        document.body.appendChild(iframe);

        const outputName = files[0].name.replace(/\.(nsp|nsz|xci|xcz)$/i, '') + '_updated.nsp';
        let writable = null;
        if (downloadMode !== 'blob' && directoryHandle) {
            try {
                let fileHandle;
                if (overwrite) {
                    fileHandle = await directoryHandle.getFileHandle(outputName, { create: true });
                } else {
                    try {
                        fileHandle = await directoryHandle.getFileHandle(outputName);
                        addLog('warn', `Exists, skipping: ${outputName}`);
                        converting = false;
                        updateButtonLabel();
                        return;
                    } catch {
                        fileHandle = await directoryHandle.getFileHandle(outputName, { create: true });
                    }
                }
                writable = await fileHandle.createWritable();
            } catch (e) {
                addLog('warn', 'Failed to create file: ' + e.message);
            }
        }
        if (!writable && (downloadMode === 'sw' || downloadMode === 'fsa') && await ensureSW()) {
            try {
                writable = await createSWWritable(outputName, iframe);
            } catch (e) {
                addLog('info', 'SW not available: ' + e.message);
            }
        }

        const onProgress = (p) => { updateProgress(p); updateStats(p); };

        try {
            const result = await converter.updateNSPs(files, {
                onProgress,
                onLog: addLog,
                writable,
                keepNpdmAcidSig: keepAcidSig,
                keepNpdmAcidKey: keepAcidKey,
            });
            checkSwDelivered(writable, result.size);
            if (writable) {
                await writable.close();
            } else {
                downloadBlob(result.blob, result.name);
            }
            addLog('success', `${result.name} (${formatBytes(result.size)}), ${result.memberCount} members`);
            for (let i = 0; i < files.length; i++) fileStatus[i] = 'ok';
            updateFileList();
        } catch (error) {
            addLog('error', `Update failed: ${error.message}`);
            if (writable) {
                try { await writable.close(); } catch (_) {}
                if (directoryHandle) {
                    try { await directoryHandle.removeEntry(outputName); } catch (_) {}
                }
            }
            fileStatus[0] = 'err';
            updateFileList();
        }

        converting = false;
        updateButtonLabel();
        progressTitle.textContent = 'Done';
        updateProgress(1);
    }

    async function runSplit() {
        if (files.length !== 1) return;

        progressContainer.classList.add('visible');
        logContainer.classList.add('visible');
        convertBtn.disabled = true;
        converting = true;
        progressSpeed.textContent = '';
        progressTime.textContent = '';

        updateProgress(0);
        addLog('info', `Starting split (${downloadMode})...`);

        addLog('info', 'Options: none');

        const totalBytes = files[0].size;
        const startTime = Date.now();
        const updateStats = makeUpdateStats(totalBytes, startTime);

        const directoryHandle = await pickDirectory();
        if (directoryHandle === 'ABORT') {
            addLog('error', 'Save location rejected');
            converting = false;
            updateButtonLabel();
            return;
        }

        const onProgress = (p) => { updateProgress(p); updateStats(p); };

        try {
            const result = await converter.splitNSP(files[0], {
                onProgress,
                onLog: addLog,
                outputFactory: async (group, index, name) => {
                    if (downloadMode === 'blob') return { memory: true, name };
                    if (downloadMode !== 'blob' && directoryHandle) {
                        if (!overwrite) {
                            try {
                                await directoryHandle.getFileHandle(name);
                                addLog('warn', `Exists, skipping: ${name}`);
                                return null;
                            } catch (_) {}
                        }
                        const fileHandle = await directoryHandle.getFileHandle(name, { create: true });
                        const writable = await fileHandle.createWritable();
                        return { writable, name };
                    }
                    if ((downloadMode === 'sw' || downloadMode === 'fsa') && await ensureSW()) {
                        try {
                            const iframe = document.createElement('iframe');
                            iframe.style.display = 'none';
                            document.body.appendChild(iframe);
                            return { writable: await createSWWritable(name, iframe), name };
                        } catch (e) {
                            addLog('info', 'SW not available: ' + e.message);
                        }
                    }
                    return { memory: true, name };
                },
            });

            for (const out of result.outputs) {
                if (out.blob) downloadBlob(out.blob, out.name);
                addLog('success', `${out.name} (${formatBytes(out.size)})`);
                if (out.missing.length > 0) {
                    addLog('warn', `${out.missing.length} NCA(s) referenced by CNMT not found in input`);
                }
            }
            if (result.outputs.length === 0) {
                addLog('warn', 'No titles produced (all outputs exist?)');
            }
            fileStatus[0] = result.outputs.length > 0 ? 'ok' : 'skip';
            updateFileList();
        } catch (error) {
            addLog('error', `Split failed: ${error.message}`);
            fileStatus[0] = 'err';
            updateFileList();
        }

        converting = false;
        updateButtonLabel();
        progressTitle.textContent = 'Done';
        updateProgress(1);
    }

    convertBtn.addEventListener('click', async () => {
        if (mode === 'merge') await runMerge();
        else if (mode === 'update') await runUpdate();
        else if (mode === 'split') await runSplit();
        else await runConvert();
    });

    const ro = new ResizeObserver(() => requestAnimationFrame(() => snapFileListHeight()));
    ro.observe(dropZone);
    snapFileListHeight();

    const sp = document.getElementById('loadingSpinner');
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

    await loadDefaultKeys();

    progressTitle.textContent = 'Ready';
    addLog('info', 'Ready');
}

main();
