import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'fs';
import { execSync } from 'child_process';

const ENTRY = 'main.js';
const OUT = 'app.mjs';
const ASSETS = ['favicon.svg', 'download-worker.js', 'sw.js'];

const AD_SITES = {
    'nsztonsp.netlify.app': `<script>(function(s){s.dataset.zone='11368266',s.src='https://nap5k.com/tag.min.js'})([document.documentElement, document.body].filter(Boolean).pop().appendChild(document.createElement('script')))</script>`,
    'nszjs.netlify.app': `<script>(function(s){s.dataset.zone='11024396',s.src='https://nap5k.com/tag.min.js'})([document.documentElement, document.body].filter(Boolean).pop().appendChild(document.createElement('script')))</script>`,
};

const DEPLOY_URL = process.env.DEPLOY_URL || process.env.URL || '';
const AD = Object.entries(AD_SITES).find(([d]) => DEPLOY_URL.includes(d))?.[1] || null;

mkdirSync('out', { recursive: true });
execSync(`npx esbuild ${ENTRY} --bundle --minify --format=esm --outfile=out/${OUT} --external:node:fs --external:node:child_process --external:node:crypto --external:node:zlib --external:crypto`, { stdio: 'inherit' });

let html = readFileSync('index.html', 'utf8');
html = html.replace(`import('./${ENTRY}')`, `import('./${OUT}')`);
if (AD) {
    html = html.replace('<head>', `<head>\n    ${AD}`);
    console.log(`[build] Ad injected`);
}
writeFileSync('out/index.html', html);

for (const file of ASSETS) {
  copyFileSync(file, `out/${file}`);
}
mkdirSync('out/static', { recursive: true });
copyFileSync('static/prod.keys', 'out/static/prod.keys');
