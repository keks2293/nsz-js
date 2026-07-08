import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'fs';
import { execSync } from 'child_process';

const ENTRY = 'main.js';
const OUT = 'app.mjs';
const ASSETS = ['favicon.svg', 'download-worker.js'];

mkdirSync('out', { recursive: true });
execSync(`npx esbuild ${ENTRY} --bundle --minify --format=esm --outfile=out/${OUT} --external:fs --external:node:child_process --external:crypto`, { stdio: 'inherit' });

let html = readFileSync('index.html', 'utf8');
html = html.replace(`import('./${ENTRY}')`, `import('./${OUT}')`);
writeFileSync('out/index.html', html);

for (const file of ASSETS) {
  copyFileSync(file, `out/${file}`);
}
mkdirSync('out/static', { recursive: true });
copyFileSync('static/prod.keys', 'out/static/prod.keys');
