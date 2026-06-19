import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'fs';
import { execSync } from 'child_process';

mkdirSync('out', { recursive: true });
execSync('npx esbuild main.js --bundle --minify --format=esm --outfile=out/app.mjs --external:fs --external:node:child_process --external:crypto', { stdio: 'inherit' });

let html = readFileSync('index.html', 'utf8');
html = html.replace("import('./main.js')", "import('./app.mjs')");
writeFileSync('out/index.html', html);

copyFileSync('favicon.svg', 'out/favicon.svg');
