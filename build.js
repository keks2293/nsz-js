import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { execSync } from 'child_process';

mkdirSync('out', { recursive: true });
execSync('npx esbuild main.js --bundle --minify --format=esm --outfile=out/app.mjs --external:fs --external:node:child_process --external:crypto', { stdio: 'inherit' });

let html = readFileSync('index.html', 'utf8');
html = html.replace("import('./main.js')", "import('./out/app.mjs')");
writeFileSync('out/index.html', html);
