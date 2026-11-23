import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const failures = [];
function run(cmd, args, label) {
  const r = spawnSync(cmd, args, { cwd: root, encoding: 'utf8' });
  if (r.status !== 0) failures.push(`${label}\n${r.stderr || r.stdout || `exit ${r.status}`}`);
  else console.log(`PASS ${label}`);
}
run(process.execPath, ['--check', 'src/worker.js'], 'Worker JavaScript syntax');
for (const file of fs.readdirSync(path.join(root, 'public')).filter(x => x.endsWith('.html'))) {
  const html = fs.readFileSync(path.join(root, 'public', file), 'utf8');
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]).filter(s => s.trim());
  for (let i = 0; i < scripts.length; i++) {
    const tmp = path.join(os.tmpdir(), `chollu-${process.pid}-${i}.js`);
    fs.writeFileSync(tmp, scripts[i]);
    run(process.execPath, ['--check', tmp], `${file} inline script ${i + 1}`);
    fs.rmSync(tmp, { force: true });
  }
}
const cfgText = fs.readFileSync(path.join(root, 'wrangler.jsonc'), 'utf8');
let cfg;
try { cfg = JSON.parse(cfgText); console.log('PASS wrangler.jsonc JSON syntax'); }
catch (e) { failures.push(`wrangler.jsonc parse\n${e.message}`); }
if (cfg) {
  if (!cfg.main || !fs.existsSync(path.join(root, cfg.main))) failures.push('wrangler main entry does not exist');
  if (!cfg.assets?.directory || !fs.existsSync(path.join(root, cfg.assets.directory))) failures.push('assets directory does not exist');
  if (cfg.d1_databases?.some(x => !x.database_id || x.database_id.includes('REPLACE_WITH'))) console.log('NOTICE D1 database_id is a deployment placeholder; replace it before deploy.');
  if (!cfg.r2_buckets?.some(x => x.binding === 'BUCKET')) failures.push('R2 BUCKET binding missing');
  if (!cfg.d1_databases?.some(x => x.binding === 'DB')) failures.push('D1 DB binding missing');
}
const sql = fs.readdirSync(path.join(root, 'migrations')).filter(x => x.endsWith('.sql')).sort();
const py = `import sqlite3, pathlib\nc=sqlite3.connect(':memory:')\nfor f in ${JSON.stringify(sql)}:\n c.executescript((pathlib.Path('migrations')/f).read_text())\nprint('PASS D1-compatible SQLite migration syntax; migrations applied in order')\n`;
run('python3', ['-c', py], 'Database migrations');
if (failures.length) {
  console.error(`\n${failures.length} CHECK(S) FAILED`);
  for (const f of failures) console.error(`\n${f}`);
  process.exit(1);
}
console.log('\nAll local static checks passed. This does NOT verify Cloudflare bindings, live APIs, security, or end-to-end feature behavior.');
