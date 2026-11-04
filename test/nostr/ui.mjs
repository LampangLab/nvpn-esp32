import { createRequire } from 'node:module'; const { chromium } = createRequire(import.meta.url)('playwright');
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
const html = readFileSync('/home/claude/nvpn-esp32/web/index.html', 'utf8');
const bundle = readFileSync('nt.bundle.mjs', 'utf8');
const results = []; const ok = (n, c) => { results.push([n, !!c]); console.log((c ? 'PASS ' : 'FAIL ') + n); };
const PORT = 7447;
async function startSim(allow) {
  const p = spawn('node', ['sim.mjs'], { env: { ...process.env, PORT: String(PORT), ALLOW: allow || '' } });
  let out = ''; p.stdout.on('data', d => out += d); p.stderr.on('data', d => out += d);
  for (let i = 0; i < 50 && !out.includes('boardNpub'); i++) await new Promise(r => setTimeout(r, 100));
  return { p, info: JSON.parse(out.split('\n').find(l => l.includes('boardNpub'))), get out() { return out; } };
}
const browser = await chromium.launch({ args: ['--disable-features=LocalNetworkAccessChecks,BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights'] });
async function page(boardNpub, keyHex) {
  const ctx = await browser.newContext();
  const pg = await ctx.newPage();
  await pg.route('https://cdn.jsdelivr.net/**', r => r.fulfill({ status: 200, contentType: 'text/javascript', body: bundle }));
  await pg.route('http://127.0.0.1:7999/', r => r.fulfill({ status: 200, contentType: 'text/html', body: html }));
  await pg.addInitScript(([b, k]) => { localStorage.setItem('nb_relay', 'ws://127.0.0.1:7447'); localStorage.setItem('nb_board', b); if (k) localStorage.setItem('nb_sk', k); }, [boardNpub, keyHex]);
  pg.on('console', m => console.log('CONSOLE', m.text())); pg.on('pageerror', e => console.log('PAGEERR', e.message));
  await pg.goto('http://127.0.0.1:7999/');
  return pg;
}
const wait = (ms) => new Promise(r => setTimeout(r, ms));
// 1) controller NOT allowed
let sim = await startSim('');
let pg = await page(sim.info.boardNpub);
await pg.waitForFunction(() => document.getElementById('boardTxt').textContent.includes('ออนไลน์'), null, { timeout: 8000 }).catch(() => {});
ok('relay connected', (await pg.textContent('#relayTxt')).includes('เชื่อมต่อ relay แล้ว'));
ok('board online from C-signed status', (await pg.textContent('#boardTxt')).includes('ออนไลน์'));
ok('status name shown', (await pg.textContent('#sName')) === 'sim-1');
await pg.click('#ping'); await wait(800);
ok('ping answered (public command)', (await pg.textContent('#log')).includes('ping: สำเร็จ'));
await pg.click('#ledOn'); await wait(800);
ok('led refused for unknown key', (await pg.textContent('#log')).includes('not allowed'));
const myNpub = await pg.textContent('#myNpub'); const myKey = await pg.evaluate(() => localStorage.getItem('nb_sk'));
sim.p.kill(); await pg.context().close(); await wait(300);
// 2) controller allowed (same browser key)
const { getPublicKey } = await import('nostr-tools/pure');
const pkHex = getPublicKey(Uint8Array.from(myKey.match(/../g).map(x => parseInt(x, 16))));
sim = await startSim(pkHex);
pg = await page(sim.info.boardNpub, myKey);
await pg.waitForFunction(() => document.getElementById('boardTxt').textContent.includes('ออนไลน์'), null, { timeout: 8000 }).catch(() => {});
await pg.click('#ledOn'); await wait(1200);
ok('led on accepted for allowed key', (await pg.textContent('#log')).includes('LED เปิด: สำเร็จ'));
ok('status shows led on', (await pg.textContent('#sLed')) === 'เปิด');
await pg.click('#ledTog'); await wait(1200);
ok('toggle -> off', (await pg.textContent('#sLed')) === 'ปิด');
// 3) page reload gets the stored status immediately; board stop -> offline detection not tested (age based)
await pg.reload(); await pg.waitForFunction(() => document.getElementById('sName').textContent === 'sim-1', null, { timeout: 5000 }).catch(() => {});
ok('status restored after reload', (await pg.textContent('#sName')) === 'sim-1');
// 4) relay dies -> UI shows disconnected, then reconnects
sim.p.kill(); await wait(800);
ok('shows disconnected', (await pg.textContent('#relayTxt')).includes('หลุด'));
console.log(sim.out.split('\n').filter(l => l.startsWith('SIM')).join('\n'));
await browser.close();
const fails = results.filter(r => !r[1]).length; console.log(`ui: ${results.length - fails}/${results.length} pass`); process.exit(fails ? 1 : 0);
