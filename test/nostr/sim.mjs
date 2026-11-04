// mock relay + board simulator that uses the REAL C code (nostr_tool) to verify commands and sign status/replies
import { WebSocketServer } from 'ws';
import { spawnSync } from 'node:child_process';
import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
import { nip19 } from 'nostr-tools';
const PORT = +process.env.PORT || 7447;
const boardSk = generateSecretKey(); const boardSkH = bytesToHex(boardSk); const boardPk = getPublicKey(boardSk);
export const info = { boardNpub: nip19.npubEncode(boardPk), boardPk };
const allow = new Set((process.env.ALLOW || '').split(',').filter(Boolean));   // controller pubkeys (hex)
const wss = new WebSocketServer({ port: PORT });
const subs = new Map(); const stored = new Map();     // ws -> Map(subid -> filter); addressable store
const match = (f, ev) => (!f.kinds || f.kinds.includes(ev.kind)) && (!f.authors || f.authors.includes(ev.pubkey)) &&
  (!f['#p'] || ev.tags.some(t => t[0]==='p' && f['#p'].includes(t[1]))) && (!f['#d'] || ev.tags.some(t => t[0]==='d' && f['#d'].includes(t[1]))) &&
  (!f.since || ev.created_at >= f.since);
function publish(ev, from) {
  for (const [w, m] of subs) for (const [id, f] of m) if (w !== from || true) if (match(f, ev) && w.readyState === 1) w.send(JSON.stringify(['EVENT', id, ev]));
}
const cSign = (kind, tags, content) => JSON.parse(spawnSync('./nostr_tool', ['sign', boardSkH, String(Math.floor(Date.now()/1000)), String(kind), JSON.stringify(tags), content]).stdout.toString());
let led = 0; const seen = new Set(); const t0 = Date.now();
function status() { publish(cSign(21080, [['name','sim-1']], JSON.stringify({name:'sim-1',up:Math.floor((Date.now()-t0)/1000),heap:200000,rssi:-55,led,t:Math.floor(Date.now()/1000)}))); }
function reply(toPk, id, ok, msg) { publish(cSign(21079, [['p',toPk],['e',id]], JSON.stringify({ok,msg}))); }
function boardHandle(ev) {   // mirrors NostrBoard.ino handleEvent
  if (ev.kind !== 21078) return;
  const r = spawnSync('./nostr_tool', ['check', ev.pubkey, String(ev.created_at), String(ev.kind), JSON.stringify(ev.tags), ev.content, ev.id, ev.sig]);
  if (r.status !== 0) { console.log('SIM bad signature'); return; }
  const now = Math.floor(Date.now()/1000); if (ev.created_at + 90 < now || ev.created_at > now + 90) { console.log('SIM stale'); return; }
  if (seen.has(ev.id)) return; seen.add(ev.id);
  const priv = allow.has(ev.pubkey); let c; try { c = JSON.parse(ev.content); } catch { return; }
  console.log('SIM cmd', c.cmd, 'priv', priv);
  if (c.cmd === 'ping') return reply(ev.pubkey, ev.id, true, 'pong');
  if (c.cmd === 'status') { reply(ev.pubkey, ev.id, true, 'status sent'); return status(); }
  if (!priv) return reply(ev.pubkey, ev.id, false, 'not allowed');
  if (c.cmd === 'led') { led = c.arg === 'toggle' ? 1 - led : (c.arg ? 1 : 0); reply(ev.pubkey, ev.id, true, led ? 'led on' : 'led off'); return status(); }
  reply(ev.pubkey, ev.id, false, 'unknown command');
}
wss.on('connection', (w) => {
  subs.set(w, new Map());
  w.on('message', (d) => { let a; try { a = JSON.parse(d); } catch { return; }
    if (a[0] === 'REQ') { subs.get(w).set(a[1], a[2]); for (const ev of stored.values()) if (match(a[2], ev)) w.send(JSON.stringify(['EVENT', a[1], ev])); w.send(JSON.stringify(['EOSE', a[1]])); }
    else if (a[0] === 'EVENT') { const ev = a[1]; if (!verifyEvent(ev)) return w.send(JSON.stringify(['OK', ev.id, false, 'invalid'])); w.send(JSON.stringify(['OK', ev.id, true, ''])); publish(ev, w); if (ev.tags.some(t=>t[0]==='p'&&t[1]===boardPk)) boardHandle(ev); }
    else if (a[0] === 'CLOSE') subs.get(w).delete(a[1]); });
  w.on('close', () => subs.delete(w));
});
setInterval(status, 30000); setTimeout(status, 200);
console.log(JSON.stringify(info)); 
