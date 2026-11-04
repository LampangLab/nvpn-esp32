import { generateSecretKey, getPublicKey, finalizeEvent, verifyEvent } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
import { execFileSync, spawnSync } from 'node:child_process';
const contents = ['hello', '{"cmd":"led","arg":1,"ts":1793534614}', 'line1\nline2\t"quoted" back\\slash', 'ไทย ✓ 😀 UTF-8', '', '{"a":"x\\ny"}'];
const tagsets = [[], [['p','ab'.repeat(32)]], [['d','nvpn-board'],['name','บอร์ด "1"']]];
let ok = 0, bad = 0;
for (const content of contents) for (const tags of tagsets) {
  const sk = generateSecretKey(); const skh = bytesToHex(sk); const t = 1793534614;
  // C signs -> JS verifies
  const out = execFileSync('./nostr_tool', ['sign', skh, String(t), '21078', JSON.stringify(tags), content]).toString().trim();
  const ev = JSON.parse(out);
  if (verifyEvent(ev) && ev.content === content && JSON.stringify(ev.tags) === JSON.stringify(tags)) ok++; else { bad++; console.log('C->JS FAIL', JSON.stringify(content)); }
  // JS signs -> C checks
  const e2 = finalizeEvent({ kind: 21078, created_at: t, tags, content }, sk);
  const r = spawnSync('./nostr_tool', ['check', e2.pubkey, String(t), '21078', JSON.stringify(tags), content, e2.id, e2.sig]);
  if (r.status === 0) ok++; else { bad++; console.log('JS->C FAIL', JSON.stringify(content)); }
  // tampered content must fail in C
  const r2 = spawnSync('./nostr_tool', ['check', e2.pubkey, String(t), '21078', JSON.stringify(tags), content + 'x', e2.id, e2.sig]);
  if (r2.status !== 0) ok++; else { bad++; console.log('tamper not detected'); }
}
console.log(`pass=${ok} fail=${bad}`); process.exit(bad ? 1 : 0);
