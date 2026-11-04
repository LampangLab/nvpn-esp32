// Runs the REAL NostrBoard.ino logic (host-compiled with Arduino stubs) against events signed by nostr-tools.
import { execSync, spawn } from 'node:child_process';
import { generateSecretKey, getPublicKey, finalizeEvent, verifyEvent } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
const S = '/tmp/claude-0/-home-claude/2da64ae9-cd8f-5675-834b-b983048861b1/scratchpad';
const N = '/home/claude/nvpn-esp32', T = N + '/test';
const askSk = generateSecretKey(), askPk = getPublicKey(askSk), otherSk = generateSecretKey();
const sh = (c) => execSync(c, { cwd: S, stdio: ['ignore', 'pipe', 'pipe'] });
sh(`sed 's|const char \\*CONTROLLERS\\[\\] = { "" };|const char *CONTROLLERS[] = { "${askPk}" };|' ${N}/examples/arduino/NostrBoard/NostrBoard.ino > NostrBoard_check.cpp`);
sh(`g++ -std=c++17 -O1 -g -w -Istub -Iaj/src -I${N}/include -I${N}/examples/arduino/NostrBoard -include stub/Arduino.h harness_main.cpp stub/nvpn_core.o stub/nvpn_sha256.o ${T}/secp256k1.o ${T}/pre_ecmult.o ${T}/pre_gen.o -o harness`);
const p = spawn(S + '/harness', [], { cwd: S }); let out = '', err = '';
p.stdout.on('data', d => out += d); p.stderr.on('data', d => err += d);
await new Promise(r => setTimeout(r, 400));
const boardPk = /board key: .*\n\s+([0-9a-f]{64})/.exec(err)[1];
const now = Math.floor(Date.now() / 1000);
const cmd = (sk, content, o = {}) => finalizeEvent({ kind: o.kind ?? 21078, created_at: o.t ?? now, tags: o.tags ?? [['p', boardPk]], content }, sk);
const lines = []; const push = (ev) => lines.push(JSON.stringify(['EVENT', 'cmd', ev]));
const e_ping = cmd(otherSk, '{"cmd":"ping"}');                    push(e_ping);                         // 1 public ping -> pong
const e_ledDeny = cmd(otherSk, '{"cmd":"led","arg":1}');          push(e_ledDeny);                      // 2 privileged from unknown -> denied
const e_ledOk = cmd(askSk, '{"cmd":"led","arg":1}');              push(e_ledOk);                        // 3 allowed -> ok + status
push(e_ledOk);                                                                                           // 4 duplicate -> ignored
push(cmd(askSk, '{"cmd":"led","arg":0}', { t: now - 300 }));                                             // 5 stale -> ignored
const bad = cmd(askSk, '{"cmd":"led","arg":0}'); bad.content = '{"cmd":"led","arg":1}'; push(bad);        // 6 tampered -> ignored
push(cmd(askSk, '{"cmd":"led","arg":0}', { kind: 21999 }));                                              // 7 wrong kind -> ignored
const e_tog = cmd(askSk, '{"cmd":"led","arg":"toggle"}', { tags: [['p', boardPk], ['x', 'บอร์ด "q"']] }); push(e_tog); // 8 toggle (unicode tag) -> ok led off
const e_unk = cmd(askSk, '{"cmd":"format"}'); push(e_unk);                                               // 9 unknown cmd
lines.push('not json'); lines.push(JSON.stringify(['NOTICE', 'hi']));                                    // 10 garbage tolerated
for (const l of lines) p.stdin.write(l + '\n'); p.stdin.end();
await new Promise(r => p.on('close', r));
const sent = out.split('\n').filter(l => l.startsWith('SEND ')).map(l => JSON.parse(l.slice(5)));
const evs = sent.filter(m => m[0] === 'EVENT').map(m => m[1]);
let pass = 0, fail = 0; const ok = (n, c) => { console.log((c ? 'PASS ' : 'FAIL ') + n); c ? pass++ : fail++; };
ok('every board-signed event verifies in nostr-tools', evs.length > 0 && evs.every(e => verifyEvent(e) && e.pubkey === boardPk));
const replies = evs.filter(e => e.kind === 21079), stat = evs.filter(e => e.kind === 21080);
const rOf = (id) => { const r = replies.find(e => e.tags.some(t => t[0] === 'e' && t[1] === id)); return r && JSON.parse(r.content); };
ok('REQ sent on connect', sent.some(m => m[0] === 'REQ' && m[2].kinds[0] === 21078 && m[2]['#p'][0] === boardPk));
ok('initial status published (ephemeral kind 21080, not 30078)', stat.length > 0 && !evs.some(e => e.kind === 30078));
ok('ping -> pong, reply tagged to sender', rOf(e_ping.id)?.msg === 'pong' && replies.find(e => e.tags.some(t => t[0] === 'e' && t[1] === e_ping.id)).tags.some(t => t[0] === 'p' && t[1] === e_ping.pubkey));
ok('led from unknown key denied', rOf(e_ledDeny.id)?.ok === false && rOf(e_ledDeny.id)?.msg === 'not allowed');
ok('led from allowed key accepted', rOf(e_ledOk.id)?.ok === true && rOf(e_ledOk.id)?.msg === 'led on');
ok('duplicate/stale/tampered/wrong-kind ignored (exactly 1 reply for e_ledOk)', replies.filter(e => e.tags.some(t => t[0] === 'e' && t[1] === e_ledOk.id)).length === 1 && replies.length === 5);
ok('toggle with unicode tag accepted -> led off', rOf(e_tog.id)?.msg === 'led off');
ok('unknown command rejected', rOf(e_unk.id)?.msg === 'unknown command');
const leds = stat.map(e => JSON.parse(e.content).led); ok('status follows led state (0,1,0)', JSON.stringify(leds) === '[0,1,0]');
console.log(`board harness: ${pass}/${pass + fail} pass`); if (fail) { console.log(out.slice(0, 2000)); console.log(err.slice(-1500)); } process.exit(fail ? 1 : 0);
