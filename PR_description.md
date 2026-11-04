# docs: interop notes for small FIPS / nostr-vpn clients (ESP32 leaf)

Adds `docs/INTEROP.md` to the independent C port at https://github.com/LampangLab/nvpn-esp32 (not a PR to nostr-vpn itself unless you want these notes upstreamed; text is ready to move).

Contents:
- tested versions (app 4.1.19 / core 0.4.110; host nodes 0.4.107 and 0.4.110; seed 4.1.17 / core 0.4.96)
- client-only negotiation for an MCU leaf, including what to do when the upstream has no leaf support (stay silent, retry; never advertise as router)
- why a leaf needs session `ReceiverReport`s (recovery rekey every ~60 s without them) and the 66-byte body check against the real decoder
- `NVPN-FIPS-CTRL` Ping/Pong handling
- four hardware runs, with the recovery-rekey counts before/after
- open items: JoinRoster over 7370, phone-to-board across networks, reconnect behaviour

No code changes in this PR.
