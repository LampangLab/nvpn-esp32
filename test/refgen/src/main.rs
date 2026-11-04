// Reference vector generator: uses the same crates (nostr 0.44) and the same
// algorithms, copied verbatim from nostr-vpn-core, to produce expected values.
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use serde_json::{json, Value};
use std::collections::HashMap;

const KIND: u16 = 30_388;

fn normalize_runtime_network_id(value: &str) -> String {
    let trimmed = value.trim();
    let without_prefix = trimmed.strip_prefix("nostr-vpn:").unwrap_or(trimmed).trim();
    let compact = without_prefix.chars().filter(|ch| !ch.is_whitespace() && *ch != '-').collect::<String>();
    if compact.is_empty() && without_prefix.chars().all(|ch| ch.is_whitespace() || ch == '-') {
        return String::new();
    }
    if !compact.is_empty() && compact.chars().all(|ch| ch.is_ascii_hexdigit()) {
        compact.to_ascii_lowercase()
    } else {
        without_prefix.to_string()
    }
}

fn derive_mesh_tunnel_ip(network_id: &str, own_pubkey_hex: &str) -> Option<String> {
    let network_id = normalize_runtime_network_id(network_id);
    let network_id = network_id.trim();
    let own_pubkey_hex = own_pubkey_hex.trim();
    if network_id.is_empty() || own_pubkey_hex.is_empty() { return None; }
    let mut hasher = Sha256::new();
    hasher.update(network_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(own_pubkey_hex.as_bytes());
    let digest = hasher.finalize();
    Some(format!("10.44.{}.{}", (digest[0] % 254) + 1, (digest[1] % 254) + 1))
}

fn normalize_magic_dns_label(value: &str) -> Option<String> {
    let mut label = String::new();
    let mut previous_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() { label.push(ch.to_ascii_lowercase()); previous_dash = false; }
        else if !previous_dash { label.push('-'); previous_dash = true; }
    }
    while label.ends_with('-') { label.pop(); }
    while label.starts_with('-') { label.remove(0); }
    if label.is_empty() { return None; }
    if label.len() > 63 { label.truncate(63); while label.ends_with('-') { label.pop(); } }
    if label.is_empty() { None } else { Some(label) }
}

fn tag(parts: &[&str]) -> Tag { Tag::parse(parts.iter().copied()).unwrap() }

// Mirrors signed_roster_tags() + SignedRoster::sign() in fips_control.rs.
fn sign_roster(network_id: &str, name: &str, devices: &[String], admins: &[String],
               aliases: &HashMap<String, String>, signed_at: u64, keys: &Keys) -> Event {
    let mut tags = vec![Tag::identifier(network_id.trim().to_string()),
        tag(&["app", "nostr-vpn/shared-roster"]), tag(&["v", "1"])];
    if !name.trim().is_empty() { tags.push(tag(&["name", name.trim()])); }
    let mut d: Vec<String> = devices.to_vec(); d.sort(); d.dedup();
    for x in d { tags.push(tag(&["member", &x])); }
    let mut a: Vec<String> = admins.to_vec(); a.sort(); a.dedup();
    for x in a { tags.push(tag(&["admin", &x])); }
    let mut al: Vec<_> = aliases.iter().collect(); al.sort_by(|l, r| l.0.cmp(r.0));
    for (pk, alias) in al { let alias = alias.trim(); if !alias.is_empty() { tags.push(tag(&["alias", pk, alias])); } }
    EventBuilder::new(Kind::Custom(KIND), "").tags(tags)
        .custom_created_at(Timestamp::from(signed_at)).sign_with_keys(keys).unwrap()
}

fn main() {
    let mut out = serde_json::Map::new();

    // network id normalisation
    let nids = ["Home", "  mesh  ", "nostr-vpn:abc", "nostr-vpn: 12AB-cd EF ", "0123-4567-89AB-cdef",
        "550e8400-e29b-41d4-a716-446655440000", "---", "   ", "", "Net Work-1", "nostr-vpn:", "ABCDEFG", "a b"];
    out.insert("netids".into(), Value::Array(nids.iter().map(|n| json!({"in": n, "out": normalize_runtime_network_id(n)})).collect()));

    // keys (deterministic) + npub + tunnel IPs
    let mut keys_v = vec![]; let mut ips = vec![]; let mut keys: Vec<Keys> = vec![];
    for i in 1u8..=6 {
        let mut sk = [0u8; 32]; sk[31] = i; sk[0] = 0x11 * i;
        let k = Keys::new(SecretKey::from_slice(&sk).unwrap());
        keys_v.push(json!({"sk": k.secret_key().to_secret_hex(), "pk": k.public_key().to_hex(), "npub": k.public_key().to_bech32().unwrap()}));
        for nid in ["home", "nostr-vpn:550E8400-e29b-41d4-a716-446655440000", "Mesh One"] {
            ips.push(json!({"net": nid, "pk": k.public_key().to_hex(), "ip": derive_mesh_tunnel_ip(nid, &k.public_key().to_hex())}));
        }
        keys.push(k);
    }
    out.insert("keys".into(), Value::Array(keys_v));
    out.insert("ips".into(), Value::Array(ips));

    // labels
    let long70 = "x".repeat(70); let long63 = format!("{}-{}", "y".repeat(62), "z");
    let labels = ["Living Room", "  Pi--Zero  ", "ESP32_#1", "café", "日本語", "a", "---", long70.as_str(), long63.as_str(), "UPPER", "", "-lead", "trail-", "a  b__c"];
    out.insert("labels".into(), Value::Array(labels.iter().map(|l| json!({"in": l, "out": normalize_magic_dns_label(l)})).collect()));

    // rosters
    let admin = &keys[0];
    let hex = |i: usize| keys[i].public_key().to_hex();
    let mut rosters = vec![];
    let mut al = HashMap::new();
    al.insert(hex(1), "Living Room".to_string());
    al.insert(hex(2), "esp32-sensor".to_string());
    al.insert(hex(0), "admin box".to_string());
    let ev = sign_roster("home", "Home Mesh", &[hex(1), hex(2), hex(3)], &[hex(0)], &al, 1_800_000_000, admin);
    let mut devs = vec![hex(1), hex(2), hex(3)]; devs.sort();
    let mut alias_json = serde_json::Map::new();
    for (k, v) in &al { alias_json.insert(k.clone(), json!(v)); }
    rosters.push(json!({"name": "basic", "event": serde_json::to_string(&ev).unwrap(), "ok": true,
        "network_id": "home", "net_name": "Home Mesh", "signed_at": 1_800_000_000u64, "id": ev.id.to_hex(), "signer": hex(0),
        "devices": devs, "admins": [hex(0)], "aliases": alias_json}));
    // wrapped SignedRoster {"event": {...}}
    rosters.push(json!({"name": "wrapped", "event": format!("{{\"event\":{}}}", serde_json::to_string(&ev).unwrap()), "ok": true,
        "network_id": "home", "signed_at": 1_800_000_000u64, "id": ev.id.to_hex()}));
    // hostile strings in name/alias
    let mut al2 = HashMap::new();
    al2.insert(hex(1), "q\"uo\\te\n\ttab\u{1}\u{1f} é 😀 \u{7f}".to_string());
    let ev2 = sign_roster("uuid-ish-1234", "Näme \"x\" 😀", &[hex(1)], &[hex(0), hex(2)], &al2, 1_700_000_001, admin);
    rosters.push(json!({"name": "escapes", "event": serde_json::to_string(&ev2).unwrap(), "ok": true,
        "network_id": "uuid-ish-1234", "signed_at": 1_700_000_001u64, "id": ev2.id.to_hex()}));
    // same event but with \u-escaped spelling & reordered keys & whitespace (valid JSON, same event)
    let v: Value = serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
    let reordered = format!("{{ \"sig\" : {}, \"tags\" : {}, \"content\":\"\",\"kind\":{}, \"created_at\":{},\"pubkey\":{},\"id\":{} }}",
        v["sig"], v["tags"], v["kind"], v["created_at"], v["pubkey"], v["id"]);
    rosters.push(json!({"name": "reordered", "event": reordered, "ok": true, "network_id": "home", "signed_at": 1_800_000_000u64, "id": ev.id.to_hex()}));
    // unicode-escaped alias spelling: rewrite "é" as é and emoji as surrogate pair in the JSON text
    let esc = serde_json::to_string(&ev2).unwrap().replace('é', "\\u00e9").replace('😀', "\\ud83d\\ude00");
    rosters.push(json!({"name": "unicode-escaped", "event": esc, "ok": true, "network_id": "uuid-ish-1234", "signed_at": 1_700_000_001u64, "id": ev2.id.to_hex()}));
    // negative: tampered tag, tampered sig, wrong kind, non-empty content, missing app
    let tampered = serde_json::to_string(&ev).unwrap().replace("Home Mesh", "Home Mash");
    rosters.push(json!({"name": "tampered-name", "event": tampered, "ok": false, "err": "ID"}));
    let mut sigbad: Value = serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
    let s = sigbad["sig"].as_str().unwrap().to_string();
    let flipped = format!("{}{}", &s[..127], if s.ends_with('0') { "1" } else { "0" });
    sigbad["sig"] = json!(flipped);
    rosters.push(json!({"name": "bad-sig", "event": sigbad.to_string(), "ok": false, "err": "SIG"}));
    let wrongkind = EventBuilder::new(Kind::Custom(30_389), "").tags(vec![Tag::identifier("home"), tag(&["app", "nostr-vpn/shared-roster"]), tag(&["v", "1"])]).sign_with_keys(admin).unwrap();
    rosters.push(json!({"name": "wrong-kind", "event": serde_json::to_string(&wrongkind).unwrap(), "ok": false, "err": "KIND"}));
    let content = EventBuilder::new(Kind::Custom(KIND), "hi").tags(vec![Tag::identifier("home"), tag(&["app", "nostr-vpn/shared-roster"]), tag(&["v", "1"])]).sign_with_keys(admin).unwrap();
    rosters.push(json!({"name": "content", "event": serde_json::to_string(&content).unwrap(), "ok": false, "err": "CONTENT"}));
    let noapp = EventBuilder::new(Kind::Custom(KIND), "").tags(vec![Tag::identifier("home"), tag(&["v", "1"])]).sign_with_keys(admin).unwrap();
    rosters.push(json!({"name": "no-app", "event": serde_json::to_string(&noapp).unwrap(), "ok": false, "err": "ROSTER"}));
    // member given as npub, must normalise
    let npub_member = EventBuilder::new(Kind::Custom(KIND), "").tags(vec![Tag::identifier("home"), tag(&["app", "nostr-vpn/shared-roster"]), tag(&["v", "1"]),
        tag(&["member", &keys[1].public_key().to_bech32().unwrap()]), tag(&["admin", &hex(0)])]).custom_created_at(Timestamp::from(1_800_000_100)).sign_with_keys(admin).unwrap();
    rosters.push(json!({"name": "npub-member", "event": serde_json::to_string(&npub_member).unwrap(), "ok": true, "network_id": "home", "signed_at": 1_800_000_100u64, "id": npub_member.id.to_hex(), "devices": [hex(1)], "admins": [hex(0)]}));
    // newer roster signed by admin, and one signed by a non-admin
    let newer = sign_roster("home", "Home Mesh", &[hex(1), hex(2), hex(3), hex(4)], &[hex(0)], &al, 1_800_000_500, admin);
    rosters.push(json!({"name": "newer", "event": serde_json::to_string(&newer).unwrap(), "ok": true, "network_id": "home", "signed_at": 1_800_000_500u64, "id": newer.id.to_hex()}));
    let rogue = sign_roster("home", "Home Mesh", &[hex(1), hex(5)], &[hex(5)], &HashMap::new(), 1_800_000_900, &keys[5]);
    rosters.push(json!({"name": "rogue", "event": serde_json::to_string(&rogue).unwrap(), "ok": true, "network_id": "home", "signed_at": 1_800_000_900u64, "id": rogue.id.to_hex()}));
    // capacity: 40 devices
    let many: Vec<String> = (0..40).map(|_| Keys::generate().public_key().to_hex()).collect();
    let big = sign_roster("big", "Big", &many, &[hex(0)], &HashMap::new(), 1_800_000_000, admin);
    rosters.push(json!({"name": "too-many", "event": serde_json::to_string(&big).unwrap(), "ok": false, "err": "CAPACITY"}));
    out.insert("rosters".into(), Value::Array(rosters));

    // schnorr: sign with the Rust lib, C must verify; C signs, Rust side verifies in-test via vector of C output later
    let msg = Sha256::digest(b"nvpn-esp32 schnorr vector");
    let sig = keys[0].sign_schnorr(&secp256k1::Message::from_digest(msg.into()));
    out.insert("schnorr".into(), json!({"pk": hex(0), "msg": hex::encode(msg), "sig": sig.to_string()}));
    println!("{}", serde_json::to_string_pretty(&Value::Object(out)).unwrap());
}
mod hex { pub fn encode(b: impl AsRef<[u8]>) -> String { b.as_ref().iter().map(|x| format!("{:02x}", x)).collect() } }
