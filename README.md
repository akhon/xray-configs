# Xray Core – Working Configs

This repository contains **proven, working xray-core configurations** that were actually deployed and used in real environments.

The goal of this repo:
- keep **reliable baseline configs**
- have a quick fallback when experimenting
- avoid re-generating keys and UUIDs every time

---

## Contents

- `brume2-bot/` — Telegram bot, Hysteria QR/client exports, private weekly statistics, trends and a local dashboard, and optional legacy Xray support ([documentation](brume2-bot/README.md))
- `xray-core-vless-reality.json` — VLESS + REALITY (experimental, environment-dependent)
- `xray-core-vmess-ja3-working.json` — VMess + TLS (JA3 / HTTPS camouflage, working setup)
- `xray-core-vmess-working.json` — VMess + TCP without TLS (baseline, most stable)

---

## Brume 2 Telegram bot and user statistics

The [bot package](brume2-bot/README.md) manages an existing OpenWrt Hysteria 2 installation, with optional legacy Xray support.

- One configured owner can use private `/stats` for the current reporting week and the common commands.
- Authorized groups retain shared-user statistics; private accounts are excluded from their traffic reports and all Telegram credential exports.
- `/qr label hiddify` generates a QR locally with the trusted public certificate and an importable profile name.
- Persistent one-minute history produces actual weekly usage, with reset/gap warnings and exact reporting dates. The reporting week starts Monday 14:00 UTC.
- Like-for-like weekly comparisons and daily charts keep incomplete history visible; an optional loopback dashboard archives counters on the Mac over SSH.
- Group/sender allowlists and a separate private owner ID enforce access. Telegram cannot create VPN users.

Updated Hysteria server, bot, private-report and cron **examples** are in `brume2-bot/examples/`. They use placeholders; keep actual passwords, Telegram tokens, keys, personal IDs and client profiles on the router or in an authorized private delivery channel.

Run tests with:

```sh
python3 -m unittest discover -s brume2-bot/tests -v
```

See the [package README](brume2-bot/README.md) for installation, access rules, TLS/QR compatibility, history limitations, legacy migration and validation.

---

## Requirements

- xray-core
- Linux / OpenWrt
- open TCP port `443`
- TLS certificate (for TLS configs)

---

## UUID Generation (VMess / VLESS)

Each user or device **must have its own UUID**.

### Using xray
```sh
xray uuid
```

### Using system tools
```sh
uuidgen
```

Example UUID:
```
11111111-1111-4111-8111-111111111111
```

Used in config as:
```json
"id": "UUID"
```

---

## VLESS + REALITY

### X25519 Key Generation

REALITY uses **X25519** keys.

> Note: the `xray x25519` command is **not available in older xray-core versions**.

#### Option A (if supported by your xray version)
```sh
xray x25519
```

Output example:
```
PrivateKey:  <PRIVATE_KEY>
PublicKey:   <PUBLIC_KEY>
```

#### Practical fallback (recommended)
If the command is unavailable on your router/device:
- generate the key pair on **any other machine** where `xray x25519` is available
- copy `PrivateKey` to the server
- use `PublicKey` on clients

- `PrivateKey` — server only
- `PublicKey` — client side
- **never share the private key**

---

### shortId Generation

`shortId` is a short hex identifier (4–16 hex characters).

```sh
# 4 bytes (8 hex chars)
openssl rand -hex 4
```

```sh
# 8 bytes (16 hex chars)
openssl rand -hex 8
```

Example:
```
6a1f9c2d
```

Used in config as:
```json
"shortIds": ["SHORT_ID"]
```

---

### What to replace in `xray-core-vless-reality.json`

- `UUID`
- `PRIVATE_KEY`
- `SHORT_ID`
- optionally `dest` and `serverNames`

---

## VMess + TLS

### Certificates

TLS configs require a **certificate and private key**.

Paths used in config:
```json
"certificateFile": "/etc/xray/certs/server.crt",
"keyFile": "/etc/xray/certs/server.key"
```

---

### Self-signed certificate (no domain)

⚠️ Not recommended for production, but useful for testing.

```sh
openssl req -x509 -newkey rsa:2048   -keyout server.key   -out server.crt   -days 3650   -nodes   -subj "/CN=example.com"
```

Install:
```sh
mkdir -p /etc/xray/certs
cp server.crt /etc/xray/certs/server.crt
cp server.key /etc/xray/certs/server.key
```

---

## VMess + TCP (No TLS)

This is the **baseline configuration**, used for:
- diagnostics
- fallback
- maximum stability

Only UUID generation is required.

---

## Running and Testing

### Validate config
```sh
xray run -c config.json
```

### Successful startup indicators
- port is in `LISTEN` state
- logs show:
```
accepted tcp:
```

---

## Recommendations

- 1 UUID = 1 user/device
- Do not use `alterId` (deprecated)
- For iOS clients:
  - disable mux / xudp
  - avoid flow / vision
- Always keep a **plain VMess config** as fallback

---

## Important Notes

VLESS + REALITY is **environment-sensitive**:
- may not work on OpenWrt / musl
- stable on glibc Linux / VPS / x86

If REALITY does not work, it is usually **not a config issue**.

---

## License

Use at your own risk.
