## 💖 Support this project

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-GitHub-pink?logo=github)](https://github.com/sponsors/DJBenson)
[![Ko-fi](https://img.shields.io/badge/Support-Ko--fi-ff5f5f?logo=ko-fi)](https://ko-fi.com/djbenson)
[![PayPal](https://img.shields.io/badge/Donate-PayPal-blue?logo=paypal)](https://paypal.me/jonathanthomson81)

# ocpp-proxy

A WebSocket proxy and charger simulator for OCPP 1.6 traffic. Useful for understanding what your charger is sending to the cloud, testing integrations against a fake charger, or spoofing charger identity to a different OCPP backend.

## What it does

The tool has three operating modes:

**proxy** — sits between your charger and the upstream OCPP server, logging all frames in both directions. Everything passes through transparently.

**masquerade** — same as proxy, but intercepts the `BootNotification` frame and rewrites the vendor, model, firmware, and/or serial fields before forwarding upstream. The upstream sees a different charger identity; the real charger is untouched.

**simulate** — no real charger needed. Connects directly to the upstream pretending to be one or more chargers, keeps charger-local state, handles common portal commands, and emits realistic charger-side traffic such as status changes, transactions, firmware status notifications, CP reads, heartbeats, and meter values.

## Setup

### DNS spoofing (proxy / masquerade modes)

To intercept a charger's traffic, point its upstream hostname at the machine running the proxy (e.g. via Pi-hole or your router's local DNS). The proxy resolves the real upstream hostname independently, so it bypasses your local DNS and connects to the actual server.

### Dependencies

```
pip install aiohttp>=3.9
```

## Usage

All modes require `--upstream` to specify the OCPP server URL.

### Proxy mode

Transparent passthrough — logs everything, touches nothing:

```bash
python ocpp-proxy.py --upstream wss://ocpp.example.com:7655 proxy
```

With TLS (if your charger refuses plain WebSocket):

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
    -subj "/CN=ocpp.example.com"

python ocpp-proxy.py --upstream wss://ocpp.example.com:7655 proxy --tls --cert cert.pem --key key.pem
```

If the upstream requires basic auth:

```bash
python ocpp-proxy.py --upstream wss://ocpp.example.com:7655 proxy \
    --upstream-charge-point-id YOUR_CPID \
    --upstream-password YOUR_PASSWORD
```

### Masquerade mode

Replace identity fields in `BootNotification` before they reach the upstream. Only the fields you specify are overridden — omit any to leave them as-is:

```bash
python ocpp-proxy.py --upstream wss://ocpp.example.com:7655 masquerade \
    --vendor ACME \
    --model VirtualCharger \
    --serial 000000000001
```

### Simulate mode

Fake charger that connects upstream and handles portal commands:

```bash
python ocpp-proxy.py --upstream wss://ocpp.example.com:7655 simulate \
    --charge-point-id 12345678901234 \
    --vendor MyVendor \
    --model SingleSocketCharger \
    --firmware 1.0.0 \
    --serial 12345678901234
```

Stateful single-charger simulation with explicit intervals and limits:

```bash
python ocpp-proxy.py --upstream wss://ocpp.example.com:7655 simulate \
    --charge-point-id 12345678901234 \
    --vendor MyVendor \
    --model SingleSocketCharger \
    --firmware 1.0.0 \
    --serial 12345678901234 \
    --heartbeat-interval 60 \
    --meter-interval 15 \
    --current-limit 32 \
    --max-import-current 80 \
    --charge-mode Boost
```

Simulate multiple chargers concurrently from one JSON file:

```bash
python ocpp-proxy.py --upstream wss://ocpp.example.com:7655 simulate --charger-config chargers.json
```

Example `chargers.json`:

```json
[
  {
    "charge_point_id": "12345678901234",
    "vendor": "MyVendor",
    "model": "SingleSocketCharger",
    "firmware": "1.0.0",
    "serial": "12345678901234",
    "meter_value_sample_interval_seconds": 15
  },
  {
    "charge_point_id": "56789012345678",
    "vendor": "MyVendor",
    "model": "SingleSocketCharger",
    "firmware": "1.0.0",
    "serial": "56789012345678",
    "connect_delay_seconds": 5
  }
]
```

Add `--verbose` to any command to also log the boot handshake frames (`BootNotification`, `Heartbeat`, `StatusNotification`, etc.) — these are hidden by default to reduce noise.

## Running as a Home Assistant add-on

The repo includes a `Dockerfile` and `config.yaml` for running as an HA add-on. Configure the mode and options via the add-on UI — the available fields map 1:1 to the CLI flags above.

Supported architectures: `amd64`, `aarch64`, `armv7`.
