# ocpp-proxy

A WebSocket proxy and charger simulator for OCPP 1.6 traffic, originally built to sniff and debug GivEnergy EV charger communications. Useful for understanding what your charger is sending to the cloud, testing integrations against a fake charger, or spoofing charger identity to a different OCPP backend.

## What it does

The tool has three operating modes:

**proxy** — sits between your charger and the upstream OCPP server, logging all frames in both directions. The charger thinks it's talking to GivEnergy; GivEnergy thinks it's talking to your charger. Everything passes through transparently.

**masquerade** — same as proxy, but intercepts the `BootNotification` frame and rewrites the vendor, model, firmware, and/or serial fields before forwarding upstream. The upstream sees a different charger identity; the real charger is untouched.

**simulate** — no real charger needed. Connects directly to the upstream pretending to be a charger, completes the boot handshake, then idles and logs any commands the portal sends down.

## Setup

### DNS spoofing (proxy / masquerade modes)

Point `ev.comms.givenergy.cloud` at the machine running the proxy (e.g. via Pi-hole or your router's local DNS). The proxy resolves the real upstream hostname independently, so it bypasses your local DNS and connects to the actual server.

### Dependencies

```
pip install aiohttp>=3.9
```

## Usage

### Proxy mode

Transparent passthrough — logs everything, touches nothing:

```bash
python proxy.py proxy
```

With TLS (if your charger refuses plain WebSocket):

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
    -subj "/CN=ev.comms.givenergy.cloud"

python proxy.py proxy --tls --cert cert.pem --key key.pem
```

If the upstream requires basic auth (e.g. Octopus Energy):

```bash
python proxy.py proxy \
    --upstream-charge-point-id YOUR_CPID \
    --upstream-password YOUR_PASSWORD
```

### Masquerade mode

Replace identity fields in `BootNotification` before they reach the upstream. Only the fields you specify are overridden — omit any to leave them as-is:

```bash
python proxy.py masquerade \
    --vendor ACME \
    --model VirtualCharger \
    --serial 000000000001
```

### Simulate mode

Fake charger that connects upstream and handles portal commands:

```bash
python proxy.py simulate \
    --charge-point-id 11288853545694 \
    --vendor WWWW \
    --model SingleSocketCharger \
    --firmware AC_GL1_1.14 \
    --serial 11288853545694
```

Add `--verbose` to any command to also log the boot handshake frames (`BootNotification`, `Heartbeat`, `StatusNotification`, etc.) — these are hidden by default to reduce noise.

### Changing the upstream

All modes accept `--upstream` to point at a different OCPP server:

```bash
python proxy.py proxy --upstream wss://some.other.server:7655
```

Default is `wss://ev.comms.givenergy.cloud:7655`.

## Running as a Home Assistant add-on

The repo includes a `Dockerfile` and `config.yaml` for running as an HA add-on. Configure the mode and options via the add-on UI — the available fields map 1:1 to the CLI flags above.

Supported architectures: `amd64`, `aarch64`, `armv7`.
