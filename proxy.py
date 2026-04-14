"""
OCPP WebSocket proxy / charger simulator for sniffing GivEnergy charger traffic.

PROXY MODE
    The charger connects here (acting as OCPP central system).
    This proxy connects upstream to the real GivEnergy OCPP server.
    All frames are logged in both directions before being forwarded.

    DNS setup:
        Point ev.comms.givenergy.cloud to this machine's IP on your router/Pi-hole.
        The proxy connects to the real server using its own DNS resolution so it
        bypasses your local DNS spoof.

    Example (plain WS — try this first, charger is happy without TLS):
        python proxy.py proxy

    Example (self-signed TLS, if charger rejects plain WS):
        openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=ev.comms.givenergy.cloud"
        python proxy.py proxy --tls --cert cert.pem --key key.pem

MASQUERADE MODE
    Like proxy mode, but intercepts BootNotification frames sent by the real charger
    and replaces the vendor, model, and/or serial number with configured values before
    forwarding to the upstream. The upstream sees the mock identity; the real charger
    is unaffected. All other traffic is relayed transparently.

    Example:
        python proxy.py masquerade \\
            --vendor ACME \\
            --model VirtualCharger \\
            --serial 000000000001

    Only the fields you specify are replaced — omit any to leave them as-is.

SIMULATE MODE
    Connects directly to the upstream as a fake charger — no real charger needed.
    Completes the boot handshake then sits idle, logging any commands the portal sends.
    Use --verbose to also see the full handshake frames.

    Example (minimal — uses real charger identity from diagnostics):
        python proxy.py simulate \\
            --charge-point-id 11288853545694 \\
            --vendor WWWW \\
            --model SingleSocketCharger \\
            --firmware AC_GL1_1.14 \\
            --serial 11288853545694

    Show full handshake frames too:
        python proxy.py simulate --charge-point-id 11288853545694 ... --verbose
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import ssl
import sys
from datetime import UTC, datetime
from uuid import uuid4

import aiohttp
from aiohttp import web
from urllib.parse import urlparse, urlunparse

# ── defaults ──────────────────────────────────────────────────────────────────

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 7655
DEFAULT_UPSTREAM = "wss://ev.comms.givenergy.cloud:7655"
OCPP_SUBPROTOCOL = "ocpp1.6"

# Actions that are part of the normal boot handshake — hidden unless --verbose
_HANDSHAKE_ACTIONS = {
    "BootNotification",
    "StatusNotification",
    "GetConfiguration",
    "Heartbeat",
    "TriggerMessage",
}

# ── logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
# Silence noisy asyncio/aiohttp debug output
logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)

_LOGGER = logging.getLogger("ocpp-proxy")

# Set by --verbose flag at startup
_VERBOSE = False


def _verbose(msg: str, *args: object) -> None:
    """Log only when --verbose is active."""
    if _VERBOSE:
        _LOGGER.info(msg, *args)


def _log_server_call(charge_point_id: str, action: str, payload: dict) -> None:
    """Always-visible log for a server-initiated CALL."""
    pretty = json.dumps(payload, indent=2)
    _LOGGER.info(
        "\n┌─ Portal → Charger ─────────────────────────────\n"
        "│  Action : %s\n"
        "│  Payload: %s\n"
        "└────────────────────────────────────────────────",
        action,
        pretty,
    )


def _log_charger_response(action: str, result: dict) -> None:
    """Always-visible log for our response to a server-initiated CALL."""
    pretty = json.dumps(result, indent=2)
    _LOGGER.info(
        "│  Response sent: %s\n"
        "└────────────────────────────────────────────────",
        pretty,
    )


# ── proxy session ─────────────────────────────────────────────────────────────

class ProxySession:
    """Manages a single charger ↔ proxy ↔ upstream session."""

    def __init__(
        self,
        charger_ws: web.WebSocketResponse,
        upstream_url: str,
        charge_point_id: str | None,
        masquerade: dict[str, str] | None = None,
        upstream_password: str | None = None,
        upstream_charge_point_id: str | None = None,
    ) -> None:
        self.charger_ws = charger_ws
        self.upstream_url = upstream_url
        self.charge_point_id = charge_point_id
        self.masquerade = masquerade or {}
        self.upstream_password = upstream_password
        # ID used for the upstream URL path and auth — may differ from the real charger's ID
        self.upstream_charge_point_id = upstream_charge_point_id or charge_point_id

    async def run(self) -> None:
        path = f"/{self.upstream_charge_point_id}" if self.upstream_charge_point_id else ""
        upstream_url = self.upstream_url.rstrip("/") + path

        _LOGGER.info("Charger connected (real ID: %s) — proxying to %s", self.charge_point_id, upstream_url)
        if self.masquerade:
            _LOGGER.info("Masquerade active — BootNotification overrides: %s", self.masquerade)
        if self.upstream_password:
            _LOGGER.info("Upstream basic auth enabled for upstream charge point ID: %s", self.upstream_charge_point_id)

        try:
            upstream_ssl: ssl.SSLContext | bool = (
                ssl.create_default_context() if upstream_url.startswith("wss://") else False
            )

            # Embed credentials in the URL as  wss://id:password@host/path
            # Some OCPP servers (e.g. Octopus) require this form and ignore
            # the Authorization header that aiohttp.BasicAuth would send.
            if self.upstream_password and self.upstream_charge_point_id:
                parsed = urlparse(upstream_url)
                authed_netloc = f"{self.upstream_charge_point_id}:{self.upstream_password}@{parsed.hostname}"
                if parsed.port:
                    authed_netloc += f":{parsed.port}"
                upstream_url = urlunparse(parsed._replace(netloc=authed_netloc))

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    upstream_url,
                    protocols=(OCPP_SUBPROTOCOL,),
                    ssl=upstream_ssl,
                ) as upstream_ws:
                    _LOGGER.info(
                        "Upstream connection established (protocol=%r, status=%s)",
                        upstream_ws.protocol,
                        upstream_ws._response.status,
                    )

                    charger_to_upstream = asyncio.create_task(
                        self._forward(self.charger_ws, upstream_ws, "→ upstream", rewrite=True)
                    )
                    upstream_to_charger = asyncio.create_task(
                        self._forward(upstream_ws, self.charger_ws, "← portal  ")
                    )

                    done, pending = await asyncio.wait(
                        {charger_to_upstream, upstream_to_charger},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for task in pending:
                        task.cancel()
                        try:
                            await task
                        except (asyncio.CancelledError, Exception):
                            pass

        except aiohttp.WSServerHandshakeError as err:
            _LOGGER.error(
                "Upstream WebSocket handshake failed: HTTP %s %s",
                err.status,
                err.message,
            )
        except aiohttp.ClientConnectorError as err:
            _LOGGER.error("Could not reach upstream: %s", err)
        except aiohttp.ClientError as err:
            _LOGGER.error("Upstream connection error (%s): %s", type(err).__name__, err)
        except Exception as err:
            _LOGGER.error("Unexpected error during proxy session (%s): %s", type(err).__name__, err)

        _LOGGER.info("Session ended")

    async def _forward(self, src, dst, label: str, rewrite: bool = False) -> None:
        frame_count = 0
        async for msg in src:
            if msg.type == aiohttp.WSMsgType.TEXT:
                frame_count += 1
                data = self._rewrite_boot_notification(msg.data) if rewrite and self.masquerade else msg.data
                _LOGGER.info("%s frame #%d: %s", label, frame_count, data[:200])
                self._log_proxy_frame(label, data)
                await dst.send_str(data)
            elif msg.type == aiohttp.WSMsgType.BINARY:
                frame_count += 1
                _LOGGER.info("%s binary frame #%d (%d bytes)", label, frame_count, len(msg.data))
                await dst.send_bytes(msg.data)
            elif msg.type == aiohttp.WSMsgType.ERROR:
                _LOGGER.error("%s WebSocket error: %s", label, src.exception())
                break
            elif msg.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED}:
                _LOGGER.info("%s connection closed (code=%s, reason=%r)", label, msg.data, msg.extra)
                break
        _LOGGER.info(
            "%s forward loop exited after %d frame(s) (close_code=%s)",
            label,
            frame_count,
            src.close_code if hasattr(src, "close_code") else "n/a",
        )

    def _rewrite_boot_notification(self, raw: str) -> str:
        """If this is a BootNotification CALL, replace configured fields before forwarding."""
        try:
            frame = json.loads(raw)
        except json.JSONDecodeError:
            return raw

        if not (isinstance(frame, list) and len(frame) == 4 and frame[0] == 2 and frame[2] == "BootNotification"):
            return raw

        payload: dict = frame[3]
        replacements = {}

        field_map = {
            "vendor": "chargePointVendor",
            "model": "chargePointModel",
            "serial": "chargePointSerialNumber",
            "firmware": "firmwareVersion",
        }
        for key, ocpp_field in field_map.items():
            if key in self.masquerade:
                original = payload.get(ocpp_field)
                payload[ocpp_field] = self.masquerade[key]
                replacements[ocpp_field] = (original, self.masquerade[key])

        if replacements:
            _LOGGER.info(
                "Masquerade — BootNotification fields replaced: %s",
                ", ".join(f"{f}: {o!r} → {n!r}" for f, (o, n) in replacements.items()),
            )

        frame[3] = payload
        return json.dumps(frame)

    def _log_proxy_frame(self, label: str, raw: str) -> None:
        try:
            frame = json.loads(raw)
            # frame[2] is the action string only for CALL frames (msg_type == 2)
            action = (
                frame[2]
                if isinstance(frame, list) and len(frame) > 2 and frame[0] == 2
                else None
            )
        except (json.JSONDecodeError, TypeError):
            action = None

        is_handshake = action in _HANDSHAKE_ACTIONS
        if is_handshake and not _VERBOSE:
            return

        if isinstance(frame, list) and frame[0] == 2 and action and action not in _HANDSHAKE_ACTIONS:
            # Server-initiated non-handshake CALL — use the prominent format
            payload = frame[3] if len(frame) > 3 else {}
            _log_server_call(self.charge_point_id or "unknown", action, payload)
        else:
            _verbose("%s\n%s", label, json.dumps(frame, indent=2))


# ── HTTP server ───────────────────────────────────────────────────────────────

class OcppProxy:
    """Accepts inbound charger WebSocket connections and proxies them upstream."""

    def __init__(
        self,
        host: str,
        port: int,
        upstream: str,
        ssl_context: ssl.SSLContext | None,
        masquerade: dict[str, str] | None = None,
        upstream_password: str | None = None,
        upstream_charge_point_id: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.upstream = upstream
        self.ssl_context = ssl_context
        self.masquerade = masquerade or {}
        self.upstream_password = upstream_password
        self.upstream_charge_point_id = upstream_charge_point_id
        self._app = web.Application()
        self._app.router.add_get("/", self._handle)
        self._app.router.add_get("/{charge_point_id:.*}", self._handle)

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        charge_point_id = request.match_info.get("charge_point_id", "").strip("/") or None
        charger_ws = web.WebSocketResponse(protocols=(OCPP_SUBPROTOCOL,))
        await charger_ws.prepare(request)
        session = ProxySession(
            charger_ws,
            self.upstream,
            charge_point_id,
            masquerade=self.masquerade,
            upstream_password=self.upstream_password,
            upstream_charge_point_id=self.upstream_charge_point_id,
        )
        await session.run()
        return charger_ws

    async def start(self) -> None:
        runner = web.AppRunner(self._app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, host=self.host, port=self.port, ssl_context=self.ssl_context)
        await site.start()
        scheme = "wss" if self.ssl_context else "ws"
        _LOGGER.info(
            "OCPP proxy listening on %s://%s:%d  →  %s",
            scheme, self.host, self.port, self.upstream,
        )


# ── inbound CALL handlers (server → simulated charger) ───────────────────────

def _handle_get_configuration(payload: dict) -> dict:
    all_keys = [
        # Keys from real charger GetConfiguration (captured via HA integration diagnostics)
        {"key": "ChargeRate",                              "readonly": False, "value": "32.0"},
        {"key": "AuthorizeRemoteTxRequests",               "readonly": True,  "value": "false"},
        {"key": "EcoMode",                                 "readonly": False, "value": "Boost"},
        {"key": "ConnectionTimeout",                       "readonly": False, "value": "60"},
        {"key": "RandomisedDelayDuration",                 "readonly": False, "value": "600"},
        {"key": "HeartbeatInterval",                       "readonly": False, "value": "300"},
        {"key": "MeterValueSampleInterval",                "readonly": False, "value": "60"},
        {"key": "NumberOfConnectors",                      "readonly": True,  "value": "1"},
        {"key": "SupportedFeatureProfiles",                "readonly": True,  "value": "Core,Reservation,Smart Charging,Remote Trigger"},
        {"key": "Imax",                                    "readonly": False, "value": "80"},
        {"key": "LocalAuthorizeOffline",                   "readonly": False, "value": "true"},
        {"key": "SendLocalListMaxLength",                  "readonly": True,  "value": "100"},
        {"key": "LocalAuthListMaxLength",                  "readonly": True,  "value": "200"},
        {"key": "ChargeProfileMaxStackLevel",              "readonly": True,  "value": "7"},
        {"key": "ChargingScheduleAllowedChargingRateUnit", "readonly": True,  "value": "Current"},
        {"key": "ChargingScheduleMaxPeriods",              "readonly": True,  "value": "21"},
        {"key": "MaxChargingProfilesInstalled",            "readonly": True,  "value": "5"},
        {"key": "LocalIPAddress",                          "readonly": True,  "value": "0.0.0.0"},
        {"key": "LocalAuthListEnabled",                    "readonly": False, "value": "true"},
        {"key": "FrontPanelLEDsEnabled",                   "readonly": False, "value": "true"},
        {"key": "EnableLocalModbus",                       "readonly": False, "value": "true"},
        {"key": "EnableRemoteDebug",                       "readonly": False, "value": "false"},
        {"key": "ChargingStateBCPVoltageLowerLimit",       "readonly": False, "value": "80"},
        {"key": "ChargingStateBCPVoltageHigherLimit",      "readonly": False, "value": "100"},
        {"key": "SuspevTime",                              "readonly": False, "value": "0"},
    ]
    requested_keys: list[str] = payload.get("key", [])
    if requested_keys:
        config_keys = [k for k in all_keys if k["key"] in requested_keys]
        unknown_keys = [k for k in requested_keys if k not in {e["key"] for e in all_keys}]
    else:
        config_keys = all_keys
        unknown_keys = []
    result: dict = {"configurationKey": config_keys}
    if unknown_keys:
        result["unknownKey"] = unknown_keys
    return result


def _handle_change_configuration(payload: dict) -> dict:
    return {"status": "Accepted"}


def _handle_remote_start_transaction(payload: dict) -> dict:
    return {"status": "Accepted"}


def _handle_remote_stop_transaction(payload: dict) -> dict:
    return {"status": "Accepted"}


def _handle_set_charging_profile(payload: dict) -> dict:
    return {"status": "Accepted"}


def _handle_clear_charging_profile(payload: dict) -> dict:
    return {"status": "Accepted"}


def _handle_update_firmware(payload: dict) -> dict:
    return {}


def _handle_reset(payload: dict) -> dict:
    return {"status": "Accepted"}


def _handle_trigger_message(payload: dict) -> dict:
    # Acknowledged here; the follow-up CALL is fired separately by the simulator
    return {"status": "Accepted"}


def _handle_unlock_connector(payload: dict) -> dict:
    return {"status": "Unlocked"}


_INBOUND_HANDLERS: dict[str, callable] = {
    "GetConfiguration":        _handle_get_configuration,
    "ChangeConfiguration":     _handle_change_configuration,
    "RemoteStartTransaction":  _handle_remote_start_transaction,
    "RemoteStopTransaction":   _handle_remote_stop_transaction,
    "SetChargingProfile":      _handle_set_charging_profile,
    "ClearChargingProfile":    _handle_clear_charging_profile,
    "UpdateFirmware":          _handle_update_firmware,
    "Reset":                   _handle_reset,
    "TriggerMessage":          _handle_trigger_message,
    "UnlockConnector":         _handle_unlock_connector,
}


# ── charger simulator ─────────────────────────────────────────────────────────

class ChargerSimulator:
    """
    Connects to the upstream OCPP server impersonating a real charger.
    Completes the boot handshake then idles, logging any portal-initiated commands.
    """

    def __init__(self, upstream: str, charge_point_id: str, boot_payload: dict) -> None:
        self.upstream = upstream.rstrip("/") + f"/{charge_point_id}"
        self.charge_point_id = charge_point_id
        self.boot_payload = boot_payload
        self._pending: dict[str, asyncio.Future] = {}

    async def run(self) -> None:
        upstream_ssl: ssl.SSLContext | bool = (
            ssl.create_default_context() if self.upstream.startswith("wss://") else False
        )

        _LOGGER.info("Connecting to %s", self.upstream)

        async with aiohttp.ClientSession() as session:
            try:
                async with session.ws_connect(
                    self.upstream,
                    protocols=(OCPP_SUBPROTOCOL,),
                    ssl=upstream_ssl,
                ) as ws:
                    _verbose("Connected")
                    recv_task = asyncio.create_task(self._receive_loop(ws))
                    try:
                        await self._boot_sequence(ws)
                    finally:
                        recv_task.cancel()
                        try:
                            await recv_task
                        except (asyncio.CancelledError, Exception):
                            pass
            except aiohttp.ClientError as err:
                _LOGGER.error("Connection failed: %s", err)

    async def _boot_sequence(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """Complete the boot handshake then heartbeat forever."""

        boot_response = await self._call(ws, "BootNotification", self.boot_payload)
        _verbose("BootNotification accepted: %s", boot_response)

        for connector_id in (0, 1):
            await self._call(ws, "StatusNotification", {
                "connectorId": connector_id,
                "errorCode": "NoError",
                "status": "Available",
            })

        interval = boot_response.get("interval", 300) if isinstance(boot_response, dict) else 300
        _LOGGER.info(
            "Boot complete — charger online. Waiting for portal commands... "
            "(heartbeat every %ds, Ctrl-C to stop)",
            interval,
        )

        while True:
            await asyncio.sleep(interval)
            await self._call(ws, "Heartbeat", {})

    async def _call(self, ws: aiohttp.ClientWebSocketResponse, action: str, payload: dict) -> dict:
        """Send an OCPP CALL and wait for the CALL_RESULT."""
        unique_id = uuid4().hex
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[unique_id] = future

        frame = [2, unique_id, action, payload]
        _verbose("→ %s %s", action, json.dumps(payload))
        await ws.send_str(json.dumps(frame))

        try:
            return await asyncio.wait_for(future, timeout=60)
        except TimeoutError:
            _LOGGER.warning("Timed out waiting for response to %s", action)
            return {}
        finally:
            self._pending.pop(unique_id, None)

    async def _handle_trigger_follow_up(
        self, ws: aiohttp.ClientWebSocketResponse, requested_message: str | None
    ) -> None:
        """After acknowledging a TriggerMessage, send the requested CALL."""
        if requested_message is None:
            return

        _verbose("TriggerMessage follow-up: sending %s", requested_message)

        if requested_message == "BootNotification":
            await self._call(ws, "BootNotification", self.boot_payload)
        elif requested_message == "Heartbeat":
            await self._call(ws, "Heartbeat", {})
        elif requested_message == "StatusNotification":
            for connector_id in (0, 1):
                await self._call(ws, "StatusNotification", {
                    "connectorId": connector_id,
                    "errorCode": "NoError",
                    "status": "Available",
                })
        elif requested_message == "MeterValues":
            await self._call(ws, "MeterValues", {
                "connectorId": 1,
                "meterValue": [{
                    "timestamp": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    "sampledValue": [{"value": "0", "measurand": "Energy.Active.Import.Register", "unit": "Wh"}],
                }],
            })
        elif requested_message == "FirmwareStatusNotification":
            await self._call(ws, "FirmwareStatusNotification", {"status": "Idle"})
        elif requested_message == "DiagnosticsStatusNotification":
            await self._call(ws, "DiagnosticsStatusNotification", {"status": "Idle"})
        else:
            _LOGGER.warning("TriggerMessage: unknown requested message '%s'", requested_message)

    async def _receive_loop(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """Receive all frames, resolve pending futures, dispatch server-initiated CALLs."""
        async for msg in ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                if msg.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR}:
                    _LOGGER.info("Server closed the connection")
                    break
                continue

            try:
                frame = json.loads(msg.data)
            except json.JSONDecodeError:
                _LOGGER.warning("Invalid JSON from server: %s", msg.data)
                continue

            if not isinstance(frame, list) or len(frame) < 2:
                continue

            msg_type = frame[0]

            if msg_type == 3 and len(frame) == 3:
                # CALL_RESULT
                unique_id, payload = frame[1], frame[2]
                _verbose("← CALL_RESULT %s", json.dumps(payload))
                future = self._pending.get(unique_id)
                if future and not future.done():
                    future.set_result(payload)

            elif msg_type == 4 and len(frame) >= 4:
                # CALL_ERROR
                unique_id, error_code = frame[1], frame[2]
                error_desc = frame[3] if len(frame) > 3 else ""
                _LOGGER.warning("CALL_ERROR %s: %s", error_code, error_desc)
                future = self._pending.get(unique_id)
                if future and not future.done():
                    future.set_result({})

            elif msg_type == 2 and len(frame) == 4:
                # Server-initiated CALL
                unique_id, action, payload = frame[1], frame[2], frame[3]
                is_handshake = action in _HANDSHAKE_ACTIONS

                if is_handshake:
                    _verbose("← Server CALL: %s %s", action, json.dumps(payload))
                else:
                    _log_server_call(self.charge_point_id, action, payload)

                handler = _INBOUND_HANDLERS.get(action)
                result = handler(payload) if handler is not None else {}

                if is_handshake:
                    _verbose("→ Response: %s", json.dumps(result))
                else:
                    _log_charger_response(action, result)

                await ws.send_str(json.dumps([3, unique_id, result]))

                if action == "TriggerMessage":
                    asyncio.create_task(
                        self._handle_trigger_follow_up(ws, payload.get("requestedMessage"))
                    )


# ── entry point ───────────────────────────────────────────────────────────────

async def _run_proxy(args: argparse.Namespace, masquerade: dict[str, str] | None = None) -> None:
    ssl_context: ssl.SSLContext | None = None
    if args.tls:
        if not args.cert or not args.key:
            _LOGGER.error("--tls requires --cert and --key")
            sys.exit(1)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(args.cert, args.key)

    upstream_password = getattr(args, "upstream_password", None) or None
    upstream_charge_point_id = getattr(args, "upstream_charge_point_id", None) or None

    proxy = OcppProxy(
        host=args.host,
        port=args.port,
        upstream=args.upstream,
        ssl_context=ssl_context,
        masquerade=masquerade,
        upstream_password=upstream_password,
        upstream_charge_point_id=upstream_charge_point_id,
    )
    await proxy.start()
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        _LOGGER.info("Shutting down")


async def _run_simulate(args: argparse.Namespace) -> None:
    boot_payload = {
        "chargePointVendor": args.vendor,
        "chargePointModel": args.model,
        "firmwareVersion": args.firmware,
        "chargePointSerialNumber": args.serial or args.charge_point_id,
    }
    simulator = ChargerSimulator(
        upstream=args.upstream,
        charge_point_id=args.charge_point_id,
        boot_payload=boot_payload,
    )
    try:
        await simulator.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        _LOGGER.info("Stopped")


def main() -> None:
    global _VERBOSE

    parser = argparse.ArgumentParser(description="OCPP WebSocket proxy / charger simulator")
    parser.add_argument("--upstream", default=DEFAULT_UPSTREAM, help="Upstream OCPP server URL")
    parser.add_argument("--verbose", action="store_true", help="Show full handshake frames (BootNotification, Heartbeat, etc.)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    proxy_parser = subparsers.add_parser("proxy", help="Transparent OCPP proxy")
    proxy_parser.add_argument("--host", default=DEFAULT_HOST)
    proxy_parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    proxy_parser.add_argument("--tls", action="store_true")
    proxy_parser.add_argument("--cert")
    proxy_parser.add_argument("--key")
    proxy_parser.add_argument("--upstream-password",        default=None, help="Password for upstream basic auth")
    proxy_parser.add_argument("--upstream-charge-point-id", default=None, help="Charge point ID to use with the upstream (overrides the real charger's ID)")

    masq_parser = subparsers.add_parser(
        "masquerade",
        help="Proxy mode that replaces BootNotification identity fields before forwarding upstream",
    )
    masq_parser.add_argument("--host", default=DEFAULT_HOST)
    masq_parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    masq_parser.add_argument("--tls", action="store_true")
    masq_parser.add_argument("--cert")
    masq_parser.add_argument("--key")
    masq_parser.add_argument("--vendor",            default="Wall Box Chargers", help="Override chargePointVendor")
    masq_parser.add_argument("--model",             default="PLP2-0-2-2",         help="Override chargePointModel")
    masq_parser.add_argument("--firmware",          default="6.11.16",            help="Override firmwareVersion")
    masq_parser.add_argument("--serial",            default=None,                 help="Override chargePointSerialNumber")
    masq_parser.add_argument("--upstream-password",        default=None, help="Password for upstream basic auth")
    masq_parser.add_argument("--upstream-charge-point-id", default=None, help="Charge point ID to use with the upstream (overrides the real charger's ID)")

    sim_parser = subparsers.add_parser("simulate", help="Simulate a charger connecting to the upstream")
    sim_parser.add_argument("--charge-point-id", required=True, help="Charge point ID / WebSocket path")
    sim_parser.add_argument("--vendor",   default="WWWW",                help="chargePointVendor")
    sim_parser.add_argument("--model",    default="SingleSocketCharger",  help="chargePointModel")
    sim_parser.add_argument("--firmware", default="AC_GL1_1.14",          help="firmwareVersion")
    sim_parser.add_argument("--serial",   default=None,                   help="chargePointSerialNumber (default: same as --charge-point-id)")

    args = parser.parse_args()
    _VERBOSE = args.verbose

    try:
        if args.command == "proxy":
            asyncio.run(_run_proxy(args))
        elif args.command == "masquerade":
            masquerade = {
                k: v
                for k, v in {
                    "vendor": args.vendor,
                    "model": args.model,
                    "firmware": args.firmware,
                    "serial": args.serial,
                }.items()
                if v is not None
            }
            asyncio.run(_run_proxy(args, masquerade=masquerade))
        elif args.command == "simulate":
            asyncio.run(_run_simulate(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
