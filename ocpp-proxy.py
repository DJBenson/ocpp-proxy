"""
OCPP WebSocket proxy / charger simulator.

PROXY MODE
    The charger connects here (acting as OCPP central system).
    This proxy connects upstream to the real OCPP server.
    All frames are logged in both directions before being forwarded.

    Example (plain WS — try this first):
        python proxy.py --upstream ws://ocpp.example.com:7655 proxy

    Example (self-signed TLS, if charger rejects plain WS):
        openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=ocpp.example.com"
        python proxy.py --upstream wss://ocpp.example.com:7655 proxy --tls --cert cert.pem --key key.pem

MASQUERADE MODE
    Like proxy mode, but intercepts BootNotification frames sent by the real charger
    and replaces the vendor, model, and/or serial number with configured values before
    forwarding to the upstream. The upstream sees the mock identity; the real charger
    is unaffected. All other traffic is relayed transparently.

    Example:
        python proxy.py --upstream wss://ocpp.example.com:7655 masquerade \\
            --vendor ACME \\
            --model VirtualCharger \\
            --serial 000000000001

    Only the fields you specify are replaced — omit any to leave them as-is.

SIMULATE MODE
    Connects directly to the upstream as a fake charger — no real charger needed.
    Completes the boot handshake then sits idle, logging any commands the portal sends.
    Use --verbose to also see the full handshake frames.

    Example:
        python proxy.py --upstream wss://ocpp.example.com:7655 simulate \\
            --charge-point-id 12345678901234 \\
            --vendor MyVendor \\
            --model SingleSocketCharger \\
            --firmware 1.0.0 \\
            --serial 12345678901234

    Show full handshake frames too:
        python proxy.py --upstream wss://ocpp.example.com:7655 simulate --charge-point-id 12345678901234 ... --verbose
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import json
import logging
import ssl
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import aiohttp
from aiohttp import web
from urllib.parse import urlparse, urlunparse

# ── defaults ──────────────────────────────────────────────────────────────────

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 7655
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


@dataclass(slots=True)
class SimulatedChargerConfig:
    """Static configuration for one simulated charger."""

    charge_point_id: str
    vendor: str = "Unknown"
    model: str = "Unknown"
    firmware: str = "Unknown"
    serial: str | None = None
    heartbeat_interval_seconds: int = 300
    meter_value_sample_interval_seconds: int = 60
    initial_current_limit_a: float = 32.0
    max_import_current_a: int = 80
    charge_mode: str = "Boost"
    connect_delay_seconds: float = 0.0
    voltage_v: float = 230.0
    remote_id_tag: str = "SIM-REMOTE"
    plugged_in: bool = False

    @property
    def boot_payload(self) -> dict[str, str]:
        """Return the BootNotification payload."""

        return {
            "chargePointVendor": self.vendor,
            "chargePointModel": self.model,
            "firmwareVersion": self.firmware,
            "chargePointSerialNumber": self.serial or self.charge_point_id,
        }


@dataclass(slots=True)
class SimulatedChargerState:
    """Mutable runtime state for one simulated charger."""

    current_limit_a: float
    max_import_current_a: int
    charge_mode: str
    heartbeat_interval_seconds: int
    meter_value_sample_interval_seconds: int
    status: str = "Available"
    plugged_in: bool = False
    operative: bool = True
    transaction_active: bool = False
    transaction_id: int | None = None
    transaction_id_tag: str | None = None
    total_energy_wh: float = 0.0
    meter_start_wh: float = 0.0
    firmware_status: str = "Idle"
    diagnostics_status: str = "Idle"
    randomised_delay_duration_seconds: int = 600
    local_modbus_enabled: bool = True
    front_panel_leds_enabled: bool = True
    suspended_state_timeout_seconds: int = 0


def _bool_string(value: bool) -> str:
    """Return an OCPP-style lower-case boolean string."""

    return "true" if value else "false"


def _cp_voltage_for_status(status: str) -> float:
    """Return a plausible CP voltage for the charger state."""

    return {
        "Available": 12.0,
        "Preparing": 9.0,
        "Charging": 6.0,
        "Finishing": 9.0,
        "Unavailable": 0.0,
        "Faulted": 0.0,
    }.get(status, 12.0)


def _cp_duty_for_current(current_a: float) -> float:
    """Return a plausible PWM duty cycle for the configured current."""

    if current_a <= 0:
        return 0.0
    if current_a <= 51:
        return round(current_a / 0.6, 1)
    if current_a <= 80:
        return round((current_a / 2.5) + 64, 1)
    return 96.0


def _decode_charge_rate(value: str | int | float) -> float:
    """Decode ChargeRate configuration values into amps."""

    try:
        decoded = float(value)
    except (TypeError, ValueError):
        return 32.0
    if decoded > 100:
        decoded /= 10.0
    return max(decoded, 6.0)


class ChargerSimulator:
    """Stateful fake charger that behaves enough like a real device for testing."""

    def __init__(self, upstream: str, config: SimulatedChargerConfig) -> None:
        self.config = config
        self.upstream = upstream.rstrip("/") + f"/{config.charge_point_id}"
        self.charge_point_id = config.charge_point_id
        self.state = SimulatedChargerState(
            current_limit_a=config.initial_current_limit_a,
            max_import_current_a=config.max_import_current_a,
            charge_mode=config.charge_mode,
            heartbeat_interval_seconds=config.heartbeat_interval_seconds,
            meter_value_sample_interval_seconds=config.meter_value_sample_interval_seconds,
            plugged_in=config.plugged_in,
        )
        self._pending: dict[str, asyncio.Future] = {}
        self._heartbeat_task: asyncio.Task | None = None
        self._meter_task: asyncio.Task | None = None
        self._next_transaction_id = 1000

    async def run(self) -> None:
        """Run one charger simulation until the server closes the connection."""

        if self.config.connect_delay_seconds > 0:
            await asyncio.sleep(self.config.connect_delay_seconds)

        upstream_ssl: ssl.SSLContext | bool = (
            ssl.create_default_context() if self.upstream.startswith("wss://") else False
        )

        _LOGGER.info("[%s] Connecting to %s", self.charge_point_id, self.upstream)

        async with aiohttp.ClientSession() as session:
            try:
                async with session.ws_connect(
                    self.upstream,
                    protocols=(OCPP_SUBPROTOCOL,),
                    ssl=upstream_ssl,
                ) as ws:
                    _verbose("[%s] Connected", self.charge_point_id)
                    recv_task = asyncio.create_task(self._receive_loop(ws))
                    try:
                        await self._boot_sequence(ws)
                        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(ws))
                        await recv_task
                    finally:
                        await self._cancel_background_tasks()
                        recv_task.cancel()
                        try:
                            await recv_task
                        except (asyncio.CancelledError, Exception):
                            pass
            except aiohttp.ClientError as err:
                _LOGGER.error("[%s] Connection failed: %s", self.charge_point_id, err)

    async def _cancel_background_tasks(self) -> None:
        """Cancel auxiliary tasks."""

        for task in (self._heartbeat_task, self._meter_task):
            if task is None:
                continue
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._heartbeat_task = None
        self._meter_task = None

    async def _boot_sequence(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """Bring the fake charger online."""

        boot_response = await self._call(ws, "BootNotification", self.config.boot_payload)
        _verbose("[%s] BootNotification accepted: %s", self.charge_point_id, boot_response)

        if isinstance(boot_response, dict):
            interval = int(boot_response.get("interval", self.state.heartbeat_interval_seconds))
            self.state.heartbeat_interval_seconds = max(interval, 5)

        await self._send_status_notification(ws, 0, "Available")
        initial_status = "Preparing" if self.config.plugged_in else "Available"
        await self._send_status_notification(ws, 1, initial_status)

        _LOGGER.info(
            "[%s] Boot complete — online. Heartbeat every %ss.",
            self.charge_point_id,
            self.state.heartbeat_interval_seconds,
        )

    async def _heartbeat_loop(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """Send periodic heartbeats."""

        while True:
            await asyncio.sleep(self.state.heartbeat_interval_seconds)
            await self._call(ws, "Heartbeat", {})

    async def _meter_loop(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """Send periodic meter values while charging."""

        while self.state.transaction_active:
            await asyncio.sleep(self.state.meter_value_sample_interval_seconds)
            if not self.state.transaction_active:
                break
            await self._send_meter_values(ws)

    def _configuration_entries(self) -> list[dict[str, object]]:
        """Return the charger's current GetConfiguration view."""

        return [
            {"key": "ChargeRate", "readonly": False, "value": f"{self.state.current_limit_a:.1f}"},
            {"key": "AuthorizeRemoteTxRequests", "readonly": True, "value": "false"},
            {"key": "EcoMode", "readonly": False, "value": self.state.charge_mode},
            {"key": "ConnectionTimeout", "readonly": False, "value": "60"},
            {
                "key": "RandomisedDelayDuration",
                "readonly": False,
                "value": str(self.state.randomised_delay_duration_seconds),
            },
            {
                "key": "HeartbeatInterval",
                "readonly": False,
                "value": str(self.state.heartbeat_interval_seconds),
            },
            {
                "key": "MeterValueSampleInterval",
                "readonly": False,
                "value": str(self.state.meter_value_sample_interval_seconds),
            },
            {"key": "NumberOfConnectors", "readonly": True, "value": "1"},
            {
                "key": "SupportedFeatureProfiles",
                "readonly": True,
                "value": "Core,Reservation,Smart Charging,Remote Trigger",
            },
            {"key": "Imax", "readonly": False, "value": str(self.state.max_import_current_a)},
            {"key": "LocalAuthorizeOffline", "readonly": False, "value": "true"},
            {"key": "SendLocalListMaxLength", "readonly": True, "value": "100"},
            {"key": "LocalAuthListMaxLength", "readonly": True, "value": "200"},
            {"key": "ChargeProfileMaxStackLevel", "readonly": True, "value": "7"},
            {
                "key": "ChargingScheduleAllowedChargingRateUnit",
                "readonly": True,
                "value": "Current",
            },
            {"key": "ChargingScheduleMaxPeriods", "readonly": True, "value": "21"},
            {"key": "MaxChargingProfilesInstalled", "readonly": True, "value": "5"},
            {"key": "LocalIPAddress", "readonly": True, "value": "0.0.0.0"},
            {"key": "LocalAuthListEnabled", "readonly": False, "value": "true"},
            {
                "key": "FrontPanelLEDsEnabled",
                "readonly": False,
                "value": _bool_string(self.state.front_panel_leds_enabled),
            },
            {
                "key": "EnableLocalModbus",
                "readonly": False,
                "value": _bool_string(self.state.local_modbus_enabled),
            },
            {"key": "EnableRemoteDebug", "readonly": False, "value": "false"},
            {"key": "ChargingStateBCPVoltageLowerLimit", "readonly": False, "value": "80"},
            {"key": "ChargingStateBCPVoltageHigherLimit", "readonly": False, "value": "100"},
            {
                "key": "SuspevTime",
                "readonly": False,
                "value": str(self.state.suspended_state_timeout_seconds),
            },
        ]

    async def _call(
        self, ws: aiohttp.ClientWebSocketResponse, action: str, payload: dict
    ) -> dict:
        """Send an OCPP CALL and wait for the CALL_RESULT."""

        unique_id = uuid4().hex
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[unique_id] = future

        frame = [2, unique_id, action, payload]
        _verbose("[%s] → %s %s", self.charge_point_id, action, json.dumps(payload))
        await ws.send_str(json.dumps(frame))

        try:
            return await asyncio.wait_for(future, timeout=60)
        except TimeoutError:
            _LOGGER.warning("[%s] Timed out waiting for response to %s", self.charge_point_id, action)
            return {}
        finally:
            self._pending.pop(unique_id, None)

    async def _send_status_notification(
        self, ws: aiohttp.ClientWebSocketResponse, connector_id: int, status: str
    ) -> None:
        """Send a StatusNotification."""

        if connector_id == 1:
            self.state.status = status
        await self._call(
            ws,
            "StatusNotification",
            {
                "connectorId": connector_id,
                "errorCode": "NoError",
                "status": status,
                "vendorErrorCode": "NoError",
            },
        )

    async def _send_meter_values(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """Send a realistic MeterValues frame."""

        charging = self.state.transaction_active
        power_w = round(self.state.current_limit_a * self.config.voltage_v, 1) if charging else 0.0
        current_a = self.state.current_limit_a if charging else 0.0

        if charging:
            delta_wh = power_w * (self.state.meter_value_sample_interval_seconds / 3600)
            self.state.total_energy_wh = round(self.state.total_energy_wh + delta_wh, 3)

        await self._call(
            ws,
            "MeterValues",
            {
                "connectorId": 1,
                "meterValue": [
                    {
                        "timestamp": datetime.now(UTC).replace(microsecond=0)
                        .isoformat()
                        .replace("+00:00", "Z"),
                        "sampledValue": [
                            {
                                "value": f"{self.state.total_energy_wh:.0f}",
                                "measurand": "Energy.Active.Import.Register",
                                "unit": "Wh",
                            },
                            {
                                "value": f"{power_w:.1f}",
                                "measurand": "Power.Active.Import",
                                "unit": "W",
                            },
                            {
                                "value": f"{current_a:.1f}",
                                "measurand": "Current.Import",
                                "unit": "A",
                            },
                            {
                                "value": f"{self.config.voltage_v:.1f}",
                                "measurand": "Voltage",
                                "unit": "V",
                            },
                        ],
                    }
                ],
            },
        )

    async def _start_transaction(self, ws: aiohttp.ClientWebSocketResponse, id_tag: str) -> None:
        """Transition into an active charging session."""

        if self.state.transaction_active:
            return

        self.state.plugged_in = True
        await self._send_status_notification(ws, 1, "Preparing")
        self.state.transaction_active = True
        self.state.transaction_id_tag = id_tag
        self.state.transaction_id = self._next_transaction_id
        self._next_transaction_id += 1
        self.state.meter_start_wh = self.state.total_energy_wh

        response = await self._call(
            ws,
            "StartTransaction",
            {
                "connectorId": 1,
                "idTag": id_tag,
                "meterStart": int(self.state.meter_start_wh),
                "timestamp": datetime.now(UTC).replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
            },
        )
        if isinstance(response, dict) and response.get("transactionId") is not None:
            self.state.transaction_id = int(response["transactionId"])

        await self._send_status_notification(ws, 1, "Charging")
        if self._meter_task is None or self._meter_task.done():
            self._meter_task = asyncio.create_task(self._meter_loop(ws))

    async def _stop_transaction(self, ws: aiohttp.ClientWebSocketResponse, reason: str) -> None:
        """Transition out of an active charging session."""

        if not self.state.transaction_active:
            return

        self.state.transaction_active = False
        if self._meter_task is not None:
            self._meter_task.cancel()
            try:
                await self._meter_task
            except (asyncio.CancelledError, Exception):
                pass
            self._meter_task = None

        await self._send_status_notification(ws, 1, "Finishing")
        await self._call(
            ws,
            "StopTransaction",
            {
                "transactionId": self.state.transaction_id,
                "idTag": self.state.transaction_id_tag,
                "meterStop": int(self.state.total_energy_wh),
                "timestamp": datetime.now(UTC).replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "reason": reason,
            },
        )
        self.state.transaction_id = None
        self.state.transaction_id_tag = None
        post_stop_status = "Preparing" if self.state.plugged_in else "Available"
        await self._send_status_notification(ws, 1, post_stop_status)

    async def _simulate_firmware_update(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """Emit a simple firmware status sequence."""

        for status in ("Downloading", "Downloaded", "Installing", "Installed"):
            self.state.firmware_status = status
            await self._call(ws, "FirmwareStatusNotification", {"status": status})
            await asyncio.sleep(1)
        self.state.firmware_status = "Idle"

    async def _handle_trigger_follow_up(
        self, ws: aiohttp.ClientWebSocketResponse, requested_message: str | None
    ) -> None:
        """After acknowledging TriggerMessage, send the requested CALL."""

        if requested_message is None:
            return

        _verbose("[%s] TriggerMessage follow-up: sending %s", self.charge_point_id, requested_message)

        if requested_message == "BootNotification":
            await self._call(ws, "BootNotification", self.config.boot_payload)
        elif requested_message == "Heartbeat":
            await self._call(ws, "Heartbeat", {})
        elif requested_message == "StatusNotification":
            await self._send_status_notification(ws, 1, self.state.status)
        elif requested_message == "MeterValues":
            await self._send_meter_values(ws)
        elif requested_message == "FirmwareStatusNotification":
            await self._call(
                ws,
                "FirmwareStatusNotification",
                {"status": self.state.firmware_status},
            )
        elif requested_message == "DiagnosticsStatusNotification":
            await self._call(
                ws,
                "DiagnosticsStatusNotification",
                {"status": self.state.diagnostics_status},
            )
        else:
            _LOGGER.warning("[%s] TriggerMessage: unknown requested message '%s'", self.charge_point_id, requested_message)

    async def _dispatch_server_call(
        self, ws: aiohttp.ClientWebSocketResponse, action: str, payload: dict
    ) -> dict:
        """Handle one central-system initiated CALL."""

        if action == "GetConfiguration":
            all_keys = self._configuration_entries()
            requested_keys: list[str] = payload.get("key", [])
            if requested_keys:
                config_keys = [k for k in all_keys if k["key"] in requested_keys]
                unknown_keys = [
                    key for key in requested_keys if key not in {entry["key"] for entry in all_keys}
                ]
            else:
                config_keys = all_keys
                unknown_keys = []

            result: dict[str, object] = {"configurationKey": config_keys}
            if unknown_keys:
                result["unknownKey"] = unknown_keys
            return result

        if action == "ChangeConfiguration":
            key = payload.get("key")
            value = payload.get("value")
            if key == "ChargeRate":
                self.state.current_limit_a = _decode_charge_rate(value)
            elif key == "EcoMode":
                self.state.charge_mode = str(value)
            elif key == "RandomisedDelayDuration":
                self.state.randomised_delay_duration_seconds = int(value)
            elif key == "HeartbeatInterval":
                self.state.heartbeat_interval_seconds = max(int(value), 5)
                if self._heartbeat_task and not self._heartbeat_task.done():
                    self._heartbeat_task.cancel()
                    self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(ws))
            elif key == "MeterValueSampleInterval":
                self.state.meter_value_sample_interval_seconds = max(int(value), 5)
                if self.state.transaction_active and self._meter_task and not self._meter_task.done():
                    self._meter_task.cancel()
                    self._meter_task = asyncio.create_task(self._meter_loop(ws))
            elif key == "Imax":
                self.state.max_import_current_a = int(value)
            elif key == "EnableLocalModbus":
                self.state.local_modbus_enabled = str(value).lower() == "true"
            elif key == "FrontPanelLEDsEnabled":
                self.state.front_panel_leds_enabled = str(value).lower() == "true"
            elif key == "SuspevTime":
                self.state.suspended_state_timeout_seconds = int(value)
            return {"status": "Accepted"}

        if action == "RemoteStartTransaction":
            id_tag = payload.get("idTag") or self.config.remote_id_tag
            asyncio.create_task(self._start_transaction(ws, str(id_tag)))
            return {"status": "Accepted"}

        if action == "RemoteStopTransaction":
            asyncio.create_task(self._stop_transaction(ws, "Remote"))
            return {"status": "Accepted"}

        if action == "SetChargingProfile":
            return {"status": "Accepted"}

        if action == "ClearChargingProfile":
            return {"status": "Accepted"}

        if action == "SendLocalList":
            return {"status": "Accepted"}

        if action == "ChangeAvailability":
            operative = str(payload.get("type", "Operative")) == "Operative"
            self.state.operative = operative
            asyncio.create_task(
                self._send_status_notification(ws, 1, "Available" if operative else "Unavailable")
            )
            return {"status": "Accepted"}

        if action == "UpdateFirmware":
            asyncio.create_task(self._simulate_firmware_update(ws))
            return {}

        if action == "Reset":
            return {"status": "Accepted"}

        if action == "TriggerMessage":
            asyncio.create_task(
                self._handle_trigger_follow_up(ws, payload.get("requestedMessage"))
            )
            return {"status": "Accepted"}

        if action == "UnlockConnector":
            return {"status": "Unlocked"}

        if action == "DataTransfer":
            vendor_id = payload.get("vendorId")
            message_id = payload.get("messageId")
            data = payload.get("data")
            if vendor_id == "GivEnergy" and message_id == "Parameter" and data == "CP":
                cp_voltage = _cp_voltage_for_status(self.state.status)
                cp_duty = _cp_duty_for_current(self.state.current_limit_a)
                duty_text = str(int(cp_duty)) if float(cp_duty).is_integer() else f"{cp_duty:.1f}"
                return {
                    "status": "Accepted",
                    "data": f"CP_Voltage:{cp_voltage:.1f}V,CP_Duty:{duty_text}%",
                }
            if vendor_id == "GivEnergy" and message_id == "Setting" and data == "Refactory":
                return {}
            return {"status": "Rejected"}

        _LOGGER.warning("[%s] Unhandled server CALL %s", self.charge_point_id, action)
        return {}

    async def _receive_loop(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """Receive all frames, resolve pending futures, dispatch server-initiated CALLs."""

        async for msg in ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                if msg.type in {aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR}:
                    _LOGGER.info("[%s] Server closed the connection", self.charge_point_id)
                    break
                continue

            try:
                frame = json.loads(msg.data)
            except json.JSONDecodeError:
                _LOGGER.warning("[%s] Invalid JSON from server: %s", self.charge_point_id, msg.data)
                continue

            if not isinstance(frame, list) or len(frame) < 2:
                continue

            msg_type = frame[0]

            if msg_type == 3 and len(frame) == 3:
                unique_id, payload = frame[1], frame[2]
                _verbose("[%s] ← CALL_RESULT %s", self.charge_point_id, json.dumps(payload))
                future = self._pending.get(unique_id)
                if future and not future.done():
                    future.set_result(payload)
                continue

            if msg_type == 4 and len(frame) >= 4:
                unique_id, error_code = frame[1], frame[2]
                error_desc = frame[3] if len(frame) > 3 else ""
                _LOGGER.warning("[%s] CALL_ERROR %s: %s", self.charge_point_id, error_code, error_desc)
                future = self._pending.get(unique_id)
                if future and not future.done():
                    future.set_result({})
                continue

            if msg_type == 2 and len(frame) == 4:
                unique_id, action, payload = frame[1], frame[2], frame[3]
                is_handshake = action in _HANDSHAKE_ACTIONS

                if is_handshake:
                    _verbose("[%s] ← Server CALL: %s %s", self.charge_point_id, action, json.dumps(payload))
                else:
                    _log_server_call(self.charge_point_id, action, payload)

                result = await self._dispatch_server_call(ws, action, payload)

                if is_handshake:
                    _verbose("[%s] → Response: %s", self.charge_point_id, json.dumps(result))
                else:
                    _log_charger_response(action, result)

                await ws.send_str(json.dumps([3, unique_id, result]))


def _build_single_simulator_config(args: argparse.Namespace) -> SimulatedChargerConfig:
    """Build one simulator config from CLI flags."""

    return SimulatedChargerConfig(
        charge_point_id=args.charge_point_id,
        vendor=args.vendor,
        model=args.model,
        firmware=args.firmware,
        serial=args.serial,
        heartbeat_interval_seconds=args.heartbeat_interval,
        meter_value_sample_interval_seconds=args.meter_interval,
        initial_current_limit_a=args.current_limit,
        max_import_current_a=args.max_import_current,
        charge_mode=args.charge_mode,
        connect_delay_seconds=args.connect_delay,
        voltage_v=args.voltage,
        remote_id_tag=args.remote_id_tag,
        plugged_in=args.plugged_in,
    )


def _load_simulator_configs(args: argparse.Namespace) -> list[SimulatedChargerConfig]:
    """Load one or more simulated charger configs."""

    if not args.charger_config:
        return [_build_single_simulator_config(args)]

    raw = json.loads(Path(args.charger_config).read_text())
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        raise ValueError("charger config must be a JSON object or a non-empty JSON array")

    configs: list[SimulatedChargerConfig] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each charger config entry must be a JSON object")
        configs.append(
            SimulatedChargerConfig(
                charge_point_id=str(item["charge_point_id"]),
                vendor=str(item.get("vendor", "Unknown")),
                model=str(item.get("model", "Unknown")),
                firmware=str(item.get("firmware", "Unknown")),
                serial=item.get("serial"),
                heartbeat_interval_seconds=int(item.get("heartbeat_interval_seconds", 300)),
                meter_value_sample_interval_seconds=int(
                    item.get("meter_value_sample_interval_seconds", 60)
                ),
                initial_current_limit_a=float(item.get("current_limit_a", 32.0)),
                max_import_current_a=int(item.get("max_import_current_a", 80)),
                charge_mode=str(item.get("charge_mode", "Boost")),
                connect_delay_seconds=float(item.get("connect_delay_seconds", 0.0)),
                voltage_v=float(item.get("voltage_v", 230.0)),
                remote_id_tag=str(item.get("remote_id_tag", "SIM-REMOTE")),
                plugged_in=bool(item.get("plugged_in", False)),
            )
        )
    return configs


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
    configs = _load_simulator_configs(args)
    simulators = [ChargerSimulator(args.upstream, config) for config in configs]

    if len(simulators) == 1:
        _LOGGER.info("Starting 1 simulated charger")
    else:
        _LOGGER.info("Starting %d simulated chargers", len(simulators))

    try:
        await asyncio.gather(*(simulator.run() for simulator in simulators))
    except (KeyboardInterrupt, asyncio.CancelledError):
        _LOGGER.info("Stopped")


def main() -> None:
    global _VERBOSE

    parser = argparse.ArgumentParser(description="OCPP WebSocket proxy / charger simulator")
    parser.add_argument("--upstream", required=True, help="Upstream OCPP server URL (e.g. wss://ocpp.example.com:7655)")
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
    masq_parser.add_argument("--vendor",            default=None, help="Override chargePointVendor")
    masq_parser.add_argument("--model",             default=None, help="Override chargePointModel")
    masq_parser.add_argument("--firmware",          default=None, help="Override firmwareVersion")
    masq_parser.add_argument("--serial",            default=None, help="Override chargePointSerialNumber")
    masq_parser.add_argument("--upstream-password",        default=None, help="Password for upstream basic auth")
    masq_parser.add_argument("--upstream-charge-point-id", default=None, help="Charge point ID to use with the upstream (overrides the real charger's ID)")

    sim_parser = subparsers.add_parser("simulate", help="Simulate a charger connecting to the upstream")
    sim_parser.add_argument("--charger-config", help="Path to a JSON object/array describing one or more simulated chargers")
    sim_parser.add_argument("--charge-point-id", help="Charge point ID / WebSocket path")
    sim_parser.add_argument("--vendor",   default="Unknown", help="chargePointVendor")
    sim_parser.add_argument("--model",    default="Unknown", help="chargePointModel")
    sim_parser.add_argument("--firmware", default="Unknown", help="firmwareVersion")
    sim_parser.add_argument("--serial",   default=None,                   help="chargePointSerialNumber (default: same as --charge-point-id)")
    sim_parser.add_argument("--heartbeat-interval", type=int, default=300, help="Heartbeat interval in seconds")
    sim_parser.add_argument("--meter-interval", type=int, default=60, help="MeterValues interval in seconds while charging")
    sim_parser.add_argument("--current-limit", type=float, default=32.0, help="Initial current limit in amps")
    sim_parser.add_argument("--max-import-current", type=int, default=80, help="Initial Imax value in amps")
    sim_parser.add_argument("--charge-mode", default="Boost", help="Initial EcoMode / charge mode")
    sim_parser.add_argument("--connect-delay", type=float, default=0.0, help="Delay this simulated charger before connecting")
    sim_parser.add_argument("--voltage", type=float, default=230.0, help="Nominal line voltage for generated MeterValues")
    sim_parser.add_argument("--remote-id-tag", default="SIM-REMOTE", help="Default idTag used for RemoteStartTransaction")
    sim_parser.add_argument("--plugged-in", action="store_true", help="Boot with connector in Preparing state (car already plugged in)")

    args = parser.parse_args()
    _VERBOSE = args.verbose

    if args.command == "simulate" and not args.charger_config and not args.charge_point_id:
        parser.error("simulate requires either --charge-point-id or --charger-config")

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
