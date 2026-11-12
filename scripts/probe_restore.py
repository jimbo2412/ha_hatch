#!/usr/bin/env python3
"""Probe an original Hatch Restore (Hatch product "restore") through the Hatch cloud.

Fork-only development tool for the restore work; HACS does not ship it.

One login, then:
  1. the product codes on the account, and the devices Hatch returns for them
  2. what the REST endpoints the other Restores use answer for this one
     (routines, alarms, sound and color content)
  3. the full device shadow over AWS IoT, as the Hatch app reads it, and then
     every change to it as it happens -- including the desired state the
     Hatch app writes when you change something there
  4. a command prompt, to re-read the shadow or try a write

Nothing is written to the device unless you type a write command. The login
is asked for at a hidden prompt and kept in memory only. Tokens, AWS keys and
identifying values (email, MAC addresses, thing name, member id, headphone
PIN) are redacted from everything printed and from the report file,
restore-probe-<time>.log in the current directory.

Run it in a throwaway container from the directory holding this file:

  docker run --rm -it -v "$PWD:/work" -w /work python:3.13-slim sh -c \
    "pip install -q --root-user-action=ignore hatch_rest_api==1.35.0 && python probe_restore.py"

Hatch rate limits logins (HTTP 429). This logs in once per run and never
retries; on a rate limit, wait before running it again. The AWS credentials
it gets last about an hour, so a session ends by then.
"""

import asyncio
import getpass
import json
import platform
import re
import sys
import threading
from datetime import datetime
from uuid import uuid4

from aiohttp import ClientSession
from awscrt import mqtt
from awscrt.auth import AwsCredentialsProvider
from awscrt.io import ClientBootstrap
from awsiot import iotshadow
from awsiot.mqtt_connection_builder import websockets_with_default_aws_signing
from hatch_rest_api import AwsHttp

API_URL = "https://data.hatchbaby.com/"
HEADERS = {"User-Agent": "hatch_rest_api"}
MQTT_TIMEOUT = 30
REST_PAUSE_SECONDS = 1
MAX_IOT_VALUE = 65535
# Every product code hatch_rest_api and homebridge-hatch-baby-rest ask for.
KNOWN_PRODUCTS = (
    "restMini",
    "restPlus",
    "riot",
    "riotPlus",
    "restBaby",
    "restore",
    "restoreIot",
    "restoreV4",
    "restoreV5",
)
# Device record fields worth showing; the rest identify the account or device.
DEVICE_FIELDS = ("product", "name", "hardwareVersion", "createDate", "updateDate", "owner")
REDACTED_KEYS = {
    key.lower()
    for key in (
        "email",
        "password",
        "token",
        "macAddress",
        "thingName",
        "memberId",
        "identityId",
        "requestedPin",
        "requestedMacAddress",
        "connectedMacAddress",
        "ssid",
    )
}
REDACTED = "***"
MIN_SECRET_LENGTH = 6
MAC_PATTERN = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")

HELP = """
Commands:
  get              print the whole shadow again
  on               start the bedtime routine at step 1     (known to work)
  off              stop whatever is playing                (known to work)
  vol <0-100>      EXPERIMENTAL: write desired sound.v
  bright <0-100>   EXPERIMENTAL: write desired color.i
  raw <json>       EXPERIMENTAL: write <json> as the desired state
  help             this list
  quit             disconnect and exit

Changes print as they happen, so you can also just change things in the
Hatch app and watch which keys move.
"""


class Report:
    """Prints to the terminal and appends to the report file, redacted."""

    def __init__(self, path: str):
        self.path = path
        self.secrets: set[str] = set()
        self._lock = threading.Lock()

    def add_secret(self, value) -> None:
        # Long values only: scrubbing a short one (a numeric id, say) out of
        # every line would mangle unrelated numbers. Short identifiers are
        # kept out of the output by key instead.
        if not value or len(str(value)) < MIN_SECRET_LENGTH:
            return
        value = str(value)
        self.secrets.add(value)
        if MAC_PATTERN.fullmatch(value):
            bare = re.sub("[:-]", "", value)
            self.secrets.update({bare, bare.lower(), bare.upper(), value.lower(), value.upper()})

    def scrub(self, text: str) -> str:
        for secret in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(secret, REDACTED)
        return MAC_PATTERN.sub(REDACTED, text)

    def out(self, text: str = "") -> None:
        text = self.scrub(text)
        with self._lock:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
            with open(self.path, "a", encoding="utf-8") as report_file:
                report_file.write(text + "\n")

    def dump(self, title: str, data) -> None:
        self.out(f"--- {title}")
        self.out(json.dumps(redact(data), indent=2, sort_keys=True, default=str))


def redact(data):
    if isinstance(data, dict):
        return {
            key: REDACTED if str(key).lower() in REDACTED_KEYS else redact(value)
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [redact(item) for item in data]
    return data


def flatten(data, prefix: str = "") -> dict:
    if not isinstance(data, dict):
        return {prefix: data} if prefix else {}
    flat = {}
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict) and value:
            flat.update(flatten(value, path))
        else:
            flat[path] = value
    return flat


def describe(path: str, value) -> str:
    """The value, plus its percentage for the 0-65535 sound and light levels."""
    text = json.dumps(value, default=str)
    if (
        re.search(r"\.(v|i)$", path)
        and isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_IOT_VALUE
    ):
        text += f" (~{round(value / MAX_IOT_VALUE * 100)}%)"
    return text


def changes(previous: dict | None, current: dict | None) -> list[str]:
    before, after = flatten(previous or {}), flatten(current or {})
    lines = []
    for path in sorted(before.keys() | after.keys()):
        if before.get(path, "<absent>") != after.get(path, "<absent>"):
            old = describe(path, before[path]) if path in before else "<absent>"
            new = describe(path, after[path]) if path in after else "<absent>"
            lines.append(f"  {path}: {old} -> {new}")
    return lines


def percent_to_iot(text: str) -> int:
    percent = int(text)
    if not 0 <= percent <= 100:
        raise ValueError("give a percentage from 0 to 100")
    return round(percent / 100 * MAX_IOT_VALUE)


def parse_command(line: str) -> tuple[str, dict | None, bool]:
    """Return (command, desired state to write or None, whether it is experimental)."""
    command, _, argument = line.strip().partition(" ")
    command = command.lower()
    argument = argument.strip()
    if command == "on":
        return command, {"content": {"playing": "routine", "paused": False, "offset": 0, "step": 1}}, False
    if command == "off":
        return command, {"content": {"playing": "none", "paused": False, "offset": 0, "step": 0}}, False
    if command == "vol":
        return command, {"sound": {"v": percent_to_iot(argument)}}, True
    if command == "bright":
        return command, {"color": {"i": percent_to_iot(argument)}}, True
    if command == "raw":
        desired = json.loads(argument)
        if not isinstance(desired, dict) or not desired:
            raise ValueError("raw needs a JSON object, e.g. raw {\"sound\": {\"v\": 6554}}")
        return command, desired, True
    return command, None, False


async def login(session: ClientSession, email: str, password: str) -> str:
    async with session.post(
        API_URL + "public/v1/login",
        json={"email": email, "password": password},
        headers=HEADERS,
    ) as response:
        if response.status == 429:
            raise SystemExit(
                "Hatch rejected the login as rate limited (HTTP 429). Wait a while "
                "before running this again; it does not retry."
            )
        try:
            body = await response.json(content_type=None)
        except ValueError:
            raise SystemExit(f"Login failed: HTTP {response.status}, not a JSON answer") from None
    if not isinstance(body, dict) or body.get("status") != "success" or not body.get("token"):
        raise SystemExit(f"Login failed: {body.get('message') or body.get('errorCode')}")
    return body["token"]


async def get(session: ClientSession, token: str, path: str, params=None):
    async with session.get(
        API_URL + path,
        headers={**HEADERS, "X-HatchBaby-Auth": token},
        params=params,
    ) as response:
        try:
            body = await response.json(content_type=None)
        except ValueError:
            body = (await response.text())[:500]
        return response.status, body


def summarize_content(payload):
    """Content items carry long asset URLs; keep everything else."""
    if isinstance(payload, dict):
        return {key: summarize_content(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [summarize_content(item) for item in payload]
    if isinstance(payload, str) and payload.startswith("http"):
        return "<url>"
    return payload


async def probe_rest(report: Report, session: ClientSession, token: str, mac: str) -> None:
    probes = (
        ("routines (v2, types=routine)", "service/app/routine/v2/fetch", [("macAddress", mac), ("types", "routine")]),
        ("favorites (v2, no type)", "service/app/routine/v2/fetch", [("macAddress", mac)]),
        ("alarms (v3, types=alarm)", "service/app/routine/v3/fetch", [("macAddress", mac), ("types", "alarm")]),
        (
            "sound and color content for product restore",
            "service/app/content/v1/fetchByProduct",
            [("product", "restore"), ("contentTypes", "sound"), ("contentTypes", "color")],
        ),
    )
    for title, path, params in probes:
        await asyncio.sleep(REST_PAUSE_SECONDS)
        status, body = await get(session, token, path, params)
        report.dump(f"{title}: HTTP {status}", summarize_content(body))
        if status == 429:
            report.out("Rate limited; skipping the remaining REST probes.")
            return


class ShadowWatcher:
    def __init__(self, report: Report, shadow_client, thing_name: str, label: str):
        self.report = report
        self.shadow_client = shadow_client
        self.thing_name = thing_name
        self.label = label

    def subscribe(self) -> None:
        thing = self.thing_name
        qos = mqtt.QoS.AT_LEAST_ONCE
        subscriptions = (
            (self.shadow_client.subscribe_to_get_shadow_accepted, iotshadow.GetShadowSubscriptionRequest, self._on_get),
            (self.shadow_client.subscribe_to_get_shadow_rejected, iotshadow.GetShadowSubscriptionRequest, self._on_rejected("get")),
            (self.shadow_client.subscribe_to_update_shadow_accepted, iotshadow.UpdateShadowSubscriptionRequest, self._on_update_accepted),
            (self.shadow_client.subscribe_to_update_shadow_rejected, iotshadow.UpdateShadowSubscriptionRequest, self._on_rejected("update")),
            (self.shadow_client.subscribe_to_shadow_updated_events, iotshadow.ShadowUpdatedSubscriptionRequest, self._on_document),
        )
        for subscribe, request_type, callback in subscriptions:
            future, _ = subscribe(request=request_type(thing_name=thing), qos=qos, callback=callback)
            future.result(MQTT_TIMEOUT)

    def request_shadow(self) -> None:
        self.shadow_client.publish_get_shadow(
            request=iotshadow.GetShadowRequest(thing_name=self.thing_name),
            qos=mqtt.QoS.AT_LEAST_ONCE,
        ).result(MQTT_TIMEOUT)

    def write(self, desired: dict) -> None:
        self.shadow_client.publish_update_shadow(
            iotshadow.UpdateShadowRequest(
                thing_name=self.thing_name,
                state=iotshadow.ShadowState(desired=desired),
            ),
            mqtt.QoS.AT_LEAST_ONCE,
        ).result(MQTT_TIMEOUT)

    def _on_get(self, response) -> None:
        state = response.state
        self.report.dump(
            f"{self.label} full shadow, version {response.version}",
            {
                "reported": state.reported if state else None,
                "desired": state.desired if state else None,
                "delta": state.delta if state else None,
            },
        )

    def _on_update_accepted(self, response) -> None:
        desired = response.state.desired if response.state else None
        if desired:
            self.report.dump(f"{self.label} update accepted, version {response.version}, desired", desired)

    def _on_rejected(self, operation: str):
        def callback(error) -> None:
            self.report.out(f"--- {self.label} {operation} REJECTED: {error.code} {error.message}")

        return callback

    def _on_document(self, event) -> None:
        previous = event.previous.state if event.previous else None
        current = event.current.state if event.current else None
        stamp = datetime.now().strftime("%H:%M:%S")
        for side in ("desired", "reported"):
            lines = changes(
                getattr(previous, side, None) if previous else None,
                getattr(current, side, None) if current else None,
            )
            if lines:
                source = "written (desired)" if side == "desired" else "device reported"
                self.report.out(f"[{stamp}] {self.label} {source}:")
                for line in lines:
                    self.report.out(line)


async def connect_mqtt(report: Report, session: ClientSession, token: str, safe_email: str):
    status, body = await get(session, token, "service/app/restPlus/token/v1/fetch")
    if status != 200 or not isinstance(body, dict) or "payload" not in body:
        raise SystemExit(f"Could not fetch the IoT token: HTTP {status}")
    aws_token = body["payload"]
    for key in ("token", "identityId"):
        report.add_secret(aws_token.get(key))
    credentials = (
        await AwsHttp(session).aws_credentials(
            region=aws_token["region"],
            identityId=aws_token["identityId"],
            aws_token=aws_token["token"],
        )
    )["Credentials"]
    for key in ("AccessKeyId", "SecretKey", "SessionToken"):
        report.add_secret(credentials.get(key))
    expires = credentials.get("Expiration")
    if expires:
        report.out(f"AWS credentials expire at {datetime.fromtimestamp(expires):%H:%M:%S}")

    connection = websockets_with_default_aws_signing(
        region=aws_token["region"],
        credentials_provider=AwsCredentialsProvider.new_static(
            credentials["AccessKeyId"],
            credentials["SecretKey"],
            session_token=credentials["SessionToken"],
        ),
        keep_alive_secs=30,
        client_bootstrap=ClientBootstrap.get_or_create_static_default(),
        endpoint=aws_token["endpoint"].removeprefix("https://"),
        # Same client id scheme as hatch_rest_api.
        client_id=f"hatch_rest_api/{safe_email}/{uuid4()}",
        enable_metrics_collection=False,
    )
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, lambda: connection.connect().result(MQTT_TIMEOUT))
    report.out("MQTT connected")
    return connection


def pick_device(report: Report, restores: list[dict]) -> dict:
    if len(restores) == 1:
        return restores[0]
    for index, device in enumerate(restores, start=1):
        report.out(f"  {index}: {device.get('name')}")
    while True:
        choice = input(f"Which Restore to watch [1-{len(restores)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(restores):
            return restores[int(choice) - 1]


async def command_loop(report: Report, watcher: ShadowWatcher) -> None:
    loop = asyncio.get_running_loop()
    report.out(HELP)
    while True:
        try:
            line = await loop.run_in_executor(None, input, "probe> ")
        except EOFError:
            return
        try:
            command, desired, experimental = parse_command(line)
        except (ValueError, json.JSONDecodeError) as error:
            report.out(f"! {error}")
            continue
        if command in ("quit", "exit", "q"):
            return
        if command in ("", "help", "?"):
            report.out(HELP)
            continue
        if command == "get":
            await loop.run_in_executor(None, watcher.request_shadow)
            continue
        if desired is None:
            report.out(f"! unknown command {command!r}; type help")
            continue
        report.out(f"> {command}: desired {json.dumps(desired)}")
        if experimental:
            answer = await loop.run_in_executor(
                None, input, "Experimental write, not known to work on this model. Send it? [y/N] "
            )
            if answer.strip().lower() != "y":
                report.out("  not sent")
                continue
        await loop.run_in_executor(None, watcher.write, desired)
        report.out("  sent; watch for 'device reported' lines to see whether it took")


async def main() -> None:
    report = Report(f"restore-probe-{datetime.now():%Y%m%d-%H%M%S}.log")
    report.out(f"Hatch Restore probe, {datetime.now():%Y-%m-%d %H:%M}, Python {platform.python_version()}")
    email = input("Hatch email: ").strip()
    password = getpass.getpass("Hatch password (hidden): ")
    report.add_secret(email)
    report.add_secret(password)
    safe_email = re.sub("[^a-z]", "", email, flags=re.IGNORECASE).lower()
    report.add_secret(safe_email)

    async with ClientSession() as session:
        token = await login(session, email, password)
        report.add_secret(token)
        del password
        report.out("Logged in")

        await asyncio.sleep(REST_PAUSE_SECONDS)
        status, body = await get(session, token, "service/app/v2/member")
        member = body.get("payload") if isinstance(body, dict) else None
        account_products = list((member or {}).get("products") or [])
        report.dump(f"account product codes: HTTP {status}", account_products)

        products = list(dict.fromkeys([*KNOWN_PRODUCTS, *account_products]))
        await asyncio.sleep(REST_PAUSE_SECONDS)
        status, body = await get(
            session,
            token,
            "service/app/iotDevice/v2/fetch",
            [("iotProducts", product) for product in products],
        )
        devices = (body.get("payload") if isinstance(body, dict) else None) or []
        for device in devices:
            for key in ("macAddress", "thingName", "email"):
                report.add_secret(device.get(key))
        report.dump(
            f"devices for {', '.join(products)}: HTTP {status}",
            [{key: device.get(key) for key in DEVICE_FIELDS} for device in devices],
        )

        restores = [device for device in devices if device.get("product") == "restore"]
        if not restores:
            report.out("No device with product 'restore' on this account; nothing more to probe.")
            return

        for device in restores:
            report.out(f"=== REST endpoints for {device.get('name')}")
            await probe_rest(report, session, token, device["macAddress"])

        device = pick_device(report, restores)
        connection = await connect_mqtt(report, session, token, safe_email)
        loop = asyncio.get_running_loop()
        try:
            watcher = ShadowWatcher(
                report, iotshadow.IotShadowClient(connection), device["thingName"], device.get("name", "Restore")
            )
            await loop.run_in_executor(None, watcher.subscribe)
            await loop.run_in_executor(None, watcher.request_shadow)
            await command_loop(report, watcher)
        finally:
            try:
                await loop.run_in_executor(None, lambda: connection.disconnect().result(10))
            except Exception as error:
                report.out(f"disconnect: {error}")
    report.out(f"Report written to {report.path}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.stdout.write("\ninterrupted\n")
    except EOFError:
        sys.stdout.write("\nno input (run the container with -it); exiting\n")
