#!/usr/bin/env python3
"""Probe an original Hatch Restore (Hatch product "restore") through the Hatch cloud.

Fork-only development tool for the restore work; HACS does not ship it.

One login, then:
  1. the product codes on the account, and the devices Hatch returns, both
     for the known product codes and with no product filter at all
  2. what the REST endpoints the other Restores use answer for this one
     (routines, alarms, sound and color content)
  3. the full device shadow over AWS IoT, as the Hatch app reads it, and then
     every change to it as it happens -- including the desired state the
     Hatch app writes when you change something there
  4. a command prompt, to re-read the shadow or try a write
  5. with --test (or the "test" command), a guided pass over every control:
     each one is sent, what the device reported back is shown, you say what
     you saw, and a working / not working table is printed at the end.
     Settings the pass changes are put back afterwards.

It prefers a device with product "restore", but will watch any device the
account has, so it still helps when the Restore turns out to be listed under
another product code.

Nothing is written to the device unless you type a write command. The login
is asked for at a hidden prompt and kept in memory only. Tokens, AWS keys and
identifying values (email, MAC addresses, thing name, device names, member
id, headphone PIN) are redacted from everything printed and from the report file,
restore-probe-<time>.log in the current directory.

Run it in a throwaway container from the directory holding this file:

  docker run --rm -it -v "$PWD:/work" -w /work python:3.13-slim sh -c \
    "pip install -q --root-user-action=ignore hatch_rest_api==1.35.0 tzdata && python probe_restore.py --test"

Hatch rate limits logins (HTTP 429). This logs in once per run and never
retries; on a rate limit, wait before running it again. The AWS credentials
it gets last about an hour, so a session ends by then.
"""

import argparse
import asyncio
import getpass
import json
import platform
import re
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import uuid4
from zoneinfo import ZoneInfo

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
# Device names are left out: people often name a device after someone.
DEVICE_FIELDS = ("product", "hardwareVersion", "createDate", "updateDate", "owner")
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
  on               start the bedtime routine at step 1     (known to work on product restore)
  off              stop whatever is playing                (known to work on product restore)
  vol <0-100>      EXPERIMENTAL: write desired sound.v
  bright <0-100>   EXPERIMENTAL: write desired color.i
  raw <json>       EXPERIMENTAL: write <json> as the desired state
  test             guided test of every control, with a results table
  help             this list
  quit             disconnect and exit

Changes print as they happen, so you can also change things in the Hatch
app or on the device itself and watch which keys move.
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


def parse_command(line: str, product: str = "restore") -> tuple[str, dict | None, bool]:
    """Return (command, desired state to write or None, whether it is experimental).

    on and off are only known to work on product restore; on anything else
    they are experimental like the rest.
    """
    command, _, argument = line.strip().partition(" ")
    command = command.lower()
    argument = argument.strip()
    proven = product == "restore"
    if command == "on":
        return command, {"content": {"playing": "routine", "paused": False, "offset": 0, "step": 1}}, not proven
    if command == "off":
        return command, {"content": {"playing": "none", "paused": False, "offset": 0, "step": 0}}, not proven
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


def compact_content(body):
    """The catalog runs to tens of thousands of lines; keep what a picker needs."""
    payload = body.get("payload") if isinstance(body, dict) else None
    if not isinstance(payload, dict) or not isinstance(payload.get("contentItems"), list):
        return summarize_content(body)
    items = payload["contentItems"]
    visible = [
        {
            "id": item.get("id"),
            "title": item.get("title"),
            "type": item.get("contentType"),
            "alarmOnly": item.get("alarmOnly"),
        }
        for item in items
        if not item.get("hidden")
    ]
    return {"status": body.get("status"), "items": len(items), "hidden": len(items) - len(visible), "visible": visible}


async def probe_rest(report: Report, session: ClientSession, token: str, mac: str, product: str) -> None:
    probes = (
        ("routines (v2, types=routine)", "service/app/routine/v2/fetch", [("macAddress", mac), ("types", "routine")]),
        ("favorites (v2, no type)", "service/app/routine/v2/fetch", [("macAddress", mac)]),
        ("alarms (v3, types=alarm)", "service/app/routine/v3/fetch", [("macAddress", mac), ("types", "alarm")]),
        ("alarms (v2, types=alarm)", "service/app/routine/v2/fetch", [("macAddress", mac), ("types", "alarm")]),
        ("everything scheduled (v3, no type filter)", "service/app/routine/v3/fetch", [("macAddress", mac)]),
        (
            f"sound and color content for product {product}",
            "service/app/content/v1/fetchByProduct",
            [("product", product), ("contentTypes", "sound"), ("contentTypes", "color")],
        ),
    )
    for title, path, params in probes:
        await asyncio.sleep(REST_PAUSE_SECONDS)
        status, body = await get(session, token, path, params)
        report.dump(f"{title}: HTTP {status}", compact_content(body) if "content" in path else summarize_content(body))
        if status == 429:
            report.out("Rate limited; skipping the remaining REST probes.")
            return


class ShadowWatcher:
    def __init__(self, report: Report, shadow_client, thing_name: str, label: str, product: str):
        self.report = report
        self.shadow_client = shadow_client
        self.thing_name = thing_name
        self.label = label
        self.product = product
        self.reported: dict | None = None
        self.ready = threading.Event()
        self._lock = threading.Lock()
        self._capture: list[str] | None = None
        self._last_change = 0.0

    def start_capture(self) -> None:
        with self._lock:
            self._capture = []

    def stop_capture(self) -> list[str]:
        with self._lock:
            captured, self._capture = self._capture or [], None
            return captured

    def capture_state(self) -> tuple[bool, float]:
        with self._lock:
            return bool(self._capture), self._last_change

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
        if state and state.reported:
            self.reported = state.reported
            self.ready.set()
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
        if current is not None and getattr(current, "reported", None):
            self.reported = current.reported
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
                if side == "reported":
                    with self._lock:
                        if self._capture is not None:
                            self._capture.extend(lines)
                        self._last_change = time.monotonic()


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


def device_list(report: Report, title: str, status: int, body) -> list[dict]:
    payload = body.get("payload") if isinstance(body, dict) else None
    devices = [device for device in payload or [] if isinstance(device, dict)]
    for device in devices:
        for key in ("macAddress", "thingName", "email", "name"):
            report.add_secret(device.get(key))
    report.dump(
        f"{title}: HTTP {status}",
        [{key: device.get(key) for key in DEVICE_FIELDS} for device in devices]
        if devices
        else body,
    )
    return devices


def pick_device(report: Report, candidates: list[dict]) -> dict:
    if len(candidates) == 1:
        return candidates[0]
    for index, device in enumerate(candidates, start=1):
        report.out(
            f"  {index}: product {device.get('product')}, hardware {device.get('hardwareVersion')}, "
            f"added {device.get('createDate')}"
        )
    while True:
        choice = input(f"Which device to watch [1-{len(candidates)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(candidates):
            return candidates[int(choice) - 1]


# ---- guided test pass -------------------------------------------------------

CLOCK_ON = 1 << 15  # the bit hatch_rest_api calls RIOT_FLAGS_CLOCK_ON
CLOCK_24_HOUR = 1 << 11
# From this model's content catalog.
WARM_WHITE = 229
BLUE = 218
LIGHT_RAIN = 10040
WHITE_NOISE = 10033
REMOTE = {"playing": "remote", "paused": False, "offset": 0, "step": 0}
STOP = {"playing": "none", "paused": False, "offset": 0, "step": 0}
ROUTINE_STEP_2 = {"playing": "routine", "paused": False, "offset": 0, "step": 2}
ANSWERS = {"y": "WORKS", "n": "NO EFFECT", "p": "PARTLY", "s": "SKIPPED"}

TEST_INTRO = """
Guided test of the light, sound, volume, clock and alarm settings.
Each check sends one command, waits a few seconds for the Restore to report
back, then asks what you saw on the device. Answer:
  y  it did what the question asks     p  something else happened (say what)
  n  nothing happened                  s  skip / can't tell
  q  stop testing
Volume stays at 30% or below. At the end playback is stopped and the sound,
light, clock and alarm settings are put back as they are now. Use q rather
than Ctrl+C to stop early, so the settings still get put back.
"""


def pct(percent: int) -> int:
    return round(percent / 100 * MAX_IOT_VALUE)


def clock_flags(baseline: dict) -> int:
    return int((baseline.get("restoreClock") or {}).get("flags") or 0)


def night_schedule_now(baseline: dict) -> dict:
    """turnOffMode custom, with the off period starting a minute ago."""
    now = datetime.now(ZoneInfo(baseline.get("timezone") or "UTC"))
    return {
        "restoreClock": {
            "flags": clock_flags(baseline) | CLOCK_ON,
            "turnOffMode": "custom",
            "turnOffAt": (now - timedelta(minutes=1)).strftime("%H:%M:00"),
            "turnOnAt": (now + timedelta(hours=3)).strftime("%H:%M:00"),
        }
    }


@dataclass(frozen=True)
class Check:
    name: str
    sends: str
    look_for: str
    desired: Callable[[dict], dict]
    loud: bool = False


CHECKS = (
    Check("light, playback untouched", "Warm White at 30%, without starting playback", "Did the light come on?",
          lambda b: {"color": {"enabled": True, "id": WARM_WHITE, "i": pct(30)}}),
    Check("light, remote playback", "remote playback + Warm White at 30%", "Is the light on, warm white and dim?",
          lambda b: {"content": REMOTE, "color": {"enabled": True, "id": WARM_WHITE, "i": pct(30)}}),
    Check("light brightness", "light brightness 70%", "Did the light get brighter?",
          lambda b: {"color": {"i": pct(70)}}),
    Check("light colour", "light colour Blue", "Did the light turn blue?",
          lambda b: {"color": {"id": BLUE}}),
    Check("sound, remote playback", "remote playback + Light Rain at 15%", "Is quiet rain playing?",
          lambda b: {"content": REMOTE, "sound": {"enabled": True, "id": LIGHT_RAIN, "v": pct(15)}}),
    Check("volume", "volume 30%", "Did it get louder?",
          lambda b: {"sound": {"v": pct(30)}}),
    Check("sound type", "sound White Noise", "Did it change to white noise?",
          lambda b: {"sound": {"id": WHITE_NOISE}}),
    Check("light off, sound kept", "light disabled", "Is the light off with the sound still playing?",
          lambda b: {"color": {"enabled": False}}),
    Check("light back on", "light enabled", "Did the light come back on?",
          lambda b: {"color": {"enabled": True}}),
    Check("sound off, light kept", "sound disabled", "Did the sound stop with the light still on?",
          lambda b: {"sound": {"enabled": False}}),
    Check("stop everything", "playback none (the known off command)", "Are the light and sound both off?",
          lambda b: {"content": STOP}),
    Check("clock brightness", "clock brightness 40%", "Did the clock get brighter?",
          lambda b: {"restoreClock": {"i": pct(40)}}),
    Check("clock display off", "clock display flag cleared", "Did the clock display turn off?",
          lambda b: {"restoreClock": {"flags": clock_flags(b) & ~CLOCK_ON}}),
    Check("clock display on", "clock display flag set", "Did the clock come back on?",
          lambda b: {"restoreClock": {"flags": clock_flags(b) | CLOCK_ON}}),
    Check("clock 24-hour", "clock 24-hour flag set",
          "Is it showing 24-hour time? (Before 1 pm it looks the same: answer s)",
          lambda b: {"restoreClock": {"flags": clock_flags(b) | CLOCK_ON | CLOCK_24_HOUR}}),
    Check("clock mode: always off", "clock turnOffMode always", "Did the clock turn off?",
          lambda b: {"restoreClock": {"flags": clock_flags(b) | CLOCK_ON, "turnOffMode": "always"}}),
    Check("clock mode: night schedule", "clock turnOffMode custom, off since a minute ago",
          "Is the clock off?", night_schedule_now),
    Check("alarms off", "alarmsDisabled true", "Did the crossed-bell light on the bottom come on?",
          lambda b: {"alarmsDisabled": True}),
    Check("alarms back on", "alarmsDisabled false", "Did the crossed-bell light go off again?",
          lambda b: {"alarmsDisabled": False}),
    Check("routine at step 2", "bedtime routine started at step 2",
          "Did the routine start? (It should report step 2)",
          lambda b: {"content": ROUTINE_STEP_2}, loud=True),
    Check("volume during routine", "volume 15% while the routine plays", "Did the routine get quieter?",
          lambda b: {"sound": {"v": pct(15)}}, loud=True),
    Check("stop routine", "playback none", "Did the routine stop?",
          lambda b: {"content": STOP}, loud=True),
)


def restore_payload(baseline: dict) -> dict:
    desired: dict = {"content": STOP}
    for key, fields in (("sound", ("enabled", "id", "v")), ("color", ("enabled", "id", "i"))):
        block = baseline.get(key)
        if isinstance(block, dict):
            desired[key] = {field: block[field] for field in fields if field in block}
    clock = baseline.get("restoreClock")
    if isinstance(clock, dict):
        desired["restoreClock"] = {
            field: clock[field]
            for field in ("i", "flags", "turnOnAt", "turnOffAt", "turnOffMode")
            if field in clock
        }
    if "alarmsDisabled" in baseline:
        desired["alarmsDisabled"] = baseline["alarmsDisabled"]
    return desired


async def ask(prompt: str) -> str:
    return (await asyncio.get_running_loop().run_in_executor(None, input, prompt)).strip().lower()


async def wait_for_reports(watcher: ShadowWatcher, timeout: float = 8.0, settle: float = 1.5) -> None:
    """Until the device has reported and gone quiet, or the timeout."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        await asyncio.sleep(0.5)
        reported, last_change = watcher.capture_state()
        if reported and time.monotonic() - last_change >= settle:
            return


async def run_check(report: Report, watcher: ShadowWatcher, check: Check, baseline: dict, number: int):
    report.out(f"\n=== Check {number}/{len(CHECKS)}: {check.name}")
    try:
        desired = check.desired(baseline)
    except Exception as error:
        report.out(f"  cannot build this check ({error}); skipped")
        return check, "SKIPPED", [], str(error)
    report.out(f"  sends {check.sends}: {json.dumps(desired)}")
    watcher.start_capture()
    await asyncio.get_running_loop().run_in_executor(None, watcher.write, desired)
    await wait_for_reports(watcher)
    reported = watcher.stop_capture()
    report.out(f"  device reported {len(reported)} change(s)" if reported else "  device reported no change")
    answer = ""
    while answer not in (*ANSWERS, "q"):
        answer = await ask(f"  {check.look_for}  [y/n/p/s/q] ")
    if answer == "q":
        report.out("  you: stop testing")
        return check, "STOPPED", reported, ""
    note = await ask("  What happened? ") if answer == "p" else ""
    report.out(f"  you: {ANSWERS[answer]}" + (f" - {note}" if note else ""))
    return check, ANSWERS[answer], reported, note


def report_results(report: Report, results: list) -> None:
    report.out("\n=== Results")
    width = max(len(check.name) for check in CHECKS)
    for check, verdict, reported, note in results:
        evidence = f"device reported {len(reported)} change(s)" if reported else "device reported nothing"
        if verdict == "SKIPPED" and note == "not chosen":
            evidence = ""
        report.out(f"  {verdict:<10} {check.name:<{width}}  {evidence}" + (f"  ({note})" if note else ""))


async def run_tests(report: Report, watcher: ShadowWatcher) -> None:
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, watcher.ready.wait, 15):
        report.out("! no device state received yet; type get, then test")
        return
    baseline = json.loads(json.dumps(watcher.reported))
    report.out(TEST_INTRO)
    if await ask("Start the test? [y/N] ") != "y":
        return
    loud = await ask("Also run the 3 routine checks? Your routine plays at full volume. [y/N] ") == "y"
    results = []
    try:
        for number, check in enumerate(CHECKS, start=1):
            if check.loud and not loud:
                results.append((check, "SKIPPED", [], "not chosen"))
                continue
            result = await run_check(report, watcher, check, baseline, number)
            results.append(result)
            if result[1] == "STOPPED":
                break
    finally:
        desired = restore_payload(baseline)
        report.out(f"\n=== Putting settings back: {json.dumps(desired)}")
        try:
            await loop.run_in_executor(None, watcher.write, desired)
            await asyncio.sleep(3)
        except Exception as error:
            report.out(f"! could not put the settings back ({error}); check the clock and alarms by hand")
        report_results(report, results)


async def command_loop(report: Report, watcher: ShadowWatcher) -> None:
    loop = asyncio.get_running_loop()
    report.out(HELP)
    while True:
        try:
            line = await loop.run_in_executor(None, input, "probe> ")
        except EOFError:
            return
        try:
            command, desired, experimental = parse_command(line, watcher.product)
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
        if command == "test":
            await run_tests(report, watcher)
            continue
        if desired is None:
            report.out(f"! unknown command {command!r}; type help")
            continue
        report.out(f"> {command}: desired {json.dumps(desired)}")
        if experimental:
            report.out(f"  experimental: not known to work on product {watcher.product}")
            answer = await loop.run_in_executor(None, input, "  send it? [y/N] ")
            if answer.strip().lower() != "y":
                report.out("  not sent")
                continue
        await loop.run_in_executor(None, watcher.write, desired)
        report.out("  sent; watch for 'device reported' lines to see whether it took")


async def main(run_test_pass: bool) -> None:
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
        # The account's own product codes are part of the query, so a device
        # under a code nobody else asks for still shows up here. (Hatch
        # rejects the query without a product filter.)
        devices = device_list(report, f"devices for {', '.join(products)}", status, body)

        devices = [device for device in devices if device.get("thingName") and device.get("macAddress")]
        if not devices:
            report.out(
                "Hatch returned no devices for this login. If the Restore was set up "
                "under another Hatch account, run this again with that login."
            )
            return
        candidates = [device for device in devices if device.get("product") == "restore"]
        if not candidates:
            report.out("No device with product 'restore'; offering every device instead.")
            candidates = devices

        for device in candidates:
            report.out(f"=== REST endpoints for the {device.get('product')} added {device.get('createDate')}")
            await probe_rest(report, session, token, device["macAddress"], device.get("product", "restore"))

        device = pick_device(report, candidates)
        connection = await connect_mqtt(report, session, token, safe_email)
        loop = asyncio.get_running_loop()
        try:
            watcher = ShadowWatcher(
                report,
                iotshadow.IotShadowClient(connection),
                device["thingName"],
                device.get("product", "device"),
                device.get("product", "restore"),
            )
            await loop.run_in_executor(None, watcher.subscribe)
            await loop.run_in_executor(None, watcher.request_shadow)
            if run_test_pass:
                await run_tests(report, watcher)
            await command_loop(report, watcher)
        finally:
            try:
                await loop.run_in_executor(None, lambda: connection.disconnect().result(10))
            except Exception as error:
                report.out(f"disconnect: {error}")
    report.out(f"Report written to {report.path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Probe an original Hatch Restore.")
    parser.add_argument("--test", action="store_true", help="run the guided test of every control after connecting")
    arguments = parser.parse_args()
    try:
        asyncio.run(main(arguments.test))
    except KeyboardInterrupt:
        sys.stdout.write("\ninterrupted\n")
    except EOFError:
        sys.stdout.write("\nno input (run the container with -it); exiting\n")
