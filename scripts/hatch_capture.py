"""mitmproxy addon: record the Hatch app's API calls, redacted.

Fork-only development tool, used to find which Hatch API calls read and save
alarms for the original Restore. Only requests to Hatch's own API hosts are
recorded; every other host is counted by name and nothing else. Tokens,
passwords, email addresses, MAC addresses and thing names are replaced with
*** in everything written.

Run with mitmdump from the directory holding this file:

  docker run --rm -it -p 8899:8080 -v "$PWD:/work" -w /work \
    -v "$PWD/mitmproxy-ca:/home/mitmproxy/.mitmproxy" \
    mitmproxy/mitmproxy mitmdump -q -s hatch_capture.py

Each call is printed as one line and appended, with request and response
bodies, to hatch-capture-<time>.jsonl in the current directory.
"""

import json
import re
from collections import Counter
from datetime import datetime

from mitmproxy import http

HATCH_HOSTS = ("hatchbaby.com", "hatch.co")
REDACTED = "***"
MAX_BODY_CHARACTERS = 40_000
MIN_SECRET_LENGTH = 6
REDACTED_KEYS = {
    key.lower()
    for key in (
        "email",
        "password",
        "token",
        "authorization",
        "x-hatchbaby-auth",
        "cookie",
        "set-cookie",
        "macAddress",
        "thingName",
        "memberId",
        "firstName",
        "lastName",
        "phone",
        "phoneNumber",
        "address",
        "identityId",
        "requestedPin",
        "requestedMacAddress",
        "connectedMacAddress",
        "ssid",
    )
}
MAC_PATTERN = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
SECRET_HEADERS = ("x-hatchbaby-auth", "authorization", "cookie")


def is_hatch_host(host: str) -> bool:
    return any(host == base or host.endswith("." + base) for base in HATCH_HOSTS)


def redact(data):
    if isinstance(data, dict):
        return {
            key: REDACTED if str(key).lower() in REDACTED_KEYS else redact(value)
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [redact(item) for item in data]
    return data


def parse_body(text: str | None):
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text[:MAX_BODY_CHARACTERS]


def summarize(body) -> str:
    """A few words on the response, for the one-line console view."""
    if not isinstance(body, dict):
        return ""
    payload = body.get("payload")
    if isinstance(payload, list):
        return f"{len(payload)} item(s)"
    if isinstance(payload, dict):
        return "keys: " + ", ".join(sorted(payload)[:8])
    return str(body.get("message") or "")[:60]


class HatchCapture:
    def __init__(self):
        self.path = f"hatch-capture-{datetime.now():%Y%m%d-%H%M%S}.jsonl"
        self.secrets: set[str] = set()
        self.other_hosts: Counter[str] = Counter()
        self.calls = 0

    def add_secret(self, value) -> None:
        if value and len(str(value)) >= MIN_SECRET_LENGTH:
            self.secrets.add(str(value))

    def scrub(self, text: str) -> str:
        for secret in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(secret, REDACTED)
        return MAC_PATTERN.sub(REDACTED, text)

    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not is_hatch_host(host):
            self.other_hosts[host] += 1
            return

        for header in SECRET_HEADERS:
            self.add_secret(flow.request.headers.get(header))
        request_body = parse_body(flow.request.get_text(strict=False))
        response_body = parse_body(flow.response.get_text(strict=False) if flow.response else None)
        for body in (request_body, response_body):
            if isinstance(body, dict):
                self.add_secret(body.get("token"))
                self.add_secret(body.get("email"))
                self.add_secret(body.get("password"))
                payload = body.get("payload")
                if isinstance(payload, dict):
                    self.add_secret(payload.get("token"))
                    self.add_secret(payload.get("email"))

        status = flow.response.status_code if flow.response else None
        record = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "method": flow.request.method,
            "host": host,
            "path": flow.request.path.split("?", 1)[0],
            "query": redact({key: flow.request.query.get_all(key) for key in flow.request.query}),
            "request_headers": sorted(flow.request.headers.keys()),
            "request_body": redact(request_body),
            "status": status,
            "response_body": redact(response_body),
        }
        line = self.scrub(json.dumps(record, default=str))
        with open(self.path, "a", encoding="utf-8") as capture_file:
            capture_file.write(line + "\n")
        self.calls += 1

        query = "&".join(f"{key}=" for key in record["query"])
        print(  # noqa: T201
            self.scrub(
                f"{record['time'][11:]}  {record['method']:<6} {host}{record['path']}"
                + (f"?{query}" if query else "")
                + f"  -> {status}  {summarize(response_body)}"
            ),
            flush=True,
        )

    def done(self) -> None:
        print(f"\n{self.calls} Hatch call(s) written to {self.path}", flush=True)  # noqa: T201
        if self.other_hosts:
            summary = ", ".join(f"{host} ({count})" for host, count in self.other_hosts.most_common(15))
            print(f"Other hosts seen, not recorded: {summary}", flush=True)  # noqa: T201
            with open(self.path, "a", encoding="utf-8") as capture_file:
                capture_file.write(json.dumps({"other_hosts": dict(self.other_hosts)}) + "\n")


addons = [HatchCapture()]
