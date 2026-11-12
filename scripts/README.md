# Scripts

`develop`, `lint` and `setup` are the integration's development helpers. The two
Python tools below were used to work out the original Hatch Restore (product
`restore`); they are not part of the integration and HACS does not install them.
What they found is written up in
[hatch_rest_api docs/restore.md](https://github.com/jimbo2412/hatch_rest_api/blob/main/docs/restore.md).

Both handle Hatch credentials and device data, so both:

- ask for, or only see, credentials at run time, and never write them anywhere;
- redact tokens, AWS keys, passwords, email addresses, MAC addresses, thing
  names, device names and other identifiers from everything they print or save;
- write their report to the current directory, where a `.gitignore` entry keeps
  it out of commits.

Read a report before posting it anywhere public all the same.

## probe_restore.py

Talks to the Hatch cloud directly, as the Hatch app does, with one login per run.

1. Lists the account's product codes and devices.
2. Asks the REST endpoints for routines, alarms, and the sound and color catalog.
3. Connects to the device shadow over AWS IoT and prints the full state, then
   every change as it happens. That includes what the Hatch app writes, so
   changing something in the app shows exactly which keys it sets.
4. Offers a prompt: `get`, `on`, `off`, `vol`, `bright`, `raw <json>`, `test`.
   Only `on` and `off` are known writes; the others ask first.

With `--test` it runs a guided test straight away. It goes through every light,
sound, volume, clock, alarm and routine control: each check sends one command,
shows what the device reported back, and asks what you saw. It ends with a
works / no effect table and puts every setting back. Sound stays at 30% or
below; the three routine checks, which play at the routine's own volume, only
run if you say yes.

It needs Python 3.12+ with `hatch_rest_api` from PyPI. The easiest way is a
throwaway container, from the directory holding the script:

```bash
docker run --rm -it -v "$PWD:/work" -w /work python:3.13-slim sh -c \
  "pip install -q --root-user-action=ignore hatch_rest_api==1.35.0 tzdata && python probe_restore.py --test"
```

The report is `restore-probe-<time>.log`. Hatch rate limits logins (HTTP 429),
and the script logs in once and never retries.

## hatch_capture.py

A [mitmproxy](https://mitmproxy.org/) addon that records the Hatch app's API
calls. It only records calls to Hatch's own hosts, and only counts other hosts by
name. This is how the original Restore's alarm API was found.

```bash
mkdir -p mitmproxy-ca
docker run --rm -it -p 8899:8080 -v "$PWD:/work" -w /work \
  -v "$PWD/mitmproxy-ca:/home/mitmproxy/.mitmproxy" \
  mitmproxy/mitmproxy mitmdump -q -s hatch_capture.py
```

Then, on a phone on the same network:

1. Set the Wi-Fi proxy to this machine's IP address, port 8899.
2. Open `http://mitm.it`, install the iOS or Android certificate it offers, and
   on iOS turn on full trust for it (Settings → General → About → Certificate
   Trust Settings).
3. Use the Hatch app. Each Hatch call prints one line and is appended, with its
   request and response, to `hatch-capture-<time>.jsonl`.
4. **Undo:** turn the phone's proxy off, remove the mitmproxy profile (Settings →
   General → VPN & Device Management on iOS), and stop the container. Leaving
   the certificate trusted lets anyone holding `mitmproxy-ca` read that phone's
   traffic.
