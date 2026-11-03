"""Print Chrome's own DBSC events (creation, refresh, challenge, termination) while loading one page.

Chrome fails DBSC silently from the server's point of view. These DevTools events carry the actual reason,
e.g. ``SigningQuotaExceeded`` or ``InvalidCredentialsCookie``.

Usage:
    BASE=https://localhost:8443 uv run --with playwright python example/scripts/trace_dbsc_events.py /protected/
"""

import json
import os
import sys
import time

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE", "https://localhost:8443")
CDP = "http://127.0.0.1:9333"


def main(path: str) -> None:
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP)
        context = browser.contexts[0]
        page = context.pages[0] if context.pages else context.new_page()
        cdp = context.new_cdp_session(page)
        events = []
        cdp.on("Network.deviceBoundSessionEventOccurred", lambda e: events.append(("event", e)))
        cdp.on("Network.deviceBoundSessionsAdded", lambda e: events.append(("sessions", e)))
        cdp.send("Network.enable")
        cdp.send("Network.enableDeviceBoundSessions", {"enable": True})

        page.goto(BASE + path)
        time.sleep(5)  # registration and refresh run in the background

        for kind, event in events:
            print(kind, json.dumps(event, indent=1)[:1500])
        print("events:", len(events), "cookies:", sorted(c["name"] for c in context.cookies(BASE)))
        browser.close()  # closes the CDP connection only


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/protected/")
