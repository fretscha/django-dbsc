"""Exhaust Chrome's DBSC signing quota and check that the session survives it.

Run the demo with a short bound-cookie lifetime (DBSC_BOUND_COOKIE_MAX_AGE=20). Chrome then refreshes on almost
every request, hits SigningQuotaExceeded, and sends Secure-Session-Skipped. Expected with fix 2: those requests get
401, but the session is NOT ended, and access comes back once Chrome's quota window allows a refresh again.

Usage:
    uv run --with playwright python example/scripts/quota_soak.py [rounds] [interval_seconds]
"""

import os
import sys
import time

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE", "https://localhost:8443")
CDP = "http://127.0.0.1:9333"


def main(rounds: int, interval: int) -> None:
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP)
        context = browser.contexts[0]
        page = context.pages[0] if context.pages else context.new_page()
        cdp = context.new_cdp_session(page)
        chrome_events = []

        def on_event(event):
            details = event.get("refreshEventDetails") or event.get("creationEventDetails") or {}
            kind = "refresh" if "refreshEventDetails" in event else "creation" if details else "other"
            chrome_events.append((time.strftime("%H:%M:%S"), kind, details.get("fetchResult"), event.get("succeeded")))

        cdp.on("Network.deviceBoundSessionEventOccurred", on_event)
        cdp.send("Network.enable")
        cdp.send("Network.enableDeviceBoundSessions", {"enable": True})

        page.goto(BASE + "/accounts/login/")
        page.fill("#id_username", "alice")
        page.fill("#id_password", "demo-pw")
        page.click("#submit")
        page.wait_for_load_state()
        time.sleep(3)

        for i in range(rounds):
            response = page.goto(BASE + "/protected/")
            body = page.inner_text("body")[:60].replace("\n", " ")
            names = {c["name"] for c in context.cookies(BASE)}
            print(
                f"[{time.strftime('%H:%M:%S')}] #{i:02d} {response.status if response else '-'} {body!r:62} "
                f"session={'sessionid' in names} bound={'dbsc_bound' in names}",
                flush=True,
            )
            time.sleep(interval)

        print("\nChrome DBSC events:")
        for ts, kind, result, ok in chrome_events:
            print(f"  {ts} {kind:8} {result} succeeded={ok}")
        browser.close()


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 22, int(sys.argv[2]) if len(sys.argv) > 2 else 20)
