"""Drive the isolated DBSC-enabled Chrome against the demo server and print what the browser sees.

Usage (see docs/real-browser-testing.md for launching Chrome and the HTTPS server):
    uv run --with playwright python example/scripts/drive_chrome.py login|refresh|steal|logout
"""

import os
import ssl
import sys
import time
import urllib.error
import urllib.request

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE", "https://localhost:8443")
CDP = "http://127.0.0.1:9333"
_INSECURE = ssl._create_unverified_context()  # local throwaway cert; used for marker/attacker requests only


LOGOUT_JS = """async (csrf) => {
    const response = await fetch('/accounts/logout/', {method: 'POST', headers: {'X-CSRFToken': csrf}});
    return response.status;
}"""


def marker(name: str) -> None:
    """Cookieless request so the server log shows where each step starts."""
    urllib.request.urlopen(f"{BASE}/accounts/login/?MARKER={name}", context=_INSECURE).read()
    print(f"\n[{time.strftime('%H:%M:%S')}] === {name} ===", flush=True)


def cookies(context) -> dict:
    return {c["name"]: c for c in context.cookies(BASE)}


def show(page, path: str) -> str:
    response = page.goto(BASE + path)
    body = page.inner_text("body")[:120] if response and response.status == 200 else ""
    print(f"  GET {path} -> {response.status if response else None} {body!r}", flush=True)
    return body


def main(step: str) -> None:
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP)
        context = browser.contexts[0]
        page = context.pages[0] if context.pages else context.new_page()

        if step == "login":
            marker("1-login")
            page.goto(BASE + "/accounts/login/")
            page.fill("#id_username", "alice")
            page.fill("#id_password", "demo-pw")
            page.click("#submit")
            page.wait_for_load_state()
            print(f"  landed on {page.url}: {page.inner_text('body')[:120]!r}")
            time.sleep(3)  # background registration
            c = cookies(context)
            print(f"  cookies: {sorted(c)}")
            if "dbsc_bound" in c:
                b = c["dbsc_bound"]
                print(
                    f"  dbsc_bound attrs: path={b['path']} secure={b['secure']} httpOnly={b['httpOnly']} "
                    f"sameSite={b['sameSite']} expires_in={b['expires'] - time.time():.0f}s"
                )
            marker("2-after-registration")
            show(page, "/protected/")
            show(page, "/sensitive/")

        elif step == "refresh":
            marker("3-wait-for-expiry")
            time.sleep(25)
            print(f"  cookies after expiry: {sorted(cookies(context))}")
            marker("4-excluded-static")
            show(page, "/static/app.css")
            marker("5-protected-after-expiry")
            show(page, "/protected/")
            print(f"  cookies after refresh: {sorted(cookies(context))}")

        elif step == "steal":
            marker("6-stolen-sessionid")
            sessionid = cookies(context)["sessionid"]["value"]
            req = urllib.request.Request(BASE + "/protected/", headers={"Cookie": f"sessionid={sessionid}"})
            try:
                status = urllib.request.urlopen(req, context=_INSECURE).status
            except urllib.error.HTTPError as exc:
                status = exc.code
            print(f"  attacker replaying only sessionid -> {status}")
            marker("7-victim-after-theft")
            show(page, "/protected/")

        elif step == "logout":
            marker("8-logout")
            csrf = cookies(context)["csrftoken"]["value"]
            status = page.evaluate(LOGOUT_JS, csrf)
            print(f"  POST /accounts/logout/ -> {status}; cookies now {sorted(cookies(context))}")

        browser.close()  # closes the CDP connection only; the Chrome process keeps running


if __name__ == "__main__":
    main(sys.argv[1])
