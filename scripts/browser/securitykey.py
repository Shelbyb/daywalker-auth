"""
Browser walkthrough of security keys on the hosted pages, using Chromium's virtual FIDO2 authenticator.
Needs the service on :3000, Python Playwright, and the seed instance's publishable key as argv[1].
  python3 scripts/browser/securitykey.py pk_test_...
"""
import sys, time, re
from playwright.sync_api import sync_playwright
PK = sys.argv[1]
S = sys.argv[2] if len(sys.argv) > 2 else "/tmp"
A = "http://localhost:3000"
email = f"key.{int(time.time())}@example.com"
pw = "a long enough password"
errors = []
with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 900, "height": 900})
    pg = ctx.new_page()
    pg.on("pageerror", lambda e: errors.append(str(e)))
    cdp = ctx.new_cdp_session(pg)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {"protocol": "ctap2", "transport": "usb", "hasResidentKey": False, "hasUserVerification": False, "isUserVerified": False, "automaticPresenceSimulation": True}})
    pg.goto(f"{A}/sign-up?pk={PK}")
    pg.get_by_label("Email").fill(email); pg.get_by_label(re.compile("Password")).fill(pw)
    pg.get_by_role("button", name=re.compile("Create account|Continue|Sign up")).click()
    pg.wait_for_timeout(1500)
    pg.goto(f"{A}/account?pk={PK}")
    pg.get_by_role("button", name="Add a security key").wait_for(); print("1 account page offers 'Add a security key'")
    pg.screenshot(path=f"{S}/sk_account.png")
    pg.get_by_role("button", name="Add a security key").click()
    pg.get_by_label("Name", exact=True).fill("Virtual YubiKey")
    pg.get_by_role("button", name="Continue").click()
    pg.get_by_text("Two-step verification is on.").wait_for(); print("2 key registered through the browser, backup codes shown")
    codes = pg.locator("ul.grid li").all_inner_texts()
    assert len(codes) == 10, codes
    pg.get_by_role("button", name="I've saved them").click()
    pg.get_by_text("Virtual YubiKey").wait_for(); print("3 key is listed on the account page")
    pg.screenshot(path=f"{S}/sk_listed.png")
    # sign out, sign back in with the key
    ctx.clear_cookies()
    pg.goto(f"{A}/sign-in?pk={PK}")
    pg.get_by_label("Email").fill(email); pg.get_by_label(re.compile("Password")).fill(pw)
    pg.get_by_role("button", name="Continue").click()
    pg.get_by_role("button", name="Use a security key").wait_for(); print("4 second step offers 'Use a security key'")
    pg.screenshot(path=f"{S}/sk_second.png")
    pg.get_by_role("button", name="Use a security key").click()
    pg.wait_for_timeout(2000)
    body = pg.inner_text("body")
    assert "Two-step verification" not in body or "signed in" in body.lower() or "welcome" in body.lower(), body[:300]
    print("5 signed in with the key:", body.strip().replace("\n", " ")[:80])
    pg.screenshot(path=f"{S}/sk_done.png")
    # remove it with a backup code
    pg.goto(f"{A}/account?pk={PK}")
    pg.get_by_role("button", name="Remove", exact=True).first.click()
    pg.get_by_label("Code").fill(codes[0]); pg.get_by_role("button", name="Continue").click()
    pg.get_by_text("Security key removed.").wait_for(); print("6 key removed with a backup code")
    b.close()
print("page errors:", errors or "none")
sys.exit(1 if errors else 0)
