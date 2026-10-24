"""
Browser walkthrough of passkey-first sign-up and conditional UI on the hosted pages, using Chrome's virtual
authenticator. Needs the service on :3000 (MAIL_TRANSPORT=dev) and Python Playwright:
  python3 scripts/browser/passkey-signup.py [screenshot-dir]
"""
import subprocess, sys, time, re
from playwright.sync_api import sync_playwright
S = sys.argv[1] if len(sys.argv) > 1 else "/tmp"
A = "http://localhost:3000"
def run(*a):
    return subprocess.run(["npx", "tsx", *a], capture_output=True, text=True, cwd="/home/claude/daywalker-auth").stdout
PK = re.search(r"PK=(\S+)", run("scripts/browser/seed-pk.ts")).group(1)
run("scripts/browser/helper.ts", "enable-passkey-signup", PK)
def code_for(email):
    for _ in range(20):
        m = re.search(r"CODE=(\d*)", run("scripts/browser/helper.ts", "mail", email))
        if m and m.group(1): return m.group(1)
        time.sleep(0.5)
    raise Exception("no code")
email = f"pkb.{int(time.time())}@example.com"
errors = []
with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 900, "height": 900})
    pg = ctx.new_page()
    pg.on("pageerror", lambda e: errors.append(str(e)))
    cdp = ctx.new_cdp_session(pg)
    cdp.send("WebAuthn.enable")
    auth_id = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {"protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
    pg.add_init_script("""
      
      const get = navigator.credentials.get.bind(navigator.credentials);
      navigator.credentials.get = (o) => { sessionStorage.setItem('gets', (sessionStorage.getItem('gets') || '') + ',' + (o && o.mediation || 'none')); return get(o); };
    """)
    pg.goto(f"{A}/sign-up?pk={PK}")
    pg.get_by_role("button", name="Sign up with a passkey instead").click()
    pg.get_by_label("First name").fill("Cora"); pg.get_by_label("Last name").fill("Mpo")
    pg.get_by_label("Email").fill(email)
    pg.screenshot(path=f"{S}/pks_form.png")
    pg.get_by_role("button", name="Email me a code").click()
    pg.get_by_text("Check your email").wait_for(); print("1 code requested")
    pg.get_by_label("Code").fill(code_for(email))
    pg.get_by_role("button", name="Verify and create passkey").click()
    pg.get_by_text("You're all set").wait_for(timeout=15000); print("2 account created with a passkey, signed in")
    creds = cdp.send("WebAuthn.getCredentials", {"authenticatorId": auth_id})["credentials"]
    assert len(creds) == 1 and creds[0]["isResidentCredential"], creds
    pg.screenshot(path=f"{S}/pks_done.png")
    # Signed out, the sign-in page arms conditional UI. The virtual authenticator answers it by itself,
    # standing in for the person picking their passkey from the email field's autofill list.
    ctx.clear_cookies()
    pg.goto(f"{A}/sign-in?pk={PK}")
    pg.get_by_text("You're signed in").wait_for(timeout=15000)
    pg.wait_for_load_state(); gets = pg.evaluate("sessionStorage.getItem('gets') || ''")
    print("3 conditional UI signed in with no click; credentials.get mediation:", gets)
    assert "conditional" in gets, gets
    pg.screenshot(path=f"{S}/pks_signin.png")
    # With conditional UI unavailable the field keeps its plain autocomplete and the button still works.
    ctx.clear_cookies()
    pg.add_init_script("window.PublicKeyCredential.isConditionalMediationAvailable = async () => false;")
    pg.goto(f"{A}/sign-in?pk={PK}")
    pg.get_by_label("Email").wait_for()
    assert pg.get_by_label("Email").get_attribute("autocomplete") == "email"
    pg.get_by_role("button", name="Sign in with a passkey").click()
    pg.get_by_text("You're signed in").wait_for(timeout=15000); print("4 without conditional UI the button still signs in")
    b.close()
print("page errors:", errors or "none")
sys.exit(1 if errors else 0)
