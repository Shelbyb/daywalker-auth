"""
Browser walkthrough of the drop-in React components in examples/nextjs (/components).
Needs the service on :3000 and the example on :3001, Python Playwright, and the example keys in the env:
  export $(grep -E "^(DAYWALKER_SECRET_KEY|NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY)=" examples/nextjs/.env.local | xargs)
  python3 scripts/browser/components.py
"""
import subprocess, sys, time, re
from playwright.sync_api import sync_playwright
S = sys.argv[1] if len(sys.argv) > 1 else "/tmp"
def helper(*a):
    out = subprocess.run(["npx", "tsx", "scripts/browser/helper.ts", *a], capture_output=True, text=True, cwd="/home/claude/daywalker-auth").stdout
    m = re.search(r"CODE=(\d*)", out)
    return m.group(1) if m else out.strip()
def code_for(email):
    for _ in range(20):
        c = helper("mail", email)
        if c: return c
        time.sleep(0.5)
    raise Exception("no code")
helper("enable")
email = f"cmp.{int(time.time())}@example.com"
errors = []
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1100, "height": 900})
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.on("console", lambda m: m.type == "error" and errors.append(m.text))
    A = "http://localhost:3001"
    pg.goto(A + "/components"); pg.get_by_test_id("signed-out").wait_for(); print("1 signed out page")
    pg.goto(A + "/components/sign-up")
    pg.get_by_label("First name").fill("Cora"); pg.get_by_label("Last name").fill("Mpo")
    pg.get_by_label("Email").fill(email); pg.get_by_label(re.compile("Password")).fill("a long enough password")
    pg.screenshot(path=f"{S}/cmp_signup.png")
    pg.get_by_role("button", name="Create account").click()
    pg.get_by_text("Verify your email").wait_for()
    pg.get_by_label("Code").fill(code_for(email)); pg.get_by_role("button", name="Verify").click()
    pg.wait_for_url(A + "/components"); pg.get_by_test_id("signed-in").wait_for(); print("2 <SignUp/> with email verification works")
    pg.get_by_role("button", name="Personal account").click()
    pg.get_by_role("button", name="+ Create organization").click()
    pg.get_by_label("Organization name").fill("Acme Rockets"); pg.get_by_role("button", name="Create").click()
    pg.get_by_role("button", name="Acme Rockets").wait_for(); print("3 <OrganizationSwitcher/> created and switched to Acme Rockets")
    pg.get_by_role("button", name="Acme Rockets").click()
    pg.get_by_role("menuitemradio", name="Personal account").click()
    pg.get_by_role("button", name="Personal account").wait_for(); print("4 switched back to personal")
    pg.screenshot(path=f"{S}/cmp_signedin.png")
    pg.get_by_role("button", name=re.compile("Account: Cora")).click()
    pg.get_by_role("menuitem", name="Sign out").click()
    pg.wait_for_url(A + "/components/sign-in"); print("5 <UserButton/> sign out")
    pg.get_by_label("Email").fill(email); pg.get_by_label("Password").fill("wrong password!!")
    pg.get_by_role("button", name="Continue").click()
    pg.get_by_role("alert").wait_for(); print("6 wrong password shows an error")
    pg.get_by_label("Password").fill("a long enough password"); pg.get_by_role("button", name="Continue").click()
    pg.wait_for_url(A + "/components"); pg.get_by_test_id("signed-in").wait_for(); print("7 <SignIn/> with password")
    pg.get_by_role("button", name=re.compile("Account: Cora")).click(); pg.get_by_role("menuitem", name="Sign out").click()
    pg.wait_for_url(A + "/components/sign-in")
    pg.get_by_role("button", name="Email me a sign-in code instead").click()
    pg.get_by_label("Email").fill(email); pg.get_by_role("button", name="Email me a code").click()
    pg.get_by_text("Check your email").wait_for()
    pg.get_by_label("Code").fill(code_for(email)); pg.get_by_role("button", name="Sign in").click()
    pg.wait_for_url(A + "/components"); pg.get_by_test_id("signed-in").wait_for(); print("8 <SignIn/> with an email code")
    pg.goto(A + "/components/sign-in"); pg.wait_for_timeout(1000); pg.screenshot(path=f"{S}/cmp_signin.png")
    b.close()
print("errors:", errors or "none")
