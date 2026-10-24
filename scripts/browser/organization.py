"""
Browser walkthrough of the hosted organization pages (/create-organization, /organization) and the
<CreateOrganization/> and <OrganizationProfile/> components they render.
Needs the service on :3000 (built, so strict CSP applies), Python Playwright, and a publishable key as argv[1]:
  PK=$(npx tsx scripts/browser/seed-pk.ts | sed -n 's/^PK=//p'); python3 scripts/browser/organization.py $PK /tmp
"""
import sys, time, re
from playwright.sync_api import sync_playwright
PK = sys.argv[1]
S = sys.argv[2] if len(sys.argv) > 2 else "/tmp"
A = "http://localhost:3000"
t = int(time.time())
email, pw = f"orgui.{t}@example.com", "a long enough password"
errors = []
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1000, "height": 900})
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.on("console", lambda m: m.type == "error" and errors.append(m.text))
    pg.goto(f"{A}/organization?pk={PK}")
    pg.wait_for_url(re.compile(r"/sign-in\?"))
    print("1 signed-out visitors are sent to sign-in")
    pg.goto(f"{A}/sign-up?pk={PK}")
    pg.get_by_label("Email").fill(email); pg.get_by_label(re.compile("Password")).fill(pw)
    pg.get_by_role("button", name=re.compile("Create account|Continue|Sign up")).click()
    pg.wait_for_timeout(1500)
    pg.goto(f"{A}/create-organization?pk={PK}")
    pg.get_by_label("Organization name").fill("Acme Rockets")
    pg.screenshot(path=f"{S}/org_create.png")
    pg.get_by_role("button", name="Create organization").click()
    pg.wait_for_url(re.compile(r"/organization\?"))
    pg.get_by_role("heading", name="Acme Rockets").first.wait_for()
    print("2 <CreateOrganization/> created the organization and moved on to the profile")
    for tab in ["Members", "Invitations", "Domains", "Settings"]:
        pg.get_by_role("tab", name=tab).wait_for()
    pg.get_by_text(email).wait_for(); pg.get_by_text("(you)").wait_for()
    print("3 admin sees all four tabs and the member list")
    pg.screenshot(path=f"{S}/org_members.png")
    pg.get_by_role("tab", name="Invitations").click()
    pg.get_by_label("Email to invite").fill(f"friend.{t}@example.com"); pg.get_by_role("button", name="Invite").click()
    pg.get_by_text(f"Invitation sent to friend.{t}@example.com").wait_for()
    pg.get_by_text("No pending invitations.").wait_for(state="detached")
    print("4 invitation sent and listed")
    pg.get_by_role("tab", name="Domains").click()
    pg.get_by_label("Domain", exact=True).fill(f"acme-{t}.example.org"); pg.get_by_role("button", name="Add").click()
    pg.get_by_text(f"_daywalker.acme-{t}.example.org").wait_for()
    pg.get_by_role("button", name="Check DNS record").click()
    pg.get_by_role("alert").wait_for()
    pg.screenshot(path=f"{S}/org_domains.png")
    print("5 domain added with DNS instructions; unverified check shows an error")
    pg.get_by_role("tab", name="Settings").click()
    pg.get_by_label("Organization name").fill("Acme Rockets Ltd"); pg.get_by_role("button", name="Save").click()
    pg.get_by_text("Name saved").wait_for()
    pg.get_by_role("heading", name="Acme Rockets Ltd").first.wait_for()
    print("6 settings: renamed")
    pg.get_by_role("button", name="Delete organization").click()
    pg.get_by_role("button", name="Yes, delete it for everyone").click()
    pg.wait_for_url(re.compile(r"/create-organization\?"))
    pg.get_by_label("Organization name").wait_for()
    print("7 deleted; sent to the create page")
    pg.goto(f"{A}/organization?pk={PK}")
    pg.get_by_text("You are not a member of this organization.").wait_for()
    print("8 profile with no organization says so")
    b.close()
bad = [e for e in errors if "favicon" not in e and "401" not in e and "Failed to load resource" not in e]
print("page errors:", bad or "none")
sys.exit(1 if bad else 0)
