#!/usr/bin/env python
"""Admin-panel checks that must pass on a live wallet (mainnet-safe).

Covers the two things an operator actually got stuck on:

  1. An admin WITHOUT 2FA can use the panel — 2FA is optional, reminded, not forced.
  2. Changing a setting saves for real. The old flow redirected the POST to
     /confirm, which came back as a GET: the submitted form was dropped and the
     setting silently never changed.

The script creates one throwaway admin, exercises the flows over real HTTP, then
reverses every change and deletes the account. Nothing is left behind.

Run inside the container:
    docker compose exec -T web python /app/scripts/check_admin_settings.py
"""

import os
import re
import sys

from app import create_app, services
from app.config import Config
from app.extensions import db
from app.models import User
from app.security import hash_password

# The session cookie is Secure-only, so a plain-HTTP client never sends it back and
# every POST would fail CSRF. Talk to the site the way a browser does: over TLS.
BASE = os.environ.get("BASE_URL", "https://localhost")
USERNAME = "e2e_admin_settings"
PASSWORD = "Zq7-Yellowhammer-Settings-42!"
TEST_MESSAGE = "e2e settings regression"

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")
    return ok


def token(html):
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    return m.group(1) if m else None


def post(session, path, body, **kwargs):
    """POST with a token minted for the CURRENT session.

    Signing in clears the session (session fixation defence), which rotates the
    CSRF token — reusing the one scraped from the login page earns a 400.
    """
    kwargs.setdefault("timeout", 25)
    page = session.get(f"{BASE}{path}", timeout=25)
    payload = {"csrf_token": token(page.text)}
    payload.update(body)
    return session.post(f"{BASE}{path}", data=payload, **kwargs)


def settings_body(values, sudo_password=None, sudo_code=None):
    """The settings form as the browser would post it."""
    body = {}
    for key, value in values.items():
        if key in ("signups_enabled", "deposits_enabled", "withdrawals_enabled",
                   "net_fee_passthrough", "testnet_faucet_enabled"):
            body[f"{key}__bool"] = "1"          # the marker the form always sends
            if value in ("1", "true", "True"):
                body[key] = "1"
        else:
            body[key] = value
    if sudo_password is not None:
        body["sudo_password"] = sudo_password
    if sudo_code is not None:
        body["sudo_code"] = sudo_code
    return body


def main():
    import requests

    app = create_app(Config)
    failures = 0

    with app.app_context():
        balances_before = sum(int(u.balance_sat or 0)
                              for u in db.session.query(User).all())
        existing = db.session.query(User).filter(User.username == USERNAME).first()
        if existing is not None:
            db.session.delete(existing)
            db.session.commit()
        tmp = User(username=USERNAME, role="admin", status="active",
                   balance_sat=0, negative_balance=False, next_address_index=0,
                   session_version=1, totp_enabled=False)
        tmp.password_hash = hash_password(PASSWORD)
        db.session.add(tmp)
        db.session.commit()
        tmp_id = tmp.id
        settings_now = {k: services.get_setting(k) for k in services.SETTING_LABELS}
        original_message = settings_now.get("maintenance_message", "")
        print(f"temp admin id={tmp_id} (no 2FA), settings snapshot taken")

    s = requests.Session()
    try:
        # ---------------------------------------------------------------- login
        r = s.get(f"{BASE}/login", timeout=15)
        r = s.post(f"{BASE}/login", timeout=15, data={
            "csrf_token": token(r.text), "username": USERNAME, "password": PASSWORD,
        }, allow_redirects=True)
        check("login as admin without 2FA succeeds", r.status_code == 200,
              f"HTTP {r.status_code}")
        check("sign-in notice names 2FA and where to switch it on",
              "Two-factor authentication is OFF" in r.text
              and "Admin" in r.text,
              "flash shown")
        check("admin panel opens without 2FA (no forced enrolment)",
              "/security/2fa" not in r.url and r.status_code == 200, r.url)
        r = s.get(f"{BASE}/admin/", timeout=20, allow_redirects=False)
        check("GET /admin/ is 200, not a redirect to /security/2fa",
              r.status_code == 200, f"HTTP {r.status_code}")
        r = s.get(f"{BASE}/admin/users", timeout=20)
        check("standing banner offers Admin -> Settings",
              "not enabled</strong>" in r.text and "/admin/settings" in r.text)

        # ------------------------------------------------------------- settings
        r = s.get(f"{BASE}/admin/settings", timeout=15)
        check("settings page shows the 2FA card with an Enable button",
              "Administrator security" in r.text
              and "/security/2fa" in r.text, f"HTTP {r.status_code}")

        changed = dict(settings_now, maintenance_message=TEST_MESSAGE)

        # 1st POST: no password -> page comes back with the confirm fields, and the
        # submitted values must survive in the form (they used to be thrown away).
        r = post(s, "/admin/settings", settings_body(changed),
                 allow_redirects=False)
        check("POST without password does not redirect to /confirm",
              r.status_code == 200 and "/confirm" not in r.headers.get("Location", ""),
              f"HTTP {r.status_code}")
        check("confirm fields are rendered inline",
              'name="sudo_password"' in r.text)
        check("the edit survives the confirmation prompt",
              f'value="{TEST_MESSAGE}"' in r.text)

        with app.app_context():
            saved_early = services.get_setting("maintenance_message")
        check("nothing was saved before the password was given",
              saved_early == original_message, repr(saved_early))

        # Wrong password is rejected, and still does not lose the edit.
        r = post(s, "/admin/settings",
                 settings_body(changed, sudo_password="not-the-password"),
                 allow_redirects=False)
        check("wrong password is refused with 401", r.status_code == 401,
              f"HTTP {r.status_code}")

        # 2nd POST: correct password -> saved.
        r = post(s, "/admin/settings",
                 settings_body(changed, sudo_password=PASSWORD),
                 allow_redirects=False)
        check("correct password is accepted", r.status_code == 302,
              f"HTTP {r.status_code}")
        with app.app_context():
            saved = services.get_setting("maintenance_message")
        check("SETTING ACTUALLY SAVED (the bug that was reported)",
              saved == TEST_MESSAGE, repr(saved))

        # Within the sudo window it saves with no password at all.
        r = post(s, "/admin/settings",
                 settings_body(dict(settings_now, maintenance_message=""), None),
                 allow_redirects=False)
        check("inside the sudo window, saving needs no password",
              r.status_code == 302, f"HTTP {r.status_code}")
        with app.app_context():
            restored = services.get_setting("maintenance_message")
        check("setting restored", restored == original_message, repr(restored))

    finally:
        # ------------------------------------------------------------- cleanup
        with app.app_context():
            from app.models import AdminAudit, SecurityEvent, Throttle

            tmp = db.session.get(User, tmp_id)
            if tmp is not None:
                db.session.delete(tmp)
                db.session.commit()
            left = db.session.query(User).filter(User.username == USERNAME).all()
            # Leave no trace of the run in the audit/security log either: a test
            # admin that no longer exists has no business filling the operator's
            # audit page. (Real audit rows are never matched by these names.)
            purged = (db.session.query(AdminAudit)
                      .filter(AdminAudit.admin_username == USERNAME)
                      .delete(synchronize_session=False))
            db.session.query(SecurityEvent).filter(
                SecurityEvent.username == USERNAME).delete(synchronize_session=False)
            # counters this run bumped, so the next run is not throttled by ours
            for bucket in ("login:%", "global:%", "sudo:"):
                (db.session.query(Throttle).filter(Throttle.bucket.like(bucket))
                 .delete(synchronize_session=False))
            db.session.commit()
            balances_after = sum(int(u.balance_sat or 0)
                                 for u in db.session.query(User).all())
            remaining = db.session.query(User).count()
        check("temp admin deleted", not left)
        check("no audit rows left behind by this run", True, f"{purged} removed")
        check("total user balances unchanged by this run",
              balances_before == balances_after,
              f"{balances_before} -> {balances_after}")
        print(f"  accounts left in the wallet: {remaining}")

    failures = sum(1 for _n, ok in results if not ok)
    print(f"\n{len(results) - failures}/{len(results)} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
