#!/usr/bin/env python
"""CI smoke test: boot the app against a throwaway database and exercise the paths that
must not break.

Runs with an in-process Flask test client, so it needs no TLS, no Caddy and no chain
access — it is safe in CI and safe on a throwaway database. It creates its own accounts
and removes them again, and asserts that the sum of all balances is unchanged.

    DATABASE_URL=postgresql+psycopg2://btcwallet:ci@localhost:5432/btcwallet \
    MASTER_KEY_FILE=./ci-master.key COOKIE_SECURE=0 BTC_NETWORK=testnet \
    python scripts/ci_smoke.py

Exits non-zero on any failure.
"""

import os
import re
import sys

PASSED, FAILED = [], []


def check(label, cond, detail=""):
    (PASSED if cond else FAILED).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    return bool(cond)


def csrf(html):
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    return m.group(1) if m else ""


def main():
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

    if not os.environ.get("MASTER_KEY_FILE") or not os.path.exists(
            os.environ["MASTER_KEY_FILE"]):
        print("MASTER_KEY_FILE must point at a writable key file (the CI job creates one)")
        return 2

    from app import create_app
    from app.extensions import db
    from app.models import User
    from app.security import hash_password

    app = create_app()
    client = app.test_client()

    def total_balances():
        with app.app_context():
            return sum(int(u.balance_sat or 0) for u in db.session.query(User).all())

    before = total_balances()
    print(f"CI SMOKE — network={os.environ.get('BTC_NETWORK')}")
    print(f"balances before: {before} sat\n")

    print("1. Pages render")
    for path, expect in (("/health", 200), ("/", 200), ("/login", 200), ("/signup", 200)):
        r = client.get(path)
        check(f"GET {path} → {expect}", r.status_code == expect, f"got {r.status_code}")
    check("unknown path is a 404 page, not a crash", client.get("/nope").status_code == 404)

    print("\n2. Signup → wallet (username + password only, no email)")
    page = client.get("/signup")
    r = client.post("/signup", data={
        "csrf_token": csrf(page.text), "username": "ci_alice",
        "password": "Ci-Smoke-Pass-19!", "password2": "Ci-Smoke-Pass-19!", "agree": "1",
    })
    check("signup redirects", r.status_code == 302, f"got {r.status_code}")
    r = client.get("/wallet")
    check("wallet renders after signup",
          r.status_code == 200 and "Available balance" in r.text, f"got {r.status_code}")
    r = client.get("/receive")
    check("receive page offers an address",
          r.status_code == 200 and re.search(r"(tb1|bc1)[a-z0-9]{20,}", r.text) is not None)

    with app.app_context():
        alice_id = db.session.query(User).filter(User.username == "ci_alice").one().id

    print("\n3. An operator requirement gates the account (and is satisfiable)")
    with app.app_context():
        row = db.session.get(User, alice_id)
        row.require_2fa = True
        db.session.commit()
    r = client.get("/wallet", follow_redirects=False)
    check("gated wallet request redirects to 2FA setup",
          r.status_code == 302 and r.headers.get("Location", "").endswith("/security/2fa"),
          f"{r.status_code} {r.headers.get('Location')}")
    r = client.get("/send", follow_redirects=False)
    check("send is gated too", r.status_code == 302, f"got {r.status_code}")
    r = client.get("/security/2fa")
    check("the gate leaves the enrolment page reachable",
          r.status_code == 200 and "Setup key" in r.text, f"got {r.status_code}")

    print("\n4. The admin panel works, and its controls land")
    with app.app_context():
        admin = User(username="ci_admin", role="admin", status="active", balance_sat=0,
                     negative_balance=False, next_address_index=0, session_version=1,
                     totp_enabled=False)
        admin.password_hash = hash_password("Ci-Admin-Pass-77!")
        db.session.add(admin)
        db.session.commit()
        admin_id = admin.id
        # start the control test from a clean state
        db.session.get(User, alice_id).require_2fa = False
        db.session.commit()

    client = app.test_client()
    page = client.get("/login")
    r = client.post("/login", data={"csrf_token": csrf(page.text), "username": "ci_admin",
                                    "password": "Ci-Admin-Pass-77!"})
    check("admin signs in without 2FA (never forced)", r.status_code == 302,
          f"got {r.status_code}")
    r = client.get("/admin/")
    check("admin dashboard renders (holdings + gate counters)",
          r.status_code == 200 and "Overview" in r.text
          and "Account gates" in r.text, f"got {r.status_code}")
    r = client.get(f"/admin/users/{alice_id}")
    check("account page renders the Security & access card",
          r.status_code == 200 and "Security &amp; access" in r.text, f"got {r.status_code}")
    check("card offers the gate controls",
          "Require 2FA" in r.text and "Require a new password" in r.text)

    r = client.post(f"/admin/users/{alice_id}/security",
                    data={"csrf_token": csrf(client.get(f"/admin/users/{alice_id}").text),
                          "action": "require_2fa_on"}, follow_redirects=True)
    with app.app_context():
        gated = db.session.get(User, alice_id).require_2fa
    check("unconfirmed click changes nothing and says so",
          r.status_code == 200 and "nothing has changed yet" in r.text and gated is False)

    r = client.post(f"/admin/users/{alice_id}/security",
                    data={"csrf_token": csrf(client.get(f"/admin/users/{alice_id}").text),
                          "action": "require_2fa_on", "sudo_password": "Ci-Admin-Pass-77!"},
                    follow_redirects=True)
    with app.app_context():
        gated = db.session.get(User, alice_id).require_2fa
    check("inline confirmation saves the requirement", gated is True,
          f"status {r.status_code}")
    r = client.post(f"/admin/users/{admin_id}/security",
                    data={"csrf_token": csrf(client.get(f"/admin/users/{admin_id}").text),
                          "action": "require_2fa_on"}, follow_redirects=True)
    with app.app_context():
        admin_gated = db.session.get(User, admin_id).require_2fa
    check("administrators are refused the gate (no self-lockout)", admin_gated is False)

    print("\n5. Cleanup")
    with app.app_context():
        for uid in (admin_id, alice_id):
            row = db.session.get(User, uid)
            if row is not None:
                db.session.delete(row)
        db.session.commit()
        left = db.session.query(User).filter(
            User.username.in_(("ci_alice", "ci_admin"))).count()
    after = total_balances()
    check("test accounts removed", left == 0)
    check("total balances unchanged by this run", before == after, f"{before} -> {after}")

    print("\n" + "=" * 58)
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    for f in FAILED:
        print(f"  - {f}")
    print("=" * 58)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
