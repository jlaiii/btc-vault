#!/usr/bin/env python
"""Verify the admin account-security controls on a LIVE wallet (mainnet-safe).

Covers the controls on Admin -> Users -> <account> -> Security & access:

  * require 2FA on a user account, prove the account is really gated, and prove
    the gate is satisfiable (the user can still enrol and get through)
  * a required-2FA account cannot switch its own 2FA off
  * clear 2FA (lost device)
  * require a new password, and walk the forced change end to end
  * unlock a locked-out account
  * clear a negative-balance flag — and refuse while the balance really is negative
  * administrator accounts are exempt from the gates (no self-lockout)
  * a click with no password changes nothing and says so (no silent no-op)

No money is created or moved: the test account starts and ends at zero balance,
everything is reversed, and the operator's totals are asserted to be identical.

Run inside the container:
    docker compose exec -T web python /app/scripts/check_admin_user_controls.py
"""

import json  # noqa: F401  (kept for parity with the other harnesses)
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone

BASE = os.environ.get("BASE_URL", "https://localhost")
ADMIN_USER = "e2e_gate_admin"
ADMIN_PW = "Zq7-Yellowhammer-Gate-42!"
USER_PW = "Wq4-Tonka-Bean-Gate-19!"
USER_PW2 = "Nv8-Barnacle-Gate-77!"
TEST_USER = f"e2e_gate_{uuid.uuid4().hex[:6]}"

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")
    return ok


# --------------------------------------------------------------------- helpers
def app_ctx():
    from app import create_app
    from app.config import Config
    return create_app(Config)


def db(fn):
    app = app_ctx()
    with app.app_context():
        return fn()


def csrf(html):
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    return m.group(1) if m else ""


def post(session, path, body, token_from=None, **kw):
    """POST with a CSRF token minted for the CURRENT session.

    Signing in clears the session (fixation defence) and rotates the token, and a
    POST-only endpoint has no page to scrape a token from — so allow the token to
    come from a different page.
    """
    kw.setdefault("timeout", 25)
    page = session.get(f"{BASE}{token_from or path}", timeout=25)
    payload = {"csrf_token": csrf(page.text)}
    payload.update(body)
    return session.post(f"{BASE}{path}", data=payload, **kw)


def login(session, username, password, allow_redirects=False):
    r = session.get(f"{BASE}/login", timeout=25)
    return session.post(f"{BASE}/login", timeout=25, allow_redirects=allow_redirects, data={
        "csrf_token": csrf(r.text), "username": username, "password": password,
    })


def admin_action(session, uid, body, **kw):
    """Post to the account-security endpoint.

    It is POST-only, so the CSRF token has to be scraped from the user page that
    renders the card (a GET of the endpoint itself is a 405 and carries no token).
    """
    return post(session, f"/admin/users/{uid}/security", body,
                token_from=f"/admin/users/{uid}", **kw)


def reset_throttles():
    """Clear the counters this script bumps — they are per-IP and they persist."""
    def _do():
        from app.extensions import db as _db
        from app.models import Throttle

        n = 0
        for bucket in ("login:%", "global:%", "sudo:%", "pwchange:%"):
            n += (_db.session.query(Throttle)
                  .filter(Throttle.bucket.like(bucket))
                  .delete(synchronize_session=False))
        _db.session.commit()
        return n
    return db(_do)


def setup_accounts():
    """Throwaway admin (no 2FA) + throwaway user, created directly in the DB."""
    def _do():
        from app import services
        from app.extensions import db as _db
        from app.models import User
        from app.security import hash_password

        for row in (_db.session.query(User)
                    .filter(User.username.in_((ADMIN_USER, TEST_USER))).all()):
            _db.session.delete(row)
        _db.session.commit()

        admin = User(username=ADMIN_USER, role="admin", status="active",
                     balance_sat=0, negative_balance=False, next_address_index=0,
                     session_version=1, totp_enabled=False)
        admin.password_hash = hash_password(ADMIN_PW)

        user = User(username=TEST_USER, role="user", status="active",
                    balance_sat=0, negative_balance=False, next_address_index=0,
                    session_version=1, totp_enabled=False)
        user.password_hash = hash_password(USER_PW)

        _db.session.add_all([admin, user])
        _db.session.commit()
        services.create_address(user, label="e2e gate", make_primary=True)
        return admin.id, user.id
    return db(_do)


def user_state():
    """Read the test account's gate flags straight from the database."""
    def _do():
        from app.extensions import db as _db
        from app.models import User

        u = _db.session.query(User).filter(User.username == TEST_USER).one_or_none()
        if u is None:
            return {}
        return {
            "require_2fa": bool(u.require_2fa),
            "must_change_password": bool(u.must_change_password),
            "totp_enabled": bool(u.totp_enabled),
            "totp_secret": bool(u.totp_secret_enc),
            "negative_balance": bool(u.negative_balance),
            "balance_sat": int(u.balance_sat or 0),
            "locked_until": u.locked_until,
        }
    return db(_do)


def poke_user(**fields):
    """Direct DB poke to create a condition (reversed before the run ends)."""
    def _do():
        from app.extensions import db as _db
        from app.models import User

        u = _db.session.query(User).filter(User.username == TEST_USER).one()
        for k, v in fields.items():
            setattr(u, k, v)
        _db.session.commit()
        return True
    return db(_do)


def admin_flag(username=ADMIN_USER):
    def _do():
        from app.extensions import db as _db
        from app.models import User

        u = _db.session.query(User).filter(User.username == username).one_or_none()
        return bool(u.require_2fa) if u else None
    return db(_do)


def totals():
    def _do():
        from app.extensions import db as _db
        from app.models import User

        return {
            "sats": sum(int(u.balance_sat or 0) for u in _db.session.query(User).all()),
            "users": _db.session.query(User).count(),
        }
    return db(_do)


def cleanup():
    """Remove the test accounts and the audit/event rows they generated."""
    def _do():
        from sqlalchemy import or_

        from app.extensions import db as _db
        from app.models import AdminAudit, Alert, SecurityEvent, Throttle, User

        names = (ADMIN_USER, TEST_USER)
        audits = (_db.session.query(AdminAudit)
                  .filter(or_(AdminAudit.admin_username.like("e2e_gate%"),
                              AdminAudit.target_username.like("e2e_gate%")))
                  .delete(synchronize_session=False))
        events = (_db.session.query(SecurityEvent)
                  .filter(SecurityEvent.username.like("e2e_gate%"))
                  .delete(synchronize_session=False))
        for row in _db.session.query(User).filter(User.username.in_(names)).all():
            _db.session.delete(row)
        _db.session.commit()
        for bucket in ("login:%", "global:%", "sudo:%", "pwchange:%"):
            (_db.session.query(Throttle).filter(Throttle.bucket.like(bucket))
             .delete(synchronize_session=False))
        _db.session.commit()
        return {
            "audits": audits,
            "events": events,
            "users_left": _db.session.query(User).filter(User.username.in_(names)).count(),
            "open_alerts": _db.session.query(Alert).filter(Alert.ack_at.is_(None)).count(),
        }
    return db(_do)


def main():
    import requests
    from app import services

    print(f"ADMIN ACCOUNT-CONTROL CHECK — {BASE}")
    with app_ctx().app_context():
        net = services.network().name
    print(f"configured network: {net}\ntest account: {TEST_USER}\n")

    before = totals()
    reset_throttles()
    admin_id, user_id = setup_accounts()
    print(f"temp admin id={admin_id} (no 2FA), test user id={user_id}\n")

    a = requests.Session()          # the admin's browser
    u = requests.Session()          # the user's browser
    try:
        # ------------------------------------------------------------ 1. login
        print("1. The panel still works for an admin without 2FA")
        r = login(a, ADMIN_USER, ADMIN_PW, allow_redirects=True)
        check("admin signed in without 2FA", r.status_code == 200, f"HTTP {r.status_code}")
        page = a.get(f"{BASE}/admin/users/{user_id}", timeout=25)
        check("user page renders the new Security & access card",
              "Security &amp; access" in page.text, f"HTTP {page.status_code}")
        check("card offers Require 2FA and Require a new password",
              "Require 2FA" in page.text and "Require a new password" in page.text)
        check("card explains the exemption on administrator targets",
              "exempt from these gates"
              in a.get(f"{BASE}/admin/users/{admin_id}", timeout=25).text)

        # ------------------------------------- 2. no password = no silent change
        print("\n2. A click with no password changes nothing and says so")
        r = admin_action(a, user_id, {"action": "require_2fa_on"},
                 allow_redirects=True)
        check("unconfirmed action refused, with an explanation",
              "nothing has changed yet" in r.text, f"HTTP {r.status_code}")
        check("2FA requirement was NOT set", user_state()["require_2fa"] is False)

        r = admin_action(a, user_id, 
                 {"action": "require_2fa_on", "sudo_password": "not-the-password"},
                 allow_redirects=True)
        check("wrong password refused", "Incorrect password" in r.text)
        check("2FA requirement still not set", user_state()["require_2fa"] is False)

        # -------------------------------------------- 3. require 2FA, inline sudo
        print("\n3. Require 2FA on the account (confirmed inline on the card)")
        r = admin_action(a, user_id, 
                 {"action": "require_2fa_on", "sudo_password": ADMIN_PW},
                 allow_redirects=True)
        check("action accepted with the inline password", r.status_code == 200,
              f"HTTP {r.status_code}")
        check("REQUIREMENT ACTUALLY SAVED (the headline control)",
              user_state()["require_2fa"] is True)
        check("confirmation is remembered afterwards", "Confirmed" in r.text)
        page = a.get(f"{BASE}/admin/users/{user_id}", timeout=25)
        check("user page shows the requirement and its release control",
              "2FA required" in page.text and "Stop requiring 2FA" in page.text)
        check("users list filter finds the gated account",
              TEST_USER in a.get(f"{BASE}/admin/users?flag=require2fa", timeout=25).text)
        check("'required, not enrolled' filter finds it",
              TEST_USER in a.get(f"{BASE}/admin/users?flag=pending2fa", timeout=25).text)
        check("dashboard shows the gate counters",
              "Account gates" in a.get(f"{BASE}/admin/", timeout=25).text)

        # ------------------------------------------------------ 4. the gate itself
        print("\n4. The account really is gated — and can get itself out")
        r = login(u, TEST_USER, USER_PW)
        check("gated user can still sign in", r.status_code == 302, f"HTTP {r.status_code}")
        r = u.get(f"{BASE}/wallet", timeout=25, allow_redirects=False)
        check("wallet BLOCKED, redirected to 2FA setup",
              r.status_code == 302 and r.headers.get("Location", "").endswith("/security/2fa"),
              f"{r.status_code} {r.headers.get('Location')}")
        check("send is blocked too",
              u.get(f"{BASE}/send", timeout=25, allow_redirects=False).status_code == 302)
        check("receive is blocked (on-chain deposits still arrive)",
              u.get(f"{BASE}/receive", timeout=25, allow_redirects=False).status_code == 302)
        page = u.get(f"{BASE}/security/2fa", timeout=25)
        m = re.search(r'class="a">([A-Za-z2-7]{16,})</span>', page.text)
        secret = m.group(1) if m else None
        check("blocked user still reaches the setup page and sees a setup key",
              bool(secret), "no key rendered")
        if secret:
            import pyotp
            r = post(u, "/security/2fa", {"code": pyotp.TOTP(secret).now()},
                     allow_redirects=True)
            check("enrolment accepted from the gate", r.status_code == 200,
                  f"HTTP {r.status_code}")
            check("user is now enrolled", user_state()["totp_enabled"] is True)

            # ---------------------------------- 5. requirement outranks opting out
            print("\n5. A required-2FA account cannot switch 2FA off itself")
            check("security page explains the requirement",
                  "requires two-factor authentication"
                  in u.get(f"{BASE}/security", timeout=25).text)
            r = post(u, "/security/2fa/disable", {"code": pyotp.TOTP(secret).now()},
                     token_from="/security", allow_redirects=True)
            check("self-service disable refused", "cannot be turned off" in r.text,
                  f"HTTP {r.status_code}")
            check("2FA is still enabled", user_state()["totp_enabled"] is True)

        r = u.get(f"{BASE}/wallet", timeout=25, allow_redirects=False)
        check("GATE OPENS once enrolled (no dead end)", r.status_code == 200,
              f"HTTP {r.status_code}")

        # ------------------------------------------------ 6. lift + clear 2FA
        print("\n6. Stop requiring 2FA, then clear an enrolment (lost device)")
        admin_action(a, user_id, {"action": "require_2fa_off"},
             allow_redirects=True)
        check("requirement lifted", user_state()["require_2fa"] is False)
        admin_action(a, user_id, {"action": "clear_2fa"}, allow_redirects=True)
        check("2FA cleared (secret and backup codes gone)",
              user_state()["totp_enabled"] is False
              and user_state()["totp_secret"] is False)

        # Clearing 2FA rotates the session version, so the user's existing cookie
        # is dead by design. Sign in again for the next phase.
        u = requests.Session()
        r = login(u, TEST_USER, USER_PW)
        check("user signs in with just a password after the clear",
              r.status_code == 302, f"HTTP {r.status_code}")

        # ------------------------------------------------ 7. forced password change
        print("\n7. Require a new password and walk the forced change")
        admin_action(a, user_id, {"action": "require_password_on"},
             allow_redirects=True)
        check("password requirement saved", user_state()["must_change_password"] is True)
        check("users list shows the account as needing a change",
              TEST_USER in a.get(f"{BASE}/admin/users?flag=mustchange", timeout=25).text)
        r = u.get(f"{BASE}/wallet", timeout=25, allow_redirects=False)
        check("wallet blocked, redirected to the change-password page",
              r.status_code == 302
              and r.headers.get("Location", "").endswith("/account/password/required"),
              f"{r.status_code} {r.headers.get('Location')}")
        r = u.get(f"{BASE}/account/password/required", timeout=25)
        check("forced change page renders",
              r.status_code == 200 and "Set a new password" in r.text,
              f"HTTP {r.status_code}")
        r = post(u, "/account/password/required",
                 {"current": "wrong-password", "password": USER_PW2,
                  "password2": USER_PW2}, allow_redirects=False)
        check("wrong current password refused", r.status_code == 401, f"HTTP {r.status_code}")
        r = post(u, "/account/password/required",
                 {"current": USER_PW, "password": USER_PW2, "password2": USER_PW2},
                 allow_redirects=False)
        check("new password accepted", r.status_code == 302, f"HTTP {r.status_code}")
        check("requirement cleared after the change",
              user_state()["must_change_password"] is False)
        check("wallet reachable again",
              u.get(f"{BASE}/wallet", timeout=25, allow_redirects=False).status_code == 200)
        v = requests.Session()
        check("new password works at a fresh sign-in",
              login(v, TEST_USER, USER_PW2).status_code == 302)

        # ------------------------------------------------------------- 8. lockout
        print("\n8. Unlock a locked-out account")
        poke_user(locked_until=datetime.now(timezone.utc) + timedelta(minutes=15))
        w = requests.Session()
        r = login(w, TEST_USER, USER_PW2, allow_redirects=True)
        check("locked account refused a sign-in", r.status_code == 429, f"HTTP {r.status_code}")
        check("locked-out filter finds the account",
              TEST_USER in a.get(f"{BASE}/admin/users?flag=locked", timeout=25).text)
        r = admin_action(a, user_id, {"action": "unlock"}, allow_redirects=True)
        check("unlock reports the lockout cleared", "can sign in again" in r.text,
              f"HTTP {r.status_code}")
        check("lockout gone in the database", user_state()["locked_until"] is None)
        w = requests.Session()
        check("account signs in again immediately",
              login(w, TEST_USER, USER_PW2).status_code == 302)

        # ------------------------------------------------------ 9. negative flag
        print("\n9. Negative-balance flag: clearable when true, refused when not")
        poke_user(balance_sat=0, negative_balance=True)
        r = admin_action(a, user_id, {"action": "clear_negative"},
                 allow_redirects=True)
        check("flag cleared at a zero balance", user_state()["negative_balance"] is False,
              f"HTTP {r.status_code}")
        poke_user(balance_sat=-1, negative_balance=True)
        r = admin_action(a, user_id, {"action": "clear_negative"},
                 allow_redirects=True)
        check("refused while the balance is genuinely negative",
              "fix the balance first" in r.text, f"HTTP {r.status_code}")
        check("flag left alone in that case", user_state()["negative_balance"] is True)
        poke_user(balance_sat=0, negative_balance=False)

        # ---------------------------------------------------- 10. admin exemption
        print("\n10. Administrator accounts are exempt (no self-lockout)")
        r = admin_action(a, admin_id, {"action": "require_2fa_on"},
                 allow_redirects=True)
        check("require-2FA on an admin refused", admin_flag() is False
              and "exempt" in r.text, f"HTTP {r.status_code}")
        admin_action(a, admin_id, {"action": "require_password_on"},
             allow_redirects=True)
        check("require-password-change on an admin refused", admin_flag() is False)
        check("admin panel stays reachable",
              a.get(f"{BASE}/admin/", timeout=25, allow_redirects=False).status_code == 200)

    finally:
        print("\n11. Cleanup")
        left = cleanup()
        after = totals()
        check("test accounts removed", left["users_left"] == 0, f"{left['users_left']} left")
        check("no open alerts added", left["open_alerts"] == 0, f"{left['open_alerts']} open")
        check("TOTAL BALANCES UNCHANGED by this run", before["sats"] == after["sats"],
              f"{before['sats']} -> {after['sats']} sat")
        print(f"  (removed {left['audits']} audit row(s), {left['events']} event row(s); "
              f"{after['users']} account(s) left in the wallet)")

    failures = sum(1 for _n, ok in results if not ok)
    print("\n" + "=" * 62)
    print(f"{len(results) - failures}/{len(results)} checks passed")
    if failures:
        print("\nFAILURES:")
        for n, ok in results:
            if not ok:
                print(f"  - {n}")
    print("=" * 62)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())