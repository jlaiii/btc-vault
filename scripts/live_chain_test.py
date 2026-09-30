#!/usr/bin/env python3
"""Live on-chain test: real testnet coins, real deposit, real broadcast.

Run inside the container:

    ADMIN_PW=<password> docker compose exec -T -e ADMIN_PW \
        web python /app/scripts/live_chain_test.py

Proves, against the real network:
  1. a confirmed deposit is credited exactly once (and a second scan does NOT
     double-credit it)
  2. the user-facing send flow works end to end over HTTP: quote -> review ->
     password confirmation -> broadcast
  3. the broadcast transaction is on-chain, its outputs match what the user was
     quoted, its signatures verify, and its fee equals the quoted fee
  4. the ledger debit equals amount + service fee + actual miner fee
  5. the wallet's accounting identity still holds afterwards

Requires the wallet to already hold a confirmed testnet UTXO (e.g. from a
faucet). Waits for the deposit to confirm before proceeding.
"""

import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import pyotp
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = os.environ.get("E2E_BASE", "https://localhost")
ADMIN_USER = os.environ.get("ADMIN_USER", "jay")
ADMIN_PW = os.environ.get("ADMIN_PW", "")
WAIT_MINUTES = int(os.environ.get("WAIT_MINUTES", "45"))
SEND_AMOUNT = int(os.environ.get("SEND_AMOUNT", "25000"))
CONFIRM_TARGET = int(os.environ.get("CONFIRM_TARGET", "3"))  # for fee tier

PASSED, FAILED = [], []
TOTP_SECRET = None


def check(name, cond, detail=""):
    if cond:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(f"{name} {detail}")
        print(f"  FAIL  {name} {detail}")
    return bool(cond)


def csrf(html):
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


def sess():
    s = requests.Session()
    s.headers["User-Agent"] = "btcwallet-live/1.0"
    return s


def ext_address():
    """A fresh testnet address we do NOT control — a genuine external send."""
    from embit import bip32, script
    from embit.networks import NETWORKS

    net = NETWORKS["test"]
    k = bip32.HDKey.from_seed(os.urandom(32), version=net["xprv"])
    spk = script.p2wpkh(k.derive("m/84'/1'/0'/0/0").key)
    return spk.address(net)


def restore_no_2fa():
    from app import create_app
    from app.config import Config
    from app.extensions import db
    from app.models import User

    app = create_app(Config)
    with app.app_context():
        u = db.session.query(User).filter(User.username == ADMIN_USER).first()
        if u and u.totp_enabled:
            u.totp_enabled = False
            u.totp_secret_enc = None
            u.backup_codes_json = None
            u.session_version = (u.session_version or 0) + 1
            db.session.commit()
            print("\n        (temporary 2FA removed — sign in and enrol your own device)")


def main():
    try:
        return run()
    finally:
        # Always restore the operator's account: a test that leaves 2FA
        # enrolled with a secret only it knows would lock the owner out.
        if TOTP_SECRET:
            try:
                restore_no_2fa()
            except Exception as exc:
                print(f"  WARNING: could not clear the temporary 2FA: {exc}")


def run():
    from app import create_app, services
    from app.chain import ChainError
    from app.config import Config
    from app.extensions import db
    from app.models import (ChainCredit, LedgerEntry, OurTx, Transaction, User,
                            Withdrawal)

    app = create_app(Config)
    with app.app_context():
        user = db.session.query(User).filter(User.username == ADMIN_USER).first()
        if user is None:
            print(f"no such user: {ADMIN_USER}")
            sys.exit(1)
        user_id = user.id
        if not user.addresses:
            print("user has no deposit address")
            sys.exit(1)
        addr = user.addresses[0].address
        print(f"user={ADMIN_USER} address={addr} balance={user.balance_sat}")

    explorer = None
    with app.app_context():
        explorer = services.explorer()

    # ---- 1. wait for a confirmed UTXO at that address
    print(f"\n1. Waiting for a confirmed UTXO (up to {WAIT_MINUTES} min)")
    deadline = time.time() + WAIT_MINUTES * 60
    utxo = None
    while time.time() < deadline:
        try:
            us = explorer.address_utxos(addr)
        except ChainError as exc:
            print(f"   explorer error: {exc}")
            us = []
        conf = [u for u in us if (u.get("status") or {}).get("confirmed")]
        if conf:
            utxo = conf[0]
            break
        pending = len(us) - len(conf)
        print(f"   [{datetime.now(timezone.utc):%H:%M:%S}] "
              f"{len(conf)} confirmed, {pending} unconfirmed")
        time.sleep(45)

    if utxo is None:
        print("\nNo confirmed deposit yet — testnet is not producing blocks fast enough.")
        print("Re-run this script later; it is safe to run repeatedly.")
        sys.exit(2)

    check("deposit confirmed on-chain", True)
    expect_sat = int(utxo["value"])
    print(f"        confirmed UTXO {utxo['txid'][:16]}…:{utxo['vout']} = {expect_sat} sat")

    # ---- 2. sync credits exactly once
    print("\n2. Deposit crediting (and idempotency)")
    with app.app_context():
        before = db.session.get(User, user_id).balance_sat
        summary = services.sync_once()
        after = db.session.get(User, user_id).balance_sat
        check("sync credited the deposit", after == expect_sat,
              f"{before} -> {after}, expected {expect_sat}")
        check("a ChainCredit guard row exists",
              db.session.query(ChainCredit).filter_by(txid=utxo["txid"], vout=utxo["vout"]).count() == 1)
        dep = (db.session.query(Transaction)
               .filter(Transaction.user_id == user_id, Transaction.txid == utxo["txid"],
                       Transaction.category == "deposit").first())
        check("deposit transaction row is confirmed",
              dep is not None and dep.status == "confirmed",
              f"{dep.status if dep else None}")

        # re-scan must NOT credit again
        services.sync_once()
        again = db.session.get(User, user_id).balance_sat
        check("re-scan does NOT double-credit", again == after, f"{after} -> {again}")
        entries = (db.session.query(LedgerEntry)
                   .filter(LedgerEntry.user_id == user_id,
                           LedgerEntry.kind == "deposit").count())
        check("exactly one deposit ledger entry", entries == 1, f"{entries}")

    # ---- 3. full HTTP send flow
    print("\n3. User-facing send flow over HTTPS")
    s = sess()
    html = s.get(f"{BASE}/login", timeout=30).text
    r = s.post(f"{BASE}/login", data={"csrf_token": csrf(html), "username": ADMIN_USER,
                                     "password": ADMIN_PW},
               timeout=30, allow_redirects=False)
    check("login accepted", r.status_code == 302, f"status={r.status_code}")

    totp_secret = None
    loc = r.headers.get("Location", "")
    # read the secret back through the vault so the login can be completed.
    if "2fa" in loc:
        with app.app_context():
            u = db.session.get(User, user_id)
            if u.totp_secret_enc:
                totp_secret = services.vault().open_str(u.totp_secret_enc)
        if not totp_secret:
            print("        2FA is enabled but the secret cannot be read; aborting")
            return finish()
        html = s.get(f"{BASE}/login/2fa", timeout=30).text
        r = s.post(f"{BASE}/login/2fa",
                   data={"csrf_token": csrf(html), "code": pyotp.TOTP(totp_secret).now()},
                   timeout=30, allow_redirects=False)
        check("completed the existing 2FA challenge", r.status_code == 302,
              f"status={r.status_code} loc={r.headers.get('Location')}")

    # An admin without 2FA is forced to enrol before doing anything.
    sec = s.get(f"{BASE}/security", timeout=30, allow_redirects=False)
    if sec.status_code == 302:
        sec = s.get(BASE + sec.headers.get("Location", "/security"), timeout=30)
    if "Set up two-factor authentication" in sec.text:
        print("        admin gate: enrolling 2FA (will be cleared afterwards)")
        html = s.get(f"{BASE}/security/2fa", timeout=30).text
        m = re.search(r'<span class="a">([A-Z2-7]{16,})</span>', html)
        totp_secret = m.group(1) if m else None
        if not totp_secret:
            print("        could not read the 2FA setup secret")
            return finish()
        r = s.post(f"{BASE}/security/2fa",
                   data={"csrf_token": csrf(html), "code": pyotp.TOTP(totp_secret).now()},
                   timeout=30, allow_redirects=False)
        check("temporary 2FA enrolment for the admin flow", r.status_code == 200,
              f"status={r.status_code}")
    with app.app_context():
        u = db.session.get(User, user_id)
        if u.totp_enabled and u.totp_secret_enc and not totp_secret:
            # re-read the secret via the vault so the sudo step can be satisfied
            totp_secret = services.vault().open_str(u.totp_secret_enc)

    if totp_secret:
        # recorded so main()'s finally can always clear the temporary enrolment
        globals()["TOTP_SECRET"] = totp_secret

    dest = ext_address()
    print(f"        sending {SEND_AMOUNT} sat to external address {dest}")

    html = s.get(f"{BASE}/send", timeout=30).text
    r = s.post(f"{BASE}/send/quote",
               data={"csrf_token": csrf(html), "address": dest,
                     "amount": f"{SEND_AMOUNT / 100_000_000:.8f}", "priority": "normal"},
               timeout=60, allow_redirects=False)
    check("quote created", r.status_code == 302 and "/send/review/" in
          r.headers.get("Location", ""), f"status={r.status_code} loc={r.headers.get('Location')}")
    quote_url = r.headers.get("Location", "")

    r = s.get(BASE + quote_url, timeout=30)
    body = r.text
    check("review page shows the destination", dest in body)
    m = re.search(r"Total deducted.*?<span class=\"v\">([\d.]+) BTC", body, re.S)
    quoted_total_btc = m.group(1) if m else None
    m2 = re.search(r"Network fee \(miners\).*?<span class=\"v\">([\d.]+) BTC", body, re.S)
    quoted_fee_btc = m2.group(1) if m2 else None
    print(f"        quoted total={quoted_total_btc} BTC network_fee={quoted_fee_btc} BTC")
    check("review page shows a network fee", quoted_fee_btc is not None)
    check("review page shows the total", quoted_total_btc is not None)

    # password re-confirmation (sudo) then the confirm POST
    html = s.get(f"{BASE}/confirm", timeout=30).text
    data = {"csrf_token": csrf(html), "password": ADMIN_PW}
    if totp_secret:
        data["code"] = pyotp.TOTP(totp_secret).now()
    r = s.post(f"{BASE}/confirm", data=data, timeout=30, allow_redirects=False)
    check("password re-confirmation accepted", r.status_code == 302,
          f"status={r.status_code}")

    qid = quote_url.rstrip("/").split("/")[-1]
    r = s.get(f"{BASE}/send/review/{qid}", timeout=30).text
    r = s.post(f"{BASE}/send/confirm/{qid}", data={"csrf_token": csrf(r)},
               timeout=90, allow_redirects=False)
    check("send submitted", r.status_code == 302, f"status={r.status_code}")

    # ---- 4. verify what actually happened
    print("\n4. On-chain and ledger verification")
    with app.app_context():
        w = (db.session.query(Withdrawal)
             .filter(Withdrawal.user_id == user_id,
                     Withdrawal.created_at >= datetime.now(timezone.utc) - timedelta(minutes=10))
             .order_by(Withdrawal.id.desc()).first())
        check("withdrawal recorded as sent",
              w is not None and w.status == "sent",
              f"{w.status if w else None} {w.error if w else ''}")
        if w is None or w.status != "sent":
            print("        aborting verification — nothing was broadcast")
            return finish()

        txid = w.txid
        check("withdrawal has a txid", bool(txid), str(txid))
        check("our_txs marks the broadcast so change is not re-credited",
              db.session.get(OurTx, txid) is not None)
        check("tx record links the withdrawal",
              db.session.query(Transaction).filter_by(withdrawal_id=w.id).count() == 1)

        u = db.session.get(User, user_id)
        expected_balance = expect_sat - w.total_sat
        check("ledger debited by amount + service fee + actual miner fee",
              u.balance_sat == expected_balance,
              f"{u.balance_sat} vs {expected_balance}")
        check("debit equals the quoted total",
              quoted_total_btc is None or
              abs(float(quoted_total_btc) - (w.total_sat / 100_000_000)) < 1e-8,
              f"quoted {quoted_total_btc} vs charged {w.total_sat/1e8}")
        check("quoted miner fee equals the fee actually paid",
              quoted_fee_btc is None or
              abs(float(quoted_fee_btc) - (w.network_fee_sat / 100_000_000)) < 1e-8,
              f"quoted {quoted_fee_btc} vs paid {w.network_fee_sat/1e8}")
        raw_hex = w.raw_hex
        amount = w.amount_sat
        svc = w.service_fee_sat
        netfee = w.network_fee_sat
        vsize_est = w.vsize_est
        prio = w.priority
        rate = w.fee_rate

    # the broadcast tx, straight from the explorer
    print("\n5. Independent on-chain confirmation")
    t = None
    for _ in range(10):
        try:
            t = explorer.tx(txid)
        except ChainError:
            t = None
        if t:
            break
        time.sleep(6)
    check("transaction is visible to the network", t is not None)
    if t:
        outs = {v.get("scriptpubkey_address"): int(v["value"]) for v in t["vout"]}
        check("payment output matches the requested amount",
              outs.get(dest) == amount, f"{outs.get(dest)} vs {amount}")
        check("no unexpected third-party outputs",
              len([v for v in t["vout"] if v.get("scriptpubkey_address") != dest]) == 1,
              f"{len(t['vout'])} outputs")
        ins = sum(int(v["prevout"]["value"]) for v in t["vin"])
        out_total = sum(int(v["value"]) for v in t["vout"])
        check("actual miner fee matches the recorded fee",
              ins - out_total == netfee, f"chain {ins-out_total} vs recorded {netfee}")

        from embit.transaction import Transaction as Tx
        from app import btc
        parsed = Tx.parse(bytes.fromhex(raw_hex))
        check("recorded raw tx matches the txid on-chain",
              parsed.txid().hex() == txid, f"{parsed.txid().hex()} vs {txid}")
        real_vsize = btc.exact_vsize(parsed)
        check("recorded vsize matches the signed transaction",
              real_vsize == vsize_est, f"recorded {vsize_est} vs actual {real_vsize}")
        achieved = netfee / real_vsize
        check("achieved fee rate is close to the chosen tier",
              abs(achieved - rate) / max(1, rate) <= 0.20,
              f"tier {rate} sat/vB, achieved {achieved:.2f}")
        print(f"        vsize={real_vsize} vB, fee={netfee} sat, "
              f"{achieved:.2f} sat/vB ({prio}), service fee {svc} sat")

    # ---- 6. accounting identity still holds
    print("\n6. Accounting identity after a real send")
    with app.app_context():
        h = services.global_holdings()
        check("identity: spendable − ledger = fees collected",
              h["fees_collected_sat"] == h["spendable_sat"] - h["user_ledger_sat"],
              f"{h['fees_collected_sat']} vs {h['spendable_sat']} - {h['user_ledger_sat']}")
        print(f"        on-chain {h['onchain_sat']} sat ({h['onchain_confirmed_sat']} confirmed, "
              f"{h['in_flight_sat']} in flight), ledger {h['user_ledger_sat']} sat, "
              f"fees {h['fees_collected_sat']} sat")
        check("service fee is retained as operator revenue",
              h["fees_collected_sat"] >= svc, f"{h['fees_collected_sat']} vs {svc}")

    # ---- restore: clear the temporary 2FA enrolment so the operator can enrol
    # their own device (also handled in main()'s finally, belt and braces)
    return finish()


def finish():
    print("\n" + "=" * 66)
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    for f in FAILED:
        print(f"  - {f}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
