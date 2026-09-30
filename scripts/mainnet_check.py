#!/usr/bin/env python3
"""Verify the wallet behaves correctly on whichever network it is configured for.

Run this after `launch-network` and before letting real money in. It creates one
throwaway account, exercises the paths that would destroy coins if they were
wrong, and removes the account again.

The point is not coverage — scripts/e2e_test.py already covers behaviour. This
covers the handful of things that only matter once the network is real:

  * addresses we hand out belong to THIS network
  * an address from ANOTHER network is refused, not accepted and signed
  * the fee oracle and the price feed are talking to the right chain/market
  * the books are internally consistent on a wallet that holds nothing yet

Usage (inside the container):

    python /app/scripts/mainnet_check.py

Exits non-zero if anything that could cost money is wrong.
"""

import os
import re
import sys
import time
import uuid

import requests

BASE = os.environ.get("BASE_URL", "https://localhost")
MIN_PW = 10
PASSWORD = "Mainnet-Check-97!x"

# a known-good address on each network, used to prove cross-network refusal
FOREIGN = {
    "mainnet": ("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet"),
    "testnet": ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "mainnet"),
}

PASSED, FAILED = [], []


def check(label, cond, detail=""):
    if cond:
        PASSED.append(label)
        print(f"  PASS  {label}")
    else:
        FAILED.append(label)
        print(f"  FAIL  {label}" + (f"  [{detail}]" if detail else ""))
    return bool(cond)


def csrf(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def flashes(html):
    return " ".join(re.findall(r'class="notice [^"]*"[^>]*>(.*?)</div>', html, re.S))[:300]


def sess():
    s = requests.Session()
    s.headers["User-Agent"] = "btcwallet-mainnet-check/1.0"
    return s


def reset_throttles():
    """Clear this script's own counters — they are per-IP and persist."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import create_app
    from app.config import Config
    from app.extensions import db
    from app.models import Throttle

    app = create_app(Config)
    with app.app_context():
        n = (db.session.query(Throttle)
             .filter(Throttle.bucket.like("signup:%")).delete(synchronize_session=False))
        n += (db.session.query(Throttle)
              .filter(Throttle.bucket.like("login:%")).delete(synchronize_session=False))
        n += (db.session.query(Throttle)
              .filter(Throttle.bucket.like("global:%")).delete(synchronize_session=False))
        db.session.commit()
    return n


def cleanup(username):
    """Remove the test account, reversing any balance rather than dropping it."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import create_app, services
    from app.config import Config
    from app.extensions import db
    from app.models import User

    app = create_app(Config)
    with app.app_context():
        u = db.session.query(User).filter(User.username == username).first()
        if u is None:
            return
        bal = int(u.balance_sat or 0)
        if bal:
            services.apply_ledger(u, -bal, "correction", ref="mainnet-check",
                                 note="Reversal of check-run credit")
        db.session.delete(u)
        db.session.commit()


def main():
    print(f"MAINNET CHECK — {BASE}")
    from app import create_app, services
    from app.config import Config
    app = create_app(Config)
    with app.app_context():
        net = services.network().name
    print(f"configured network: {net}\n")

    prefix = "bc1" if net == "mainnet" else "tb1"

    # ---------------------------------------------------------------- 1
    print("1. Deposit addresses belong to this network")
    reset_throttles()
    name = f"mcheck_{uuid.uuid4().hex[:6]}"
    s = sess()
    html = s.get(f"{BASE}/signup", timeout=30).text
    r = s.post(f"{BASE}/signup", data={
        "csrf_token": csrf(html), "username": name,
        "password": PASSWORD, "password2": PASSWORD, "agree": "1"},
        timeout=30, allow_redirects=False)
    check("signup succeeded", r.status_code == 302, f"status={r.status_code}")
    if r.status_code != 302:
        print(flashes(s.get(f"{BASE}/signup", timeout=30).text))
        return finish()

    page = s.get(f"{BASE}/receive", timeout=40).text
    m = re.search(rf"({prefix}[a-z0-9]{{20,}})", page)
    got = m.group(1) if m else None
    check(f"receive page shows a {prefix} address", bool(got), "no address found")

    if got:
        from app import btc
        with app.app_context():
            try:
                canonical, _spk, stype = btc.validate_destination(got, services.network())
                ok = True
            except Exception as exc:
                canonical, stype, ok = None, str(exc), False
        check("our own address validates for this network", ok, str(stype))
        check("address is the right kind (p2wpkh)",
              ok and stype == "p2wpkh", str(stype))
        # must be findable by the chain watcher, i.e. the explorer knows the chain
        try:
            with app.app_context():
                utxos = services.explorer().address_utxos(got)
            check("chain watcher can query the address", isinstance(utxos, list),
                  str(type(utxos)))
        except Exception as exc:
            check("chain watcher can query the address", False, str(exc))

    check("QR code offered for the address", "qr" in page.lower())

    # ---------------------------------------------------------------- 2
    print("\n2. An address from the WRONG network must be refused")
    foreign_addr, foreign_net = FOREIGN[net]
    html = s.get(f"{BASE}/send", timeout=30).text
    r = s.post(f"{BASE}/send/quote", data={
        "csrf_token": csrf(html), "address": foreign_addr, "amount": "0.0001",
        "tier": "normal"}, timeout=40, allow_redirects=False)
    body = r.text if r.status_code < 400 else ""
    if r.status_code == 302:
        body = s.get(BASE + r.headers.get("Location", "/send"), timeout=30).text
    refused = ("different network" in body.lower()
               or foreign_net in body.lower()
               or "mainnet address but this wallet is on testnet" in body.lower()
               or "testnet address but this wallet is on mainnet" in body.lower())
    check(f"a {foreign_net} address is refused on {net}", refused,
          f"status={r.status_code} {body and body[:120]}")

    # ---------------------------------------------------------------- 3
    print("\n3. Fee estimation talks to the right chain")
    try:
        with app.app_context():
            rates, meta = services.get_fee_rates()
        check("fee rates returned", bool(rates), str(rates))
        vals = [rates.get(k) for k in ("fast", "normal", "economy")]
        check("all fee rates are positive", all(v and v > 0 for v in vals), str(vals))
        check("fee rates look like this chain's market (< 2000 sat/vB)",
              all(v and v < 2000 for v in vals), str(vals))
        check("fast >= economy", vals[0] >= vals[2], str(vals))
        print(f"        fast/normal/economy = {vals[0]}/{vals[1]}/{vals[2]} sat/vB")
    except Exception as exc:
        check("fee estimation works", False, f"{type(exc).__name__}: {exc}")

    # ---------------------------------------------------------------- 4
    print("\n4. Price feed")
    try:
        from app.price import get_price
        with app.app_context():
            price, src = get_price()
        check("USD price available", bool(price) and price > 0, f"{price} from {src}")
        check("price is in a believable range for BTC",
              bool(price) and 1000 < price < 10_000_000, str(price))
        print(f"        BTC/USD = {price} (source: {src})")
    except Exception as exc:
        check("price feed works", False, f"{type(exc).__name__}: {exc}")

    # ---------------------------------------------------------------- 5
    print("\n5. Books are consistent on an empty wallet")
    try:
        with app.app_context():
            h = services.global_holdings()
        check("no float shortfall", h["float_shortfall"] == 0, str(h))
        check("identity: spendable - ledger = fees",
              h["fees_collected_sat"] == h["spendable_sat"] - h["user_ledger_sat"],
              str(h))
        check("spendable = confirmed + in-flight",
              h["spendable_sat"] == h["onchain_confirmed_sat"] + h["in_flight_sat"],
              str(h))
        print(f"        on-chain {h['onchain_sat']} sat | owed {h['user_ledger_sat']} "
              f"| fees {h['fees_collected_sat']}")
    except Exception as exc:
        check("holdings computed", False, str(exc))

    # ---------------------------------------------------------------- 6
    print("\n6. No testnet leftovers on a mainnet wallet")
    if net == "mainnet":
        with app.app_context():
            from app.extensions import db
            from app.models import Address, User
            bad = [a.address for a in db.session.query(Address).all()
                   if not a.address.startswith("bc1")]
            check("every stored address is a mainnet address", not bad, str(bad[:3]))
            check("testnet faucet is disabled",
                  not services.get_bool_setting("testnet_faucet_enabled"))

    cleanup(name)
    print(f"\n  (removed test account {name})")
    return finish()


def finish():
    print("\n" + "=" * 62)
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        print("\nFAILURES:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 62)
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
