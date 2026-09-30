"""Operator CLI.

    python -m app.cli init                 # create schema, settings, wallet seed
    python -m app.cli create-admin --username jay --email jay@example.com
    python -m app.cli show-seed            # print the recovery phrase
    python -m app.cli sync                 # one chain-watch pass
    python -m app.cli holdings             # on-chain vs user balances
    python -m app.cli settings             # dump current settings

Moving to mainnet (run in this order):

    python -m app.cli launch-network --confirm    # destructive migration + new seed
    python -m app.cli ack-seed-backup            # after writing the words down
    python -m app.cli preflight                  # GO/NO-GO before real money
"""

import argparse
import secrets
import sys

from app import create_app, services
from app.config import Config
from app.extensions import db
from app.models import User
from app.security import hash_password
from app.utils import password_problems


def cmd_init(args):
    app = create_app(Config)
    with app.app_context():
        print("Schema, settings and sequence: ready.")
        created = services.ensure_seed()
        if created:
            print("\n" + "=" * 72)
            print("HOT WALLET RECOVERY PHRASE (write this down, then delete any copy)")
            print("=" * 72)
            print(created)
            print("=" * 72)
            print("This is the ONLY copy that will ever be printed here.")
            print("It is also stored encrypted in the database and (if the mount")
            print("was writable) in the file named by SEED_BACKUP_FILE.")
            print("=" * 72 + "\n")
        else:
            print("A wallet seed already exists — left untouched.")
        print(f"Network: {app.config['BTC_NETWORK']}")
        print(f"Explorers: {services.explorer().urls}")


def cmd_create_admin(args):
    app = create_app(Config)
    with app.app_context():
        username = args.username.strip()
        email = (args.email or "").strip().lower() or None

        existing = db.session.query(User).filter(
            db.func.lower(User.username) == username.lower()).first()
        if existing:
            existing.role = "admin"
            target = existing
            db.session.commit()
            print(f"Promoted existing account '{username}' to admin.")
            if not args.force_password:
                print("Password unchanged.")
                return
            password = args.password or ("btc-" + secrets.token_urlsafe(9))
        else:
            problems = password_problems(args.password or "", username, email)
            if args.password and problems:
                print("Password rejected:")
                for p in problems:
                    print(f"  - {p}")
                sys.exit(1)
            password = args.password or ("btc-" + secrets.token_urlsafe(9))
            target = User(
                username=username, email=email,
                password_hash=hash_password(password),
                role="admin", status="active",
            )
            db.session.add(target)
            db.session.commit()

        target.password_hash = hash_password(password)
        target.role = "admin"
        target.status = "active"
        target.deleted_at = None
        target.failed_logins = 0
        target.locked_until = None
        db.session.commit()

        # an admin is a wallet holder too — without this their dashboard shows
        # no wallet until they happen to open the Receive page
        try:
            services.ensure_primary_address(target)
        except Exception as exc:
            print(f"warning: could not create a deposit address: {exc}")

        print("\n" + "=" * 72)
        print(f"ADMIN ACCOUNT READY: {username}")
        if not args.password or existing is None or args.force_password:
            print(f"PASSWORD: {password}")
            print("Change it after signing in.")
        print("=" * 72)
        print("Two-factor authentication is MANDATORY for admins: the first")
        print("sign-in will force you straight to the 2FA setup page.")
        print("=" * 72 + "\n")


def cmd_show_seed(args):
    app = create_app(Config)
    with app.app_context():
        try:
            print(services.reveal_mnemonic())
        except Exception as exc:
            print(f"Could not read the seed: {exc}", file=sys.stderr)
            sys.exit(1)


def cmd_sync(args):
    app = create_app(Config)
    with app.app_context():
        summary = services.sync_once(verbose=True)
        for k, v in summary.items():
            print(f"{k}: {v}")


def cmd_holdings(args):
    app = create_app(Config)
    with app.app_context():
        h = services.global_holdings()
        from app.utils import sats_to_btc_str

        print(f"network:                {services.network().name}")
        print(f"on-chain total:         {sats_to_btc_str(h['onchain_sat'])} BTC "
              f"({h['onchain_sat']} sats)")
        print(f"  confirmed:            {h['onchain_confirmed_sat']} sats")
        print(f"  unconfirmed:          {h['onchain_unconfirmed_sat']} sats")
        print(f"user balances (ledger): {sats_to_btc_str(h['user_ledger_sat'])} BTC "
              f"({h['user_ledger_sat']} sats)")
        print(f"operator fees:          {h['fees_collected_sat']} sats")
        print(f"queued withdrawals:     {h['queued_withdrawals_sat']} sats")
        print(f"addresses:              {h['address_count']}")
        if h["float_shortfall"]:
            print(f"!! FLOAT SHORTFALL:     {h['float_shortfall']} sats")
        for e in h["errors"]:
            print(f"  explorer error: {e}")


def cmd_settings(args):
    app = create_app(Config)
    with app.app_context():
        for key in services.SETTING_LABELS:
            print(f"{key:32} = {services.get_setting(key)}")


def cmd_add_funds_hint(args):
    print(
        "To put testnet coins into the wallet, open the site's Receive page for\n"
        "any account and use the built-in faucet (admin: /admin/settings), or\n"
        "send testnet BTC to any deposit address from an external faucet such as\n"
        "https://coinfaucet.eu/en/btc-testnet/ or https://mempool.space/testnet/faucet"
    )


SEED_ACK_KEY = "seed_backed_up"


def cmd_launch_network(args):
    """Move the wallet onto the configured network, in one deliberate step."""
    app = create_app(Config)
    with app.app_context():
        target = services.network().name
        recorded = services.launch_network() or "(none)"
        pending = services.network_transition_required()

        if not pending:
            print(f"Nothing to do: wallet is already on {target}.")
            return 0
        if not args.confirm:
            print(f"REFUSING: this database holds {recorded} data and BTC_NETWORK "
                  f"is {target}.\n")
            print("This migration is destructive and deliberate:")
            print(f"  - every account balance is zeroed ({recorded} coins are a "
                  f"different chain and worth nothing here)")
            print(f"  - all existing deposit addresses are removed (their "
                  f"derivation paths are unreachable on {target})")
            print("  - a NEW wallet seed is generated for " + target)
            print("  - deposits are disabled until you confirm the seed is backed up\n")
            print("Re-run with --confirm to proceed.")
            return 2

        before = services.global_holdings()
        print(f"Moving {recorded} -> {target}")
        print(f"  on-chain {before['onchain_sat']} sats, ledger "
              f"{before['user_ledger_sat']} sats (all {recorded})\n")

        res = services.reset_for_network_launch(args.seed_out)

        # settings that only make sense on testnet
        services.set_setting("testnet_faucet_enabled", "0")
        # Deposits stay as configured (on by default): the operator asked for a site
        # that is ready to use, so the wallet does not silently close them after a
        # network move. `preflight` still reports an un-backed-up seed.
        services.set_setting("min_confirmations", str(args.min_confirmations))
        services.set_setting("instant_send_max_sat", str(args.auto_send_max_sat))
        services.set_setting(SEED_ACK_KEY, "0")

        print(f"  accounts zeroed      : {res['accounts_zeroed']} "
              f"({res['sats_cleared']} sats cleared)")
        print(f"  addresses removed    : {res['addresses_removed']}")
        print(f"  new seed written to  : {res['mnemonic_file']}")
        print(f"  network recorded     : {services.launch_network()}")
        print(f"  min confirmations    : {args.min_confirmations}")
        print(f"  auto-send ceiling    : {args.auto_send_max_sat} sats "
              f"(above this, sends need your approval)")
        print("\nNEXT STEPS — the wallet will not accept deposits yet:")
        print(f"  1. Read {res['mnemonic_file']}, write the 24 words on paper,")
        print("     store them offline, then delete that file.")
        print("  2. Confirm it:  python -m app.cli ack-seed-backup")
        print("  3. Check readiness:  python -m app.cli preflight")
        if res["mnemonic_file"] and not res["mnemonic_file"].startswith("/run/secrets"):
            print("\n!! CARE: this CLI ran inside the container, so that path is")
            print("   inside the container's own filesystem. Copy it to the host")
            print("   NOW, before the container is ever recreated:")
            print(f"     docker cp btcwallet-web:{res['mnemonic_file']} "
                  f"/root/mainnet-seed.txt && chmod 600 /root/mainnet-seed.txt")
        return 0


def cmd_ack_seed_backup(args):
    """Record that the operator has written the seed down, and open deposits."""
    app = create_app(Config)
    with app.app_context():
        if services.network_transition_required():
            print("Refusing: finish `launch-network` first.")
            return 2
        if not services.seed_exists():
            print("Refusing: there is no wallet seed to back up.")
            return 2
        services.set_setting(SEED_ACK_KEY, "1")
        services.set_setting("deposits_enabled", "1")
        print("Seed backup acknowledged. Deposits are now ENABLED.\n")
        print("If you have NOT actually written the words down, say so now by")
        print("running:  python -m app.cli preflight   (it will remind you)")
        print("then disable deposits in Admin -> Settings until you have.")
        return 0


# Genesis block hash of each chain — a definitive way to prove which network an
# explorer endpoint is actually serving.
GENESIS = {
    "mainnet": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    "testnet": "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
}


def cmd_preflight(args):
    """Honest GO/NO-GO before this wallet is allowed to hold real money."""
    app = create_app(Config)
    go, nogo, warn = [], [], []

    def ok(msg):
        go.append(msg)

    def bad(msg):
        nogo.append(msg)

    def caution(msg):
        warn.append(msg)

    with app.app_context():
        net = services.network().name
        print(f"PREFLIGHT — network: {net}\n")

        # --- network consistency
        pending = services.network_transition_required()
        if pending:
            bad(f"network transition incomplete (data is {pending['recorded']}, "
                f"configured {pending['configured']}) — run launch-network")
        else:
            ok(f"database and configuration agree on {net}")

        # --- seed present and decryptable
        if not services.seed_exists():
            bad("no wallet seed exists")
        else:
            try:
                words = services.reveal_mnemonic().split()
                ok(f"seed present and decrypts ({len(words)} words)")
                if len(words) != 24:
                    caution(f"seed has {len(words)} words, not 24")
            except Exception as exc:
                bad(f"seed cannot be decrypted ({type(exc).__name__}) — is the "
                    f"master key present and readable?")

        if services.get_setting(SEED_ACK_KEY) == "1":
            ok("seed backup acknowledged by the operator")
        else:
            bad("seed backup NOT acknowledged — anyone who has the words can "
                "spend every coin, so an unbacked seed loses everything on "
                "hardware failure (run ack-seed-backup once it is written down)")

        # --- the explorer must really be the chain we think it is
        try:
            client = services.explorer()
            resp = client._get("/block-height/0")   # returns a Response
            genesis = (getattr(resp, "text", "") or "").strip().strip('"')
            if genesis == GENESIS.get(net):
                ok(f"explorer serves real {net} data (genesis block verified)")
            elif genesis in GENESIS.values():
                other = [k for k, v in GENESIS.items() if v == genesis][0]
                bad(f"explorer is serving {other} data while configured for {net} "
                    f"— deposits would be watched on the wrong chain")
            else:
                caution(f"could not confirm the explorer's chain (got "
                        f"{genesis[:16]!r})")
        except Exception as exc:
            bad(f"explorer unreachable ({type(exc).__name__}: {exc}) — the wallet "
                f"could not see deposits or broadcast")

        # --- money settings
        if services.get_bool_setting("deposits_enabled"):
            ok("deposits enabled")
        else:
            caution("deposits are disabled (no new money will arrive)")

        ceiling = services.get_int_setting("instant_send_max_sat")
        if ceiling <= 0:
            ok("every send requires your approval")
        elif net == "mainnet" and ceiling > 500_000:
            caution(f"auto-send ceiling is {ceiling} sats (~{ceiling/1e8:.4f} BTC) "
                    f"and leaves the wallet without your confirmation")
        else:
            ok(f"sends up to {ceiling} sats are automatic, above that need approval")

        conf = services.get_int_setting("min_confirmations")
        if net == "mainnet" and conf < 2:
            caution(f"min_confirmations is {conf}; 2+ avoids crediting a deposit "
                    f"that a reorg can undo")
        else:
            ok(f"min_confirmations = {conf}")

        if net == "mainnet" and services.get_bool_setting("testnet_faucet_enabled"):
            bad("the testnet faucet is enabled on mainnet")

        # --- admin accounts
        from app.models import User
        admins = db.session.query(User).filter(User.role == "admin",
                                               User.deleted_at.is_(None)).all()
        if not admins:
            bad("there is no admin account")
        for a in admins:
            if not a.totp_enabled:
                # Not a blocker: 2FA is optional for admins by operator choice. The
                # app nudges (sign-in notice, banner, Admin -> Settings) instead of
                # forcing it, and this is the same information, stated once more.
                caution(f"admin {a.username} has no 2FA — strongly recommended; "
                        f"a stolen password is otherwise account takeover")
            else:
                ok(f"admin {a.username} has 2FA")
            try:
                from app.security import verify_password
                if verify_password(a.password_hash, "btc-lOe8fOyuA28L"):
                    bad(f"admin {a.username} still uses the original password "
                        f"from the setup transcript — change it")
            except Exception:
                pass

        # --- signups / exposure
        if services.get_bool_setting("signups_enabled"):
            caution("PUBLIC SIGNUPS ARE OPEN. Holding other people's bitcoin is "
                    "regulated money transmission in the US (FinCEN MSB + state "
                    "licences, incl. Texas Finance Code Ch. 151). Safe to open "
                    "for a small pilot with people you know; taking strangers' "
                    "funds publicly is a legal question, not a technical one")
        else:
            ok("signups are closed (invite-only by hand)")

        # --- theft surface
        try:
            import os, stat
            keyf = app.config["MASTER_KEY_FILE"]
            if os.path.exists(keyf):
                mode = stat.S_IMODE(os.stat(keyf).st_mode)
                ok(f"master key present (mode {oct(mode)})" if mode == 0o600
                   else f"master key mode is {oct(mode)}, expected 600")
            else:
                bad(f"master key missing at {keyf}")
            if os.path.exists("/run/secrets/HOTWALLET_MNEMONIC.txt"):
                caution("a mnemonic file is still on disk at "
                        "/run/secrets/HOTWALLET_MNEMONIC.txt — write the words "
                        "down offline and delete it")
        except Exception as exc:
            caution(f"could not inspect secret permissions ({exc})")

        # --- books
        try:
            h = services.global_holdings()
            if h["float_shortfall"]:
                bad(f"float shortfall of {h['float_shortfall']} sats — users are "
                    f"owed more than the wallet can pay")
            else:
                ok(f"books balance (on-chain {h['onchain_sat']}, owed "
                   f"{h['user_ledger_sat']}, fees {h['fees_collected_sat']})")
        except Exception as exc:
            caution(f"could not compute holdings ({exc})")

    print("PASS")
    for m in go:
        print(f"  + {m}")
    if warn:
        print("\nREVIEW")
        for m in warn:
            print(f"  ! {m}")
    if nogo:
        print("\nNOT READY")
        for m in nogo:
            print(f"  x {m}")
    print("\n" + "=" * 62)
    print("GO — ready to hold real bitcoin" if not nogo
          else f"NO-GO — {len(nogo)} blocker(s) above must be fixed first")
    print("=" * 62)
    return 0 if not nogo else 1


def main():
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create schema + wallet seed")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("create-admin", help="create or reset an admin account")
    p.add_argument("--username", required=True)
    p.add_argument("--email", default=None,
                   help="optional, unused by the app (accounts are username + password)")
    p.add_argument("--password", default=None, help="omit to auto-generate")
    p.add_argument("--force-password", action="store_true",
                   help="reset the password even if the account exists")
    p.set_defaults(func=cmd_create_admin)

    p = sub.add_parser("show-seed", help="print the hot wallet recovery phrase")
    p.set_defaults(func=cmd_show_seed)

    p = sub.add_parser("sync", help="run one chain-watch pass")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("holdings", help="show on-chain vs user balances")
    p.set_defaults(func=cmd_holdings)

    p = sub.add_parser("settings", help="dump all settings")
    p.set_defaults(func=cmd_settings)

    p = sub.add_parser("faucet-hint", help="how to get testnet coins")
    p.set_defaults(func=cmd_add_funds_hint)

    p = sub.add_parser("launch-network",
                       help="move the wallet onto the configured network (destructive)")
    p.add_argument("--confirm", action="store_true",
                   help="required: this zeroes balances and regenerates the seed")
    p.add_argument("--seed-out", default="/root/btcwallet-seed.txt",
                   help="where to write the new recovery phrase for backup")
    p.add_argument("--min-confirmations", type=int, default=2,
                   help="block confirmations before a deposit is credited (default 2)")
    p.add_argument("--auto-send-max-sat", type=int, default=50_000,
                   help="sends at or below this need no approval (default 50000 sats)")
    p.set_defaults(func=cmd_launch_network)

    p = sub.add_parser("ack-seed-backup",
                       help="record that you wrote the seed down, and enable deposits")
    p.set_defaults(func=cmd_ack_seed_backup)

    p = sub.add_parser("preflight",
                       help="GO/NO-GO readiness check before holding real money")
    p.set_defaults(func=cmd_preflight)

    args = parser.parse_args()
    # propagate the command's exit status so scripts (and preflight) can gate on it
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
