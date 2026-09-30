# Operations

## Install

```bash
git clone https://github.com/jlaiii/btc-vault.git
cd btc-vault
./scripts/setup.sh          # .env (random secrets), secrets/master.key, an admin, a seed
docker compose up -d --build
curl -s localhost:8810/health      # {"ok":true,"service":"btcwallet"}
```

`setup.sh` prints the admin password **once** and where the recovery phrase is (the file
it writes). Write the 24 words on paper, then delete that file and acknowledge it:

```bash
docker compose exec web python -m app.cli ack-seed-backup
```

Put TLS in front (`deploy/caddy-btc.conf` is a working Caddy vhost — replace the hostname).
HTTPS is not optional: the session cookie is `Secure`, so plain HTTP means no session.

## Routine checks

```bash
docker compose ps                                  # all three healthy (syncer has a heartbeat healthcheck)
docker compose logs --tail 100 web syncer
docker compose exec web python -m app.cli holdings # on-chain vs owed vs fees
docker compose exec web python -m app.cli preflight # GO / REVIEW / NOT READY
docker compose exec -T web python /app/scripts/mainnet_check.py
```

The admin dashboard shows the same invariant continuously; a float shortfall raises a
critical alert. Acknowledge alerts after acting on them, not before.

## Upgrade

```bash
cd /path/to/btc-vault
git pull
docker compose up -d --build          # rebuild images, recreate containers
docker compose exec web python -m app.cli preflight
```

`app/` and `scripts/` are bind-mounted read-only into both containers, so a plain
`docker compose restart web syncer` picks up code edits without a rebuild. **Environment
changes need a recreate** (`up -d`, or `stop` + `rm -f` + `create` + `start`) —
`restart` keeps the old environment, which looks exactly like a broken guard.

Schema changes are applied by the app on boot: `_ensure_columns()` in `app/__init__.py`
checks `information_schema` first and only issues `ALTER TABLE ... ADD COLUMN` when the
column is genuinely missing, under `lock_timeout = 5s`, one commit per column. Watch for
a `schema drift: added …` line in the logs after an upgrade.

### Changing the Bitcoin network

Never edit `BTC_NETWORK` and restart. Derivation paths differ per network, so every
stored address belongs to the other chain. Use the migration:

```bash
# 1. edit BTC_NETWORK in .env, then RECREATE every service (not restart)
docker compose stop && docker compose rm -f && docker compose up -d

# 2. run the migration: zeroes balances with a recorded `network_reset` ledger entry,
#    deletes the now-unreachable addresses, generates a fresh seed, applies defaults
docker compose exec web python -m app.cli launch-network --seed-out /tmp/seed.txt

# 3. get the new seed OFF the container (it is ephemeral in there), write it down, delete
docker cp btcwallet-web:/tmp/seed.txt ./HOTWALLET_MNEMONIC.txt
docker compose exec web rm -f /tmp/seed.txt

# 4. deposits stay disabled until you acknowledge the backup
docker compose exec web python -m app.cli ack-seed-backup
docker compose exec web python -m app.cli preflight
```

While a migration is pending the app returns 503 with an explanation (the `/health`
endpoint keeps answering). That is deliberate: down with a clear message beats quietly
handing out addresses that cannot receive.

## Backups

Three things, in order of irreplaceability:

1. **`secrets/master.key`** — without it the seed cannot be decrypted. Back it up
   *separately* from the database; storing them together defeats the point.
2. **The recovery phrase** — on paper, offline. It is the only way to recover the coins
   if the master key and the database are both lost.
3. **The `btcwallet-db` volume** — accounts, ledger, audit trail:

```bash
docker compose exec -T db pg_dump -U btcwallet -d btcwallet | gzip > backup-$(date +%F).sql.gz
```

Restore into a fresh volume:

```bash
gunzip -c backup-2026-09-30.sql.gz | docker compose exec -T db psql -U btcwallet -d btcwallet
```

Test a restore before you need one. A backup you have never restored is a hope.

## Incident runbook

**Float shortfall alert** (`services.check_invariant` or the dashboard)
1. `cli holdings` — compare `spendable_sat`, `user_ledger_sat`, `fees_collected_sat`.
2. Look for an admin balance change in Ledger and admin_audit.
3. Fix by crediting/debiting the operator account until the identity holds. Never edit
   `users.balance_sat` with SQL — the ledger would no longer explain the balance.

**Broadcast failed** (`broadcast_failed` alert)
1. The withdrawal is marked failed and refunded automatically.
2. Check the destination address and the fee rate in the withdrawal row.
3. Retry by approving the withdrawal again once the cause is fixed (or ask the user to
   re-submit if the address was rejected).

**Chain watcher silent** (`credited=0` forever, or the heartbeat alert)
1. `docker compose logs --tail 50 syncer` — compare the logged tip with the real tip
   (mainnet ≈ 900k today, testnet3 ≈ 4.6M).
2. A tip that never moves means the explorer is unreachable or the watcher is on the
   wrong network. Check `BTC_NETWORK` **inside the syncer container**:
   `docker compose exec syncer env | grep BTC_NETWORK`.
3. Fix by recreating that service; never leave it running on the other network.

**Suspected account compromise**
1. Admin → Users → the account → **Freeze** (stops sends; deposits still arrive) or
   **Ban** (signs them out everywhere).
2. **Sign out everywhere** to kill live sessions.
3. **Require a new password** so the next sign-in is a password they choose.
4. Read the account's Security events and the audit log before you change anything else.
5. If the balance is in question, `cli holdings` and the ledger page; sweep only as a
   last resort (it moves the claim, not the coins).

**Lost authenticator on an admin account**
The panel cannot help — reaching it needs a sign-in. From the host:

```bash
docker compose exec db psql -U btcwallet -d btcwallet \
  -c "UPDATE users SET totp_enabled=false, totp_secret_enc=NULL, backup_codes_json=NULL WHERE username='you';"
```

That is exactly the lockout the "administrators are never forced into 2FA" rule exists to
avoid; keep the recovery phrase of that account's credentials somewhere physical.

**Disk full / database won't start**
The DB volume is the only stateful thing. Free space, then `docker compose up -d db`;
the web container retries its database bootstrap 10 times at 3-second intervals.

## Routine hardening checklist

- [ ] 2FA on every admin account (the panel reminds at every sign-in until it is on)
- [ ] Setup-transcript password changed (`preflight` flags it)
- [ ] Recovery phrase written down, file deleted, backup acknowledged (`preflight`)
- [ ] `secrets/master.key` backed up offline, `0600`, owned by uid 1500
- [ ] Host firewall: only 80/443 (and SSH) open; the app listens on loopback only
- [ ] `min_confirmations >= 2` before real money
- [ ] A send-approval ceiling set (`instant_send_max_sat`) that you are comfortable losing
- [ ] Signups closed (`signups_enabled` off) unless you intend to onboard people
- [ ] Alerts acknowledged daily; the audit page read weekly
