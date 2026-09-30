#!/usr/bin/env bash
# One-shot provisioning for BTC Vault.
#   - generates .env with strong random secrets (never printed, never committed)
#   - generates the AES master key OUTSIDE the database
#   - creates the docker volume and brings the stack up
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
ENV_FILE="$ROOT/.env"
SECRETS="$ROOT/secrets"

echo "==> BTC Vault setup in $ROOT"

mkdir -p "$SECRETS"
chmod 700 "$SECRETS"

# ---- master key: encrypts the hot wallet seed at rest ----------------------
# Owned by uid 1500 = the container's runtime user. 0600 + 0700 dir means the
# app can read it but no host user (and no other container) can.
if [ ! -s "$SECRETS/master.key" ]; then
  umask 077
  openssl rand -hex 32 > "$SECRETS/master.key"
  echo "    generated secrets/master.key (AES-256 master key)"
else
  echo "    secrets/master.key already exists — left untouched"
fi
chown 1500:1500 "$SECRETS/master.key"
chmod 600 "$SECRETS/master.key"
chown 1500:1500 "$SECRETS"

# ---- .env ------------------------------------------------------------------
if [ -s "$ENV_FILE" ]; then
  echo "    .env already exists — leaving it alone"
else
  umask 077
  PG_PASS="$(openssl rand -hex 24)"
  SECRET_KEY="$(openssl rand -hex 48)"
  # SITE_URL / MAIL_FROM. Set HOSTNAME_HINT to your hostname, or leave it empty and edit
  # SITE_URL afterwards. (sslip.io is a public wildcard DNS: 1-2-3-4.sslip.io → 1.2.3.4,
  # handy when you have no domain yet.)
  HOSTNAME_HINT="${HOSTNAME_HINT:-}"
  if [ -n "$HOSTNAME_HINT" ]; then
    SITE_URL_VALUE="https://btc.$HOSTNAME_HINT.sslip.io"
    MAIL_FROM_VALUE="vault@$HOSTNAME_HINT.sslip.io"
  else
    SITE_URL_VALUE="https://vault.example.com"
    MAIL_FROM_VALUE="vault@example.com"
  fi
  cat > "$ENV_FILE" <<EOF
# BTC Vault — generated $(date -u '+%Y-%m-%dT%H:%M:%SZ')
# Do not commit. Do not paste into chat.

POSTGRES_PASSWORD=$PG_PASS
SECRET_KEY=$SECRET_KEY

# ---- Bitcoin network: testnet | mainnet ----
# Switching to mainnet REQUIRES a fresh wallet seed: run the app with an empty
# database (or wipe the wallet_seed_enc setting) or existing addresses will be
# derived from the old seed's other coin type.
BTC_NETWORK=testnet

SITE_NAME=BTC Vault
SITE_URL=$SITE_URL_VALUE

# Leave empty to use the network's default Esplora endpoints
ESPLORA_URLS=

MASTER_KEY_FILE=/run/secrets/master.key
SEED_BACKUP_FILE=/run/secrets/HOTWALLET_MNEMONIC.txt

COOKIE_SECURE=1
SYNC_INTERVAL_SECONDS=60

# ---- money policy (also editable live in Admin -> Settings) ----
SERVICE_FEE_PCT=0.5
SERVICE_FEE_MIN_SAT=0
INSTANT_SEND_MAX_SAT=200000
WITHDRAW_MIN_SAT=10000
WITHDRAW_DAILY_MAX_SAT=5000000
MIN_CONFIRMATIONS=1

# ---- mail for password resets (host Postfix via the docker gateway) ----
MAIL_ENABLED=1
MAIL_HOST=host.docker.internal
MAIL_PORT=25
MAIL_FROM=$MAIL_FROM_VALUE

AUTO_CREATE_TABLES=1
EOF
  chmod 600 "$ENV_FILE"
  echo "    wrote .env (600) with fresh secrets"
fi

echo "==> building images"
docker compose build

echo "==> starting database"
docker compose create db
docker compose start db
for i in $(seq 1 30); do
  if docker compose exec -T db pg_isready -U btcwallet -d btcwallet >/dev/null 2>&1; then
    echo "    database ready"
    break
  fi
  sleep 1
done

echo "==> creating schema + hot wallet seed"
docker compose create web
docker compose start web
sleep 8
docker compose exec -T web python -m app.cli init

# The seed is written to the database encrypted, and a plaintext recovery copy
# is captured here on the HOST (the container's secret mount stays read-only, so
# the app itself can never rewrite the key material it depends on).
if docker compose exec -T web python -m app.cli show-seed > "$SECRETS/HOTWALLET_MNEMONIC.txt" 2>/dev/null; then
  chmod 600 "$SECRETS/HOTWALLET_MNEMONIC.txt"
  chown 1500:1500 "$SECRETS/HOTWALLET_MNEMONIC.txt"
  echo "    recovery phrase saved to secrets/HOTWALLET_MNEMONIC.txt (600)"
  echo "    >>> WRITE IT DOWN OFFLINE, THEN DELETE THAT FILE <<<"
else
  echo "    could not capture the recovery phrase — run: docker compose exec web python -m app.cli show-seed"
fi

echo "==> starting chain watcher"
docker compose create syncer
docker compose start syncer

echo
echo "==> next step: create the admin account"
echo "    docker compose exec web python -m app.cli create-admin --username <name> --email <you@example.com>"
echo
echo "==> then the site is at $(grep '^SITE_URL=' "$ENV_FILE" | cut -d= -f2)"
echo "    (add the Caddy vhost first — see deploy/caddy-btc.conf)"
