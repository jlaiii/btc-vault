"""BTC Vault configuration — everything from environment variables (.env)."""

import os

from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))


def _bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class Config:
    # --- core ---
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    SITE_NAME = os.environ.get("SITE_NAME", "Vault")
    SITE_URL = os.environ.get("SITE_URL", "http://localhost:8810").rstrip("/")

    # --- bitcoin network -------------------------------------------------
    # "testnet" or "mainnet". This is deliberately an ENV setting, not an
    # admin-editable one: switching it changes the BIP44 coin type and the
    # address format, so it must never be flippable from a web form.
    BTC_NETWORK = os.environ.get("BTC_NETWORK", "testnet").strip().lower()
    if BTC_NETWORK not in ("testnet", "mainnet"):
        BTC_NETWORK = "testnet"

    # Esplora-compatible block explorers. Leave EMPTY to use the network's
    # defaults (see chain.default_esplora_urls). First entry is primary; the
    # rest are failover for reads, and broadcast is attempted against each.
    ESPLORA_URLS = [
        u.strip().rstrip("/")
        for u in os.environ.get("ESPLORA_URLS", "").split(",")
        if u.strip()
    ]

    # --- data ---
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql+psycopg2://btcwallet:btcwallet@db:5432/btcwallet"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 280}

    # Master key file: encrypts the hot wallet seed + TOTP secrets at rest.
    MASTER_KEY_FILE = os.environ.get("MASTER_KEY_FILE", "/run/secrets/master.key")
    SEED_BACKUP_FILE = os.environ.get("SEED_BACKUP_FILE", "/run/secrets/HOTWALLET_MNEMONIC.txt")

    # --- sessions / cookies ---
    COOKIE_SECURE = _bool("COOKIE_SECURE", "1")
    SESSION_COOKIE_SECURE = COOKIE_SECURE
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # idle timeout: the cookie lifetime refreshes on every request, so this is
    # "30 minutes of inactivity" rather than a hard 30-minute cap
    PERMANENT_SESSION_LIFETIME = 60 * 30
    SESSION_REFRESH_EACH_REQUEST = True
    PREFERRED_URL_SCHEME = "https" if COOKIE_SECURE else "http"

    # how long a password re-entry ("sudo mode") unlocks sensitive actions
    SUDO_WINDOW_SECONDS = _int("SUDO_WINDOW_SECONDS", 900)

    # --- money policy defaults (admin can change these live in Settings) ---
    DEFAULT_SERVICE_FEE_PCT = os.environ.get("SERVICE_FEE_PCT", "0.5")   # percent
    DEFAULT_SERVICE_FEE_MIN_SAT = _int("SERVICE_FEE_MIN_SAT", 0)
    DEFAULT_INSTANT_SEND_MAX_SAT = _int("INSTANT_SEND_MAX_SAT", 200_000)  # 0.002 BTC
    DEFAULT_WITHDRAW_MIN_SAT = _int("WITHDRAW_MIN_SAT", 10_000)          # 0.0001 BTC
    DEFAULT_WITHDRAW_DAILY_MAX_SAT = _int("WITHDRAW_DAILY_MAX_SAT", 5_000_000)  # 0.05 BTC
    DEFAULT_MIN_CONFIRMATIONS = _int("MIN_CONFIRMATIONS", 1)

    # network fee bounds (sat/vB). A floor protects against a stuck tx from a
    # zero reading; the ceiling stops a bad oracle from draining a user.
    MIN_FEE_RATE = _int("MIN_FEE_RATE", 1)
    MAX_FEE_RATE = _int("MAX_FEE_RATE", 500)
    # fallback rates if the explorer is unreachable: fast / normal / economy
    FALLBACK_FEE_RATES = {"fast": 20, "normal": 8, "economy": 2}

    # --- limits ---
    MAX_CONTENT_LENGTH = 512 * 1024
    MAX_FORM_MEMORY_SIZE = 640 * 1024
    ITEMS_PER_PAGE = 25

    # auth throttling (DB-backed, so exact across worker restarts)
    LOGIN_MAX_FAILS = _int("LOGIN_MAX_FAILS", 5)
    LOGIN_LOCK_MINUTES = _int("LOGIN_LOCK_MINUTES", 15)
    LOGIN_IP_MAX_PER_10MIN = _int("LOGIN_IP_MAX_PER_10MIN", 20)
    SIGNUP_IP_MAX_PER_HOUR = _int("SIGNUP_IP_MAX_PER_HOUR", 3)   # accounts created
    SIGNUP_IP_MAX_ATTEMPTS = _int("SIGNUP_IP_MAX_ATTEMPTS", 20)  # submissions
    SEND_MAX_PER_HOUR = _int("SEND_MAX_PER_HOUR", 10)
    # coarse backstop for every state-changing request, per source IP.
    # Generous on purpose: a person never gets near it.
    GLOBAL_IP_MAX_WRITES_PER_10MIN = _int("GLOBAL_IP_MAX_WRITES_PER_10MIN", 150)

    PASSWORD_MIN_LENGTH = _int("PASSWORD_MIN_LENGTH", 10)

    # --- chain watcher ---
    SYNC_INTERVAL_SECONDS = _int("SYNC_INTERVAL_SECONDS", 60)
    SYNC_ADDRESS_DELAY_MS = _int("SYNC_ADDRESS_DELAY_MS", 250)

    # --- CSRF ---
    WTF_CSRF_SSL_STRICT = False
    WTF_CSRF_TIME_LIMIT = None

    # --- mail (password reset). Local Postfix by default. ---
    MAIL_ENABLED = _bool("MAIL_ENABLED", "1")
    MAIL_HOST = os.environ.get("MAIL_HOST", "host.docker.internal")
    MAIL_PORT = _int("MAIL_PORT", 25)
    MAIL_FROM = os.environ.get("MAIL_FROM", "vault@example.com")

    # --- misc ---
    JSON_SORT_KEYS = False
    TEMPLATES_AUTO_RELOAD = False
    AUTO_CREATE_TABLES = _bool("AUTO_CREATE_TABLES", "1")
