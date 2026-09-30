"""Formatting, validation and QR helpers."""

import io
import re
from datetime import datetime, timezone

import qrcode
import qrcode.image.svg

SATS_PER_BTC = 100_000_000

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[a-zA-Z]{2,}$")


# --------------------------------------------------------------- money format
def sats_to_btc_str(sats: int) -> str:
    """1234567 -> '0.01234567' (8 dp, no float rounding anywhere)."""
    sats = int(sats or 0)
    sign = "-" if sats < 0 else ""
    sats = abs(sats)
    whole, frac = divmod(sats, SATS_PER_BTC)
    return f"{sign}{whole}.{frac:08d}"


def sats_to_btc_trim(sats: int) -> str:
    """Human display: trailing zeros removed ('0.01234567', '0.5', '0')."""
    text = sats_to_btc_str(sats)
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def btc_str_to_sats(text: str) -> int:
    """'0.01234567' -> 1234567. Raises ValueError on anything invalid."""
    if text is None:
        raise ValueError("missing amount")
    text = str(text).strip().replace(",", "").replace("_", "")
    if not text:
        raise ValueError("missing amount")
    if not re.fullmatch(r"\d{1,15}(\.\d{0,8})?", text):
        raise ValueError("Enter a valid amount (up to 8 decimal places).")
    whole, _, frac = text.partition(".")
    frac = (frac + "00000000")[:8]
    return int(whole) * SATS_PER_BTC + int(frac)


def btc_str_to_sats_signed(text: str) -> int:
    """Parse a BTC amount that MAY be negative.

    Admin balance corrections only: a user-facing amount field must use the
    strict unsigned parser above, so a negative send amount can never be
    entered through a normal form.
    """
    t = str(text if text is not None else "").strip().replace(",", "").replace("_", "")
    negative = t.startswith("-")
    if negative or t.startswith("+"):
        t = t[1:]
    value = btc_str_to_sats(t)
    return -value if negative else value


def usd_str(sats: int, price_usd) -> str:
    """USD value of a sat amount at a given BTC price."""
    if price_usd is None:
        return "—"
    value = (int(sats or 0) / SATS_PER_BTC) * float(price_usd)
    if abs(value) >= 1000:
        return f"${value:,.2f}"
    if abs(value) >= 1:
        return f"${value:,.2f}"
    return f"${value:,.4f}"


# ------------------------------------------------------------------- time
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def time_ago(dt) -> str:
    """Relative dates — Jay prefers 'today' / '3 min ago' over timestamps."""
    if not dt:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = utcnow() - dt
    secs = int(delta.total_seconds())
    if secs < 0:
        return "just now"
    if secs < 60:
        return "just now"
    if secs < 3600:
        m = secs // 60
        return f"{m} min ago"
    if secs < 86400:
        h = secs // 3600
        return f"{h} hour{'s' if h != 1 else ''} ago"
    if secs < 172800:
        return "yesterday"
    if secs < 604800:
        return f"{secs // 86400} days ago"
    return dt.strftime("%b %d, %Y")


def full_time(dt) -> str:
    if not dt:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M UTC")


# -------------------------------------------------------------------- QR
def qr_svg_data_uri(data: str) -> str:
    """Inline SVG QR code — no Pillow dependency, scales crisply on phones."""
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(data, image_factory=factory, box_size=12, border=2)
    buf = io.BytesIO()
    img.save(buf)
    svg = buf.getvalue().decode("utf-8")
    # strip the XML declaration: it is illegal inside inline HTML
    svg = svg.split("?>", 1)[-1].strip()
    from urllib.parse import quote

    return "data:image/svg+xml;charset=utf-8," + quote(svg)


# ---------------------------------------------------------------- validation
def is_valid_username(name: str) -> bool:
    return bool(name and USERNAME_RE.match(name))


def is_valid_email(addr: str) -> bool:
    return bool(addr and EMAIL_RE.match(addr))


def password_problems(password: str, username: str = "", email: str = "", min_len: int = 10):
    """Return a list of human-readable problems; empty list means acceptable."""
    problems = []
    pw = password or ""
    if len(pw) < min_len:
        problems.append(f"Use at least {min_len} characters.")
    if len(pw) > 200:
        problems.append("Too long (200 characters max).")
    classes = sum(
        [
            any(c.islower() for c in pw),
            any(c.isupper() for c in pw),
            any(c.isdigit() for c in pw),
            any(not c.isalnum() for c in pw),
        ]
    )
    if classes < 3:
        problems.append("Mix upper case, lower case, numbers or symbols (at least 3 of those).")
    low = pw.lower()
    for token in (username, email.split("@")[0] if email else ""):
        token = (token or "").strip().lower()
        if token and len(token) >= 3 and token in low:
            problems.append("Do not include your username or email in the password.")
            break
    weak = {
        "password", "password1", "passw0rd", "12345678", "123456789", "1234567890",
        "qwertyuiop", "qwerty123", "letmein", "iloveyou", "welcome", "admin123",
        "bitcoin", "bitcoin1", "satoshi", "changeme", "aaaaaaaaaa", "1qaz2wsx",
    }
    if low in weak:
        problems.append("That password is in the most-guessed list — pick another.")
    return problems


def truncate_middle(text: str, head: int = 14, tail: int = 8) -> str:
    if not text:
        return ""
    if len(text) <= head + tail + 3:
        return text
    return f"{text[:head]}…{text[-tail:]}"


def client_ip(request) -> str:
    """Real client IP behind Caddy.

    ProxyFix(x_for=1) has already unwrapped one hop, so remote_addr is the
    value Caddy appended — the actual client. We never read X-Forwarded-For
    directly here: that header is client-controlled and would let anyone
    forge a rate-limit or audit identity.
    """
    return (request.remote_addr or "unknown")[:45]
