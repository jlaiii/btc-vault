"""BTC/USD price with caching and provider failover.

Note on testnet: testnet coins have no market value. We display the real
BTC/USD rate as a *reference* conversion so amounts are readable, and the UI
labels it as such.
"""

import logging
import time

import requests

log = logging.getLogger("btcwallet.price")

CACHE_SECONDS = 60
_PROVIDERS = (
    ("coingecko",
     "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd",
     lambda d: (d.get("bitcoin") or {}).get("usd")),
    ("coinbase",
     "https://api.coinbase.com/v2/prices/BTC-USD/spot",
     lambda d: (d.get("data") or {}).get("amount")),
    ("kraken",
     "https://api.kraken.com/0/public/Ticker?pair=XBTUSD",
     lambda d: (((d.get("result") or {}).get("XXBTZUSD") or {}).get("c") or [None])[0]),
)

# in-process cache: (timestamp, price, source)
_cache = {"ts": 0.0, "price": None, "source": None}


def get_price(force: bool = False):
    """Return (price_usd, source) or (None, None) if every provider failed.

    Never raises: a price outage must not break the wallet.
    """
    now = time.time()
    if not force and _cache["price"] and (now - _cache["ts"]) < CACHE_SECONDS:
        return _cache["price"], _cache["source"]

    for name, url, extract in _PROVIDERS:
        try:
            r = requests.get(url, timeout=6, headers={"User-Agent": "btcwallet/1.0"})
            if r.status_code != 200:
                continue
            raw = extract(r.json())
            value = float(raw) if raw is not None else None
            # sanity band: a misreported price would mislead every screen
            if value and 1000 < value < 2_000_000:
                _cache.update(ts=now, price=value, source=name)
                return value, name
        except Exception as exc:
            log.warning("price provider %s failed: %s", name, exc)
    # keep serving the last good value rather than nothing
    return _cache["price"], _cache["source"]


def price_age_seconds() -> float:
    return max(0.0, time.time() - _cache["ts"]) if _cache["ts"] else 0.0
