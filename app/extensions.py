"""Shared extension instances (imported everywhere to avoid circular imports).

There is deliberately NO Flask-Limiter here. Rate limiting lives in
``security.throttle()``, which counts in PostgreSQL. Reasons:

* an in-memory limiter is per-worker and resets whenever the container
  restarts, so the effective limit is "whatever the attacker allows between
  deploys" — not a limit at all;
* auth throttling must be exact, and it must be shared between the web process
  and any future worker.

``security.throttle()`` gives precise per-bucket windows for the sensitive
endpoints (login, signup, 2FA, sudo, sends, faucet) and
``app.register_abuse_guard()`` applies a coarse global per-IP POST cap for
everything else.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
csrf = CSRFProtect()
