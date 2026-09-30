"""Outbound mail. Uses the box's local Postfix (port 25) by default.

Mail is a convenience here, never a dependency: if the relay is unavailable we
log it and carry on. Nothing about signing in, sending funds or admin controls
depends on an email arriving.
"""

import logging
import smtplib
from email.message import EmailMessage

from flask import current_app

log = logging.getLogger("btcwallet.mailer")


def send_email(to_address: str, subject: str, body: str) -> bool:
    cfg = current_app.config
    if not cfg.get("MAIL_ENABLED"):
        log.info("mail disabled; would have sent %r to %s", subject, to_address)
        return False
    msg = EmailMessage()
    msg["From"] = cfg["MAIL_FROM"]
    msg["To"] = to_address
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(cfg["MAIL_HOST"], cfg["MAIL_PORT"], timeout=15) as smtp:
            smtp.ehlo()
            smtp.send_message(msg)
        log.info("sent %r to %s", subject, to_address)
        return True
    except Exception as exc:
        log.warning("could not send %r to %s: %s", subject, to_address, exc)
        return False
