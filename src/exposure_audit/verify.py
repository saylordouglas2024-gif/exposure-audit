"""Ownership verification: the consent gate.

Every email and phone number must be proven to belong to the person running
the audit before any check touches it. That proof is the line between a
self-audit and a lookup tool for strangers, so there is deliberately no flag
to skip it.

Email codes go out over SMTP; phone codes go through Twilio Verify. Both are
configured with environment variables (see README).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import smtplib
import time
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Callable

import requests

CODE_TTL_SECONDS = 600
MAX_ATTEMPTS = 3


class VerificationError(Exception):
    pass


@dataclass
class PendingCode:
    digest: bytes
    salt: bytes
    expires_at: float

    @classmethod
    def new(cls, code: str) -> "PendingCode":
        salt = secrets.token_bytes(16)
        return cls(_digest(code, salt), salt, time.time() + CODE_TTL_SECONDS)

    def matches(self, code: str) -> bool:
        if time.time() > self.expires_at:
            return False
        return hmac.compare_digest(self.digest, _digest(code.strip(), self.salt))


def _digest(code: str, salt: bytes) -> bytes:
    return hashlib.sha256(salt + code.encode()).digest()


def generate_code() -> str:
    return f"{secrets.randbelow(10**6):06d}"


# ---------------------------------------------------------------- email ---

def send_email_code(address: str, code: str) -> None:
    host = os.environ.get("SMTP_HOST")
    sender = os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USER")
    if not host or not sender:
        raise VerificationError(
            "Email verification needs SMTP_HOST and SMTP_FROM (or SMTP_USER) set. See README."
        )
    port = int(os.environ.get("SMTP_PORT", "587"))
    msg = EmailMessage()
    msg["Subject"] = "Your exposure-audit verification code"
    msg["From"] = sender
    msg["To"] = address
    msg.set_content(
        f"Your verification code is {code}\n\n"
        "Someone (hopefully you) is running exposure-audit on this address. "
        "If that wasn't you, ignore this message; nothing will be checked "
        "without this code."
    )
    with smtplib.SMTP(host, port, timeout=20) as s:
        s.starttls()
        user, pw = os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASS")
        if user and pw:
            s.login(user, pw)
        s.send_message(msg)


def verify_email(
    address: str,
    prompt: Callable[[str], str] = input,
    sender: Callable[[str, str], None] = send_email_code,
) -> bool:
    code = generate_code()
    pending = PendingCode.new(code)
    sender(address, code)
    del code
    for attempt in range(1, MAX_ATTEMPTS + 1):
        entered = prompt(f"Code sent to {address} (attempt {attempt}/{MAX_ATTEMPTS}): ")
        if pending.matches(entered):
            return True
    return False


# ---------------------------------------------------------------- phone ---

def _twilio() -> tuple[str, tuple[str, str]]:
    sid = os.environ.get("TWILIO_ACCOUNT_SID")
    token = os.environ.get("TWILIO_AUTH_TOKEN")
    service = os.environ.get("TWILIO_VERIFY_SID")
    if not (sid and token and service):
        raise VerificationError(
            "Phone verification needs TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and "
            "TWILIO_VERIFY_SID set. See README."
        )
    return f"https://verify.twilio.com/v2/Services/{service}", (sid, token)


def verify_phone(e164: str, prompt: Callable[[str], str] = input) -> bool:
    base, auth = _twilio()
    r = requests.post(f"{base}/Verifications", data={"To": e164, "Channel": "sms"},
                      auth=auth, timeout=20)
    if r.status_code >= 400:
        raise VerificationError(f"Twilio refused to send a code: {r.status_code} {r.text[:200]}")
    for attempt in range(1, MAX_ATTEMPTS + 1):
        entered = prompt(f"Code sent to {e164} (attempt {attempt}/{MAX_ATTEMPTS}): ").strip()
        r = requests.post(f"{base}/VerificationCheck", data={"To": e164, "Code": entered},
                          auth=auth, timeout=20)
        if r.ok and r.json().get("status") == "approved":
            return True
    return False
