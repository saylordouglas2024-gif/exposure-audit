"""Runs every check over already-verified identifiers."""

from __future__ import annotations

import json
from importlib import resources

import requests

from .checks import breaches, dorks, gravatar, phone, usernames
from .http import session
from .models import AuditResult


def load_brokers() -> list[dict]:
    return json.loads(resources.files("exposure_audit.data").joinpath("brokers.json").read_text())


def run_audit(emails: list[str], phones: list[str], handles: list[str],
              http: requests.Session | None = None, log=print) -> AuditResult:
    """All inputs must already be verified/attested by the caller (see cli.py)."""
    http = http or session()
    result = AuditResult(emails=list(emails), phones=list(phones), usernames=list(handles))

    for email in emails:
        log(f"  · breaches for {email}")
        breaches.run(email, result, http)
        log(f"  · gravatar for {email}")
        for u in gravatar.run(email, result, http):
            # Pivot: handles listed on the owner's own Gravatar are the owner's.
            if u.lower() not in {h.lower() for h in result.usernames}:
                log(f"    ↳ gravatar lists username '{u}', adding it to the username check")
                result.usernames.append(u)
                result.link(email, u, "gravatar profile")
        local = email.partition("@")[0]
        if local.lower() not in {h.lower() for h in result.usernames} and usernames.USERNAME_RE.match(local):
            result.usernames.append(local)
            result.link(email, local, "email local-part")
        dorks.run(email, "email", result)

    for e164 in phones:
        log(f"  · phone metadata for {e164}")
        phone.run(e164, result)
        dorks.run(e164, "phone", result, variants=phone.formats(e164))

    for u in result.usernames:
        log(f"  · username '{u}' across {len(usernames.load_sites())} sites")
        usernames.run(u, result, http)
        dorks.run(u, "username", result)

    return result
