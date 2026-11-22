"""Gravatar: anyone who knows your email can hash it and pull your public profile.

This check is a good illustration of a pivot: the profile often lists a
display name, location and linked accounts, each of which leads somewhere else.
Usernames found here are fed back into the username check, because they
belong to the verified owner.
"""

from __future__ import annotations

import hashlib

import requests

from ..models import AuditResult, Finding, Severity

PROFILE = "https://gravatar.com/{}.json"


def email_hash(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()


def run(email: str, result: AuditResult, http: requests.Session) -> list[str]:
    """Returns usernames discovered on the profile, for follow-up checks."""
    h = email_hash(email)
    r = http.get(PROFILE.format(h), timeout=15)
    if r.status_code == 404:
        result.add(Finding("gravatar", "No public Gravatar profile", Severity.INFO, email))
        return []
    if r.status_code != 200:
        result.errors.append(f"gravatar: HTTP {r.status_code}")
        return []

    entries = r.json().get("entry") or []
    if not entries:
        return []
    p = entries[0]
    result.link(email, f"gravatar:{h[:10]}…", "email hash")

    exposed = []
    for label, key in (("display name", "displayName"), ("name", "name"),
                       ("location", "currentLocation"), ("bio", "aboutMe"),
                       ("job title", "job_title"), ("company", "company")):
        val = p.get(key)
        if isinstance(val, dict):
            val = val.get("formatted") or " ".join(str(v) for v in val.values() if v)
        if val:
            exposed.append(f"{label}: {val}")

    found_usernames: list[str] = []
    if p.get("preferredUsername"):
        found_usernames.append(p["preferredUsername"])
    accounts = p.get("accounts") or []
    for a in accounts:
        if a.get("username"):
            found_usernames.append(a["username"])
        result.link(email, f"{a.get('shortname', a.get('domain', 'account'))}:"
                           f"{a.get('username') or a.get('url')}", "gravatar linked account")
    for u in p.get("urls") or []:
        if u.get("value"):
            exposed.append(f"link: {u['value']}")

    sev = Severity.MEDIUM if (accounts or any(x.startswith(("location", "name")) for x in exposed)) \
        else Severity.LOW
    result.add(Finding(
        "gravatar", "Public Gravatar profile is tied to this email", sev, email,
        detail=("Anyone with your email can fetch this. It reveals: "
                + ("; ".join(exposed) if exposed else "an avatar image")
                + (f"; plus {len(accounts)} linked account(s)" if accounts else "")),
        url=p.get("profileUrl"),
        remediation="Edit or hide fields at gravatar.com, or delete the profile; "
                    "remove linked accounts you don't want connected to this email.",
        data={"hash": h},
    ))
    return sorted(set(found_usernames), key=str.lower)
