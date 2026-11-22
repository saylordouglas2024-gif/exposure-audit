"""Username reuse: the same handle on many sites lets anyone stitch your accounts together.

Results are best-effort. Sites change their pages, block automated requests
and rate-limit, so anything we couldn't decide is reported as "unknown"
rather than guessed.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from importlib import resources
from urllib.parse import quote

import requests

from ..models import AuditResult, Finding, Severity

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def load_sites() -> list[dict]:
    return json.loads(resources.files("exposure_audit.data").joinpath("sites.json").read_text())


# Bot-protection interstitials often come back as HTTP 200, which would read
# as "account exists" for every username. Treat them as undecidable.
CHALLENGE_MARKERS = ("<title>Client Challenge", "<title>Just a moment...",
                     "cf-challenge", "challenge-platform", "<title>Attention Required!",
                     "px-captcha", "_Incapsula_Resource")


def _looks_like_challenge(text: str) -> bool:
    head = text[:4000]
    return any(m in head for m in CHALLENGE_MARKERS)


def _dig(obj, path):
    for p in path:
        try:
            obj = obj[p]
        except (KeyError, IndexError, TypeError):
            return None
    return obj


def probe(site: dict, username: str, http: requests.Session) -> bool | None:
    """True = account exists, False = doesn't, None = couldn't tell."""
    url = site["check"].format(quote(username, safe=""))
    try:
        r = http.get(url, timeout=12, allow_redirects=True)
    except requests.RequestException:
        return None

    m = site["method"]
    if r.status_code in (403, 429) or r.status_code >= 500:
        return None
    if r.status_code == 200 and _looks_like_challenge(r.text):
        return None
    if m == "status":
        if r.status_code == 200:
            return True
        if r.status_code in (404, 410, 400):
            return False
        return None
    if r.status_code != 200:
        return False if r.status_code == 404 else None
    if m == "absent_text":
        return site["text"] not in r.text
    if m == "present_text":
        return site["text"] in r.text
    try:
        body = r.json()
    except ValueError:
        return None
    if m == "json_not_null":
        return body is not None
    if m == "json_nonempty_list":
        return isinstance(body, list) and len(body) > 0
    if m == "json_path_not_null":
        return _dig(body, site["path"]) is not None
    return None


def run(username: str, result: AuditResult, http: requests.Session,
        sites: list[dict] | None = None, workers: int = 8) -> None:
    if not USERNAME_RE.match(username):
        result.errors.append(f"usernames: skipped {username!r} (unusual characters)")
        return
    sites = sites or load_sites()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(lambda s: (s, probe(s, username, http)), sites))

    found = [s for s, ok in outcomes if ok]
    unknown = [s["name"] for s, ok in outcomes if ok is None]

    for s in found:
        result.link(username, f"{s['name']}:{username}", "same username")

    if found:
        n = len(found)
        sev = Severity.HIGH if n >= 8 else Severity.MEDIUM if n >= 3 else Severity.LOW
        result.add(Finding(
            "usernames", f"'{username}' is in use on {n} of {len(sites)} sites checked", sev,
            username,
            detail=("Accounts found (not all may be yours; check each): "
                    + ", ".join(s["name"] for s in found)
                    + ". A reused handle is a key that links these accounts, and anything "
                      "you've said in one of them, to each other."),
            remediation="Use different handles for different parts of your life, and delete "
                        "or rename old accounts you no longer use. Check each profile's bio, "
                        "location and links for details you didn't mean to share.",
            data={"profiles": {s["name"]: s["profile"].format(username) for s in found}},
        ))
    else:
        result.add(Finding("usernames", f"'{username}' not found on the sites checked",
                           Severity.INFO, username))
    if unknown:
        result.errors.append(f"usernames: couldn't determine {username!r} on: " + ", ".join(unknown))
