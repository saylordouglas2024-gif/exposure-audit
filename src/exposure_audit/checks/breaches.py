"""Breach exposure via Have I Been Pwned (requires an API key: HIBP_API_KEY)."""

from __future__ import annotations

import os
import time
from urllib.parse import quote

import requests

from ..models import AuditResult, Finding, Severity

API = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"

# Data classes that make a breach notably worse for the person in it.
SENSITIVE = {"Passwords", "Physical addresses", "Phone numbers", "Dates of birth",
             "Security questions and answers", "Government issued IDs",
             "Credit cards", "Bank account numbers", "Partial credit card data"}


def run(email: str, result: AuditResult, http: requests.Session) -> None:
    key = os.environ.get("HIBP_API_KEY")
    if not key:
        result.errors.append("breaches: HIBP_API_KEY not set, breach check skipped "
                             "(get a key at haveibeenpwned.com/API/Key)")
        return

    url = API.format(quote(email)) + "?truncateResponse=false"
    for _ in range(3):
        r = http.get(url, headers={"hibp-api-key": key}, timeout=20)
        if r.status_code == 429:
            time.sleep(float(r.headers.get("retry-after", 2)))
            continue
        break

    if r.status_code == 404:
        result.add(Finding("breaches", "Not found in any known breach", Severity.INFO, email,
                           detail="Have I Been Pwned has no record of this address."))
        return
    if r.status_code != 200:
        result.errors.append(f"breaches: HIBP returned {r.status_code} for {email}")
        return

    for b in r.json():
        classes = set(b.get("DataClasses", []))
        hit = sorted(classes & SENSITIVE)
        sev = Severity.HIGH if "Passwords" in classes else Severity.MEDIUM if hit else Severity.LOW
        result.add(Finding(
            "breaches",
            f"Exposed in the {b.get('Title', b.get('Name'))} breach ({b.get('BreachDate', '?')})",
            sev, email,
            detail="Leaked data: " + ", ".join(sorted(classes)),
            url=f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name')}",
            remediation=(
                "Change the password on this site and anywhere you reused it; turn on 2FA."
                if "Passwords" in classes else
                "Be alert for phishing that uses this leaked data; you can't un-leak it, "
                "but you can make it less useful (unique passwords, 2FA, credit freeze)."
            ),
            data={"breach": b.get("Name"), "classes": sorted(classes)},
        ))
