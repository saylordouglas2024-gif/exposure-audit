"""Phone metadata, offline: what the number itself gives away (region, carrier, line type)."""

from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, number_type, PhoneNumberType, timezone

from ..models import AuditResult, Finding, Severity

TYPE_NAMES = {
    PhoneNumberType.MOBILE: "mobile", PhoneNumberType.FIXED_LINE: "landline",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "landline or mobile", PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.TOLL_FREE: "toll-free",
}


def normalize(raw: str, default_region: str = "US") -> str:
    """Return E.164 or raise ValueError."""
    try:
        n = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException as e:
        raise ValueError(f"not a phone number: {raw!r}") from e
    if not phonenumbers.is_valid_number(n):
        raise ValueError(f"not a valid phone number: {raw!r}")
    return phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)


def formats(e164: str) -> list[str]:
    """The ways a number tends to be written online, for search dorks."""
    n = phonenumbers.parse(e164)
    out = {phonenumbers.format_number(n, f) for f in (
        phonenumbers.PhoneNumberFormat.E164, phonenumbers.PhoneNumberFormat.NATIONAL,
        phonenumbers.PhoneNumberFormat.INTERNATIONAL)}
    national = str(n.national_number)
    if n.country_code == 1 and len(national) == 10:
        a, b, c = national[:3], national[3:6], national[6:]
        out |= {f"{a}-{b}-{c}", f"{a}.{b}.{c}", f"({a}) {b}-{c}", national}
    return sorted(out)


def run(e164: str, result: AuditResult) -> None:
    n = phonenumbers.parse(e164)
    region = geocoder.description_for_number(n, "en") or "unknown region"
    carr = carrier.name_for_number(n, "en") or "unknown carrier"
    kind = TYPE_NAMES.get(number_type(n), "unknown type")
    tz = ", ".join(timezone.time_zones_for_number(n))
    result.add(Finding(
        "phone", "What the number reveals by itself", Severity.LOW, e164,
        detail=(f"Region: {region}; original carrier: {carr}; line type: {kind}; "
                f"time zone(s): {tz}. This is from public numbering-plan data, so anyone "
                "can get it; carrier may be out of date if the number was ported."),
        remediation="If you post a number publicly, consider a forwarding/VoIP number "
                    "(e.g. Google Voice) instead of your real mobile, which is often the "
                    "key people-search sites use to join records.",
        data={"region": region, "carrier": carr, "type": kind},
    ))
