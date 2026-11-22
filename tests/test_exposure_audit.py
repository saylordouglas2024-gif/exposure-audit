import json
import time

import pytest

from exposure_audit import cli, verify
from exposure_audit.audit import run_audit
from exposure_audit.checks import dorks, gravatar, phone, usernames
from exposure_audit.models import AuditResult, Severity
from exposure_audit.report import to_html, to_markdown


class FakeResp:
    def __init__(self, status=200, body=None, text=None, headers=None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else (json.dumps(body) if body is not None else "")
        self.headers = headers or {}

    def json(self):
        if self._body is None and not self.text:
            raise ValueError
        return self._body if self._body is not None else json.loads(self.text)


class FakeHTTP:
    """Maps URL substrings to responses; anything unmatched is a 404."""
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(url)
        for frag, resp in self.routes.items():
            if frag in url:
                return resp
        return FakeResp(404)


# --------------------------------------------------------- verification ---

def test_code_matches_and_expires(monkeypatch):
    p = verify.PendingCode.new("123456")
    assert p.matches("123456") and p.matches(" 123456 ")
    assert not p.matches("654321")
    monkeypatch.setattr(time, "time", lambda: p.expires_at + 1)
    assert not p.matches("123456")


def test_verify_email_accepts_right_code():
    sent = {}
    ok = verify.verify_email("me@example.com",
                             prompt=lambda _: sent["code"],
                             sender=lambda addr, code: sent.update(code=code))
    assert ok


def test_verify_email_rejects_after_max_attempts():
    tries = []
    ok = verify.verify_email("me@example.com",
                             prompt=lambda _: tries.append(1) or "000000x",
                             sender=lambda a, c: None)
    assert not ok and len(tries) == verify.MAX_ATTEMPTS


def test_cli_audits_nothing_unverified(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "verify_email", lambda e: False)
    ran = []
    monkeypatch.setattr(cli, "run_audit", lambda *a, **k: ran.append(1))
    assert cli.main(["--email", "someone@example.com", "--out", str(tmp_path / "r")]) == 1
    assert not ran


def test_cli_requires_email_or_phone():
    assert cli.main(["--username", "someone"]) == 2


def test_missing_smtp_config_is_an_error(monkeypatch):
    for k in ("SMTP_HOST", "SMTP_FROM", "SMTP_USER"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(verify.VerificationError):
        verify.send_email_code("me@example.com", "123456")


# --------------------------------------------------------------- checks ---

def test_username_probe_methods():
    http = FakeHTTP({
        "api.github.com/users/alice": FakeResp(200, {"login": "alice"}),
        "hacker-news.firebaseio.com/v0/user/alice": FakeResp(200, text="null"),
        "gitlab.com/api/v4/users?username=alice": FakeResp(200, [{"id": 1}]),
        "steamcommunity.com/id/alice": FakeResp(200, text="The specified profile could not be found"),
        "reddit.com/user/alice": FakeResp(429),
    })
    sites = {s["name"]: s for s in usernames.load_sites()}
    assert usernames.probe(sites["GitHub"], "alice", http) is True
    assert usernames.probe(sites["Hacker News"], "alice", http) is False
    assert usernames.probe(sites["GitLab"], "alice", http) is True
    assert usernames.probe(sites["Steam"], "alice", http) is False
    assert usernames.probe(sites["Reddit"], "alice", http) is None
    assert usernames.probe(sites["Codeberg"], "alice", http) is False


def test_bot_challenge_page_is_unknown_not_found():
    http = FakeHTTP({"pypi.org/user/": FakeResp(200, text="<html><title>Client Challenge</title>")})
    site = next(s for s in usernames.load_sites() if s["name"] == "PyPI")
    assert usernames.probe(site, "anyone", http) is None


def test_username_run_records_finding_and_edges():
    http = FakeHTTP({"api.github.com/users/bob": FakeResp(200, {}),
                     "codeberg.org/api/v1/users/bob": FakeResp(200, {})})
    r = AuditResult()
    usernames.run("bob", r, http, workers=2)
    f = [x for x in r.findings if x.check == "usernames"][0]
    assert "2 of" in f.title and set(f.data["profiles"]) == {"GitHub", "Codeberg"}
    assert any(e.target == "GitHub:bob" for e in r.edges)


def test_gravatar_pivots_usernames():
    h = gravatar.email_hash("Me@Example.com ")
    http = FakeHTTP({f"gravatar.com/{h}.json": FakeResp(200, {"entry": [{
        "preferredUsername": "mehandle", "displayName": "Me", "currentLocation": "Springfield",
        "accounts": [{"shortname": "github", "username": "me-gh"}],
        "profileUrl": "https://gravatar.com/mehandle"}]})})
    r = AuditResult()
    found = gravatar.run("me@example.com", r, http)
    assert found == ["me-gh", "mehandle"]
    assert r.findings[0].severity == Severity.MEDIUM
    assert "Springfield" in r.findings[0].detail


def test_phone_normalize_and_formats():
    e164 = phone.normalize("(201) 555-0123")
    assert e164 == "+12015550123"
    f = phone.formats(e164)
    assert "201-555-0123" in f and "(201) 555-0123" in f
    with pytest.raises(ValueError):
        phone.normalize("12")


def test_dorks_build_links():
    r = AuditResult()
    dorks.run("me@example.com", "email", r)
    links = r.findings[0].data["links"]
    assert "Exact matches anywhere" in links
    assert links["Exact matches anywhere"]["Google"].startswith("https://www.google.com/search?q=")


def test_breaches_skipped_without_key(monkeypatch):
    from exposure_audit.checks import breaches
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    r = AuditResult()
    breaches.run("me@example.com", r, FakeHTTP({}))
    assert r.errors and not r.findings


def test_breaches_severity(monkeypatch):
    from exposure_audit.checks import breaches
    monkeypatch.setenv("HIBP_API_KEY", "x")
    http = FakeHTTP({"haveibeenpwned.com": FakeResp(200, [
        {"Name": "A", "Title": "A", "BreachDate": "2020-01-01", "DataClasses": ["Email addresses", "Passwords"]},
        {"Name": "B", "Title": "B", "BreachDate": "2021-01-01", "DataClasses": ["Email addresses"]},
    ])})
    r = AuditResult()
    breaches.run("me@example.com", r, http)
    assert [f.severity for f in r.findings] == [Severity.HIGH, Severity.LOW]


# ---------------------------------------------------------- end-to-end ---

def test_full_audit_and_reports(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    http = FakeHTTP({"api.github.com/users/me": FakeResp(200, {})})
    r = run_audit(["me@example.com"], ["+12015550123"], [], http=http, log=lambda *_: None)
    assert "me" in r.usernames                       # pivot from email local-part
    md, page = to_markdown(r), to_html(r)
    assert "Data broker opt-outs" in md and "Spokeo" in md
    assert "<script" not in page and "Exposure audit report" in page


def test_html_escapes_untrusted_values():
    r = AuditResult(usernames=["<img src=x onerror=alert(1)>"])
    r.link("a", "<script>x</script>", "test")
    page = to_html(r)
    assert "<script>x" not in page and "&lt;script&gt;" in page
