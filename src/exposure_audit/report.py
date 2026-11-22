"""Render an AuditResult as Markdown or a self-contained HTML page."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .audit import load_brokers
from .models import AuditResult, Severity

SEV_LABEL = {Severity.HIGH: "HIGH", Severity.MEDIUM: "MEDIUM", Severity.LOW: "LOW", Severity.INFO: "info"}


def _score(r: AuditResult) -> int:
    weights = {Severity.HIGH: 10, Severity.MEDIUM: 4, Severity.LOW: 1, Severity.INFO: 0}
    return min(100, sum(weights[f.severity] for f in r.findings))


def _summary_counts(r: AuditResult) -> dict[Severity, int]:
    out = {s: 0 for s in Severity}
    for f in r.findings:
        out[f.severity] += 1
    return out


# ------------------------------------------------------------- markdown ---

def to_markdown(r: AuditResult) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    c = _summary_counts(r)
    L = [
        "# Exposure audit report", "",
        f"_Generated {now}. This report contains your personal data; store it carefully._", "",
        f"**Exposure score:** {_score(r)}/100 · "
        f"{c[Severity.HIGH]} high · {c[Severity.MEDIUM]} medium · {c[Severity.LOW]} low", "",
        "**Audited (verified):** " + ", ".join(r.emails + r.phones + r.usernames), "",
    ]
    if r.edges:
        L += ["## How your identifiers link together", "",
              "Each line is a hop someone could make starting from what you posted.", ""]
        L += [f"- `{e.source}` → `{e.target}` _(via {e.via})_" for e in r.edges]
        L.append("")

    L += ["## Findings", ""]
    for f in r.sorted_findings():
        if f.check == "dorks":
            continue
        L.append(f"### [{SEV_LABEL[f.severity]}] {f.title}")
        L.append(f"*{f.check} · `{f.identifier}`*  ")
        if f.detail:
            L.append(f.detail + "  ")
        if f.url:
            L.append(f"Link: {f.url}  ")
        for name, url in (f.data.get("profiles") or {}).items():
            L.append(f"- {name}: {url}")
        if f.remediation:
            L.append(f"\n**Fix:** {f.remediation}")
        L.append("")

    dork_findings = [f for f in r.findings if f.check == "dorks"]
    if dork_findings:
        L += ["## Search it yourself", ""]
        for f in dork_findings:
            L.append(f"**{f.identifier}**")
            for label, engines in f.data["links"].items():
                L.append(f"- {label}: " + " · ".join(f"[{n}]({u})" for n, u in engines.items()))
            L.append("")

    L += ["## Data broker opt-outs", "",
          "People-search sites join records by phone, email and address. Search yourself on "
          "each, then opt out. Expect to repeat this every few months; listings come back.", ""]
    L += [f"- **{b['name']}**: [search]({b['search']}) · [opt out]({b['optout']})" for b in load_brokers()]
    L.append("")

    if r.errors:
        L += ["## Notes", ""] + [f"- {e}" for e in r.errors] + [""]
    return "\n".join(L)


# ----------------------------------------------------------------- html ---

CSS = """
:root{--bg:#fafaf9;--fg:#1c1917;--muted:#57534e;--card:#fff;--line:#e7e5e4;
--high:#b91c1c;--med:#c2410c;--low:#a16207;--info:#57534e;--link:#1d4ed8}
@media (prefers-color-scheme:dark){:root{--bg:#1c1917;--fg:#f5f5f4;--muted:#a8a29e;--card:#292524;
--line:#44403c;--high:#f87171;--med:#fb923c;--low:#facc15;--info:#a8a29e;--link:#93c5fd}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px}
h1{margin:0 0 4px;font-size:28px}h2{margin:40px 0 12px;font-size:19px}
.muted{color:var(--muted)}a{color:var(--link)}
.score{display:flex;gap:16px;flex-wrap:wrap;margin:20px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:110px}
.tile b{display:block;font-size:26px}
.f{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--info);
border-radius:8px;padding:12px 16px;margin:10px 0}
.f.high{border-left-color:var(--high)}.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}
.tag{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.high .tag{color:var(--high)}.medium .tag{color:var(--med)}.low .tag{color:var(--low)}.info .tag{color:var(--info)}
.fix{margin-top:8px;padding-top:8px;border-top:1px dashed var(--line)}
code{font-size:13px;overflow-wrap:anywhere}ul{padding-left:20px}li{margin:3px 0}
"""


def to_html(r: AuditResult) -> str:
    e = html.escape
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    c = _summary_counts(r)
    P = [f"<!doctype html><html lang=en><head><meta charset=utf-8>"
         f"<meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>Exposure audit</title><style>{CSS}</style></head><body><main>",
         "<h1>Exposure audit report</h1>",
         f"<p class=muted>Generated {now}. This report contains your personal data; store it carefully.</p>",
         "<div class=score>",
         f"<div class=tile><b>{_score(r)}</b><span class=muted>score / 100</span></div>",
         f"<div class=tile><b>{c[Severity.HIGH]}</b><span class=muted>high</span></div>",
         f"<div class=tile><b>{c[Severity.MEDIUM]}</b><span class=muted>medium</span></div>",
         f"<div class=tile><b>{c[Severity.LOW]}</b><span class=muted>low</span></div></div>",
         "<p><b>Audited (verified):</b> " + ", ".join(f"<code>{e(x)}</code>" for x in r.emails + r.phones + r.usernames) + "</p>"]

    if r.edges:
        P.append("<h2>How your identifiers link together</h2><p class=muted>Each line is a hop "
                 "someone could make starting from what you posted.</p><ul>")
        P += [f"<li><code>{e(x.source)}</code> → <code>{e(x.target)}</code> "
              f"<span class=muted>via {e(x.via)}</span></li>" for x in r.edges]
        P.append("</ul>")

    P.append("<h2>Findings</h2>")
    for f in r.sorted_findings():
        if f.check == "dorks":
            continue
        P.append(f"<div class='f {f.severity.value}'><span class=tag>{SEV_LABEL[f.severity]}</span> "
                 f"<b>{e(f.title)}</b><div class=muted>{e(f.check)} · <code>{e(f.identifier)}</code></div>")
        if f.detail:
            P.append(f"<div>{e(f.detail)}</div>")
        if f.url:
            P.append(f"<div><a href='{e(f.url)}' rel=noopener>{e(f.url)}</a></div>")
        prof = f.data.get("profiles") or {}
        if prof:
            P.append("<ul>" + "".join(f"<li>{e(n)}: <a href='{e(u)}' rel=noopener>{e(u)}</a></li>"
                                      for n, u in prof.items()) + "</ul>")
        if f.remediation:
            P.append(f"<div class=fix><b>Fix:</b> {e(f.remediation)}</div>")
        P.append("</div>")

    dork_findings = [f for f in r.findings if f.check == "dorks"]
    if dork_findings:
        P.append("<h2>Search it yourself</h2>")
        for f in dork_findings:
            P.append(f"<p><b><code>{e(f.identifier)}</code></b></p><ul>")
            for label, engines in f.data["links"].items():
                P.append(f"<li>{e(label)}: " + " · ".join(
                    f"<a href='{e(u)}' rel=noopener>{e(n)}</a>" for n, u in engines.items()) + "</li>")
            P.append("</ul>")

    P.append("<h2>Data broker opt-outs</h2><p class=muted>People-search sites join records by phone, "
             "email and address. Search yourself on each, then opt out. Listings come back, so repeat "
             "every few months.</p><ul>")
    P += [f"<li><b>{e(b['name'])}</b>: <a href='{e(b['search'])}' rel=noopener>search</a> · "
          f"<a href='{e(b['optout'])}' rel=noopener>opt out</a></li>" for b in load_brokers()]
    P.append("</ul>")
    if r.errors:
        P.append("<h2>Notes</h2><ul>" + "".join(f"<li class=muted>{e(x)}</li>" for x in r.errors) + "</ul>")
    P.append("</main></body></html>")
    return "\n".join(P)
