"""Search-engine queries for the user to run themselves.

We don't scrape search engines (it violates their terms and gets blocked).
Instead we build the exact queries, with links, so you can see what turns up.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from ..models import AuditResult, Finding, Severity

ENGINES = {
    "Google": "https://www.google.com/search?q={}",
    "Bing": "https://www.bing.com/search?q={}",
    "DuckDuckGo": "https://duckduckgo.com/?q={}",
}

LEAK_SITES = "site:pastebin.com OR site:github.com OR site:gist.github.com OR site:trello.com"
DOC_TYPES = "filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:csv"


def queries_for(identifier: str, kind: str, variants: list[str] | None = None) -> list[tuple[str, str]]:
    variants = variants or [identifier]
    exact = " OR ".join(f'"{v}"' for v in variants)
    qs = [
        ("Exact matches anywhere", exact),
        ("Paste / code / board sites", f"({exact}) ({LEAK_SITES})"),
        ("Documents (resumes, rosters, spreadsheets)", f"({exact}) ({DOC_TYPES})"),
    ]
    if kind == "email":
        user, _, domain = identifier.partition("@")
        qs.append(("Username part of the email", f'"{user}" -"{domain}"'))
    if kind == "phone":
        qs.append(("People-search listings", f"({exact}) (whitepages OR spokeo OR truepeoplesearch "
                                              "OR fastpeoplesearch OR \"reverse phone\")"))
    return qs


def run(identifier: str, kind: str, result: AuditResult, variants: list[str] | None = None) -> None:
    links = {}
    for label, q in queries_for(identifier, kind, variants):
        links[label] = {name: tpl.format(quote_plus(q)) for name, tpl in ENGINES.items()}
    result.add(Finding(
        "dorks", f"Search queries to run for this {kind}", Severity.INFO, identifier,
        detail="Open these yourself to see where the identifier appears publicly. Anything a "
               "search engine finds, a people-search site can index too.",
        remediation="For pages you control, edit them. For others, ask the site owner, or use "
                    "Google's 'Results about you' tool to request removal of contact details.",
        data={"links": links},
    ))
