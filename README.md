# exposure-audit

**What can the public internet tie back to *you*?**

Put in your own email, phone number and usernames. exposure-audit shows how
far someone could get from those details: breaches they've leaked in, public
profiles they unlock, the accounts a reused handle links together, and the
people-search sites that probably list you. Then it tells you how to clean
each one up.

It's built to prove a point: posting "contact me at jane.doe88@…" in a bio
is a bigger deal than it looks.

## Consent is built in

The tool only audits identifiers you can prove are yours:

- **Emails** are verified with a one-time code sent over SMTP.
- **Phone numbers** are verified with an SMS code (Twilio Verify).
- **Usernames** can't be proven with a code, so they're only accepted
  alongside at least one verified email or phone, after you confirm each is yours.

There is no flag to skip verification. Codes are salted, hashed, expire after
10 minutes and allow 3 attempts. Please don't fork it to remove this. Running
it against someone else is the harm it exists to warn about, and in many
places it's illegal.

## What it checks

| Check | Input | What it shows |
|---|---|---|
| Breaches | email | Every known breach via [Have I Been Pwned](https://haveibeenpwned.com), ranked by what leaked (passwords = high) |
| Gravatar | email | The public profile anyone can fetch by hashing your email: name, location, linked accounts |
| Username reuse | username | Which of ~25 sites have an account with that handle |
| Phone metadata | phone | Region, carrier, line type and time zone, offline from numbering-plan data |
| Search queries | all | Ready-made Google/Bing/DDG queries for exact matches, paste sites and documents |
| Broker opt-outs | n/a | Search and opt-out links for the major people-search sites |

**Pivots:** usernames found on your Gravatar profile, and the local part of
your email, are added to the username check automatically. The report has a
"how your identifiers link together" section showing each hop.

The tool does **not** scrape people-search sites or search engines (that
breaks their terms and gets blocked). It gives you links to check yourself.

## Install

```bash
pip install -e ".[dev]"
```

## Configure

```bash
# Email verification (any SMTP provider; Gmail needs an app password)
export SMTP_HOST=smtp.gmail.com SMTP_PORT=587
export SMTP_USER=you@gmail.com SMTP_PASS=your-app-password SMTP_FROM=you@gmail.com

# Phone verification (optional): create a Verify service in the Twilio console
export TWILIO_ACCOUNT_SID=AC... TWILIO_AUTH_TOKEN=... TWILIO_VERIFY_SID=VA...

# Breach check (optional, paid): https://haveibeenpwned.com/API/Key
export HIBP_API_KEY=...
```

## Run

```bash
exposure-audit --email you@example.com --phone "+1 555 123 4567" --username yourhandle
```

This writes `exposure-report.html` and `exposure-report.md`, readable only by
you (mode 600). Options: `--out PATH`, `--format html|md|both`, `--region GB`.

## Limitations

- Username detection is best-effort. Sites change, rate-limit and put up bot
  challenges. Anything undecidable is listed as "couldn't determine", never
  guessed. A hit means *a* matching account exists, not that it's yours.
- Broker opt-out URLs move often. PRs welcome.
- The breach check needs a paid HIBP key; it's skipped without one.

## Adding a site

Add an entry to `src/exposure_audit/data/sites.json`:

```json
{"name": "Example", "check": "https://example.com/api/users/{}", "profile": "https://example.com/{}", "method": "status"}
```

Methods: `status` (200 = exists, 404 = doesn't), `json_not_null`,
`json_nonempty_list`, `json_path_not_null` (+ `path`), `absent_text` /
`present_text` (+ `text`). Test with a handle you know exists **and** a random
string; both must give the right answer.

## Development

```bash
pytest
```

## License

MIT
