# phishcheck

A small command-line tool that triages a suspicious email (`.eml`) the way a first-line SOC analyst would: it reads the authentication results, the sender, the links and the attachments, and produces a score where every point is explained. Standard library only, no dependencies. Offline by default.

## Usage

```bash
python -m phishcheck message.eml            # human-readable report
python -m phishcheck message.eml --json     # machine-readable
VT_API_KEY=... python -m phishcheck message.eml --enrich   # also look up links on VirusTotal
```

Exit code: `0` low risk, `1` suspicious, `2` likely phishing, `3` error. Useful in scripts and mail pipelines.

Try it on the two fictional samples in `tests/samples/`:

```
$ python -m phishcheck tests/samples/phishing.eml
Verdict:   LIKELY PHISHING (score 100/100)
  [+30] A link displays one domain but points to another
         shows 'https://www.contoso.com/secure/login' -> goes to http://192.0.2.77/contoso/login
  [+25] DMARC failed: the message does not align with the From domain policy
  [+20] Display name shows a different domain than the real sender address
  ...

$ python -m phishcheck tests/samples/legitimate.eml
Verdict:   LOW RISK (score 0/100)
```

## What it checks

| Area | Checks |
| --- | --- |
| Headers | SPF, DKIM and DMARC results from `Authentication-Results`; Reply-To and Return-Path on a different domain; display name showing another domain than the real sender; earliest public IP in the `Received` chain |
| Links | Raw IP or decimal-encoded host; `user@host` trick; punycode; URL shorteners; long subdomain chains; suspicious TLDs; plain HTTP; **link text showing one domain while the `href` goes to another** |
| Language | English and French urgency and account-threat phrases |
| Attachments | Executable and script types, macro-enabled Office files, HTML files, archives, double extensions such as `invoice.pdf.exe`. Files are hashed (SHA-256), never opened |
| Reputation (opt-in) | VirusTotal verdicts for the first links |

## Design choices

- **Explainable, additive score.** Each rule adds a fixed number of points and reports its evidence. Repeating a rule (ten shortened links) adds evidence, not points, so one noisy pattern cannot drown the others. The total is capped at 100. Thresholds: under 20 low risk, 20 to 49 suspicious, 50 and above likely phishing.
- **No verdict called "safe".** A heuristic can only say "no strong indicator". The report says so.
- **Offline by default.** The analyzer never touches the network. Reputation lookups live in their own module (`enrich.py`), are opt-in, and the HTTP opener is injected so tests run without network.
- **One weak signal does not condemn a message.** Return-Path on another domain is common for legitimate bulk senders, so it only weighs 5 points.
- **Missing authentication results is reported, not penalised.** Many `.eml` files are saved without the header; the tool says the check could not be done instead of guessing.

## Limitations

- `Authentication-Results` is only trustworthy if your own receiving server added it. A sender can forge that header, and this tool does not re-verify SPF, DKIM or DMARC itself.
- The registrable domain is approximated without the public suffix list. Common suffixes such as `co.uk` are handled, exotic ones are not.
- Weights are reasoned, not tuned on a labelled corpus. Precision and recall are unknown. Measuring them is on the roadmap.
- Homograph detection covers punycode only, not visually similar characters inside a Latin domain.
- No attachment content analysis and no sandboxing. No QR codes or text inside images.
- A VirusTotal lookup tells VirusTotal which URLs were in the message. The free tier allows about 4 requests per minute, hence the delay between lookups.
- The VirusTotal lookup is tested against mocks only; it has not been run against the live API.

## Tests

```bash
python -m unittest
```

Runs 38 tests, with no network. Sample emails use reserved or documentation-only domains and addresses (`.test`, `example.org`, `192.0.2.0/24`, `203.0.113.0/24`); nothing in them is real.

## Project layout

```
phishcheck/
  analyzer.py     parsing, rules, scoring (offline)
  enrich.py       VirusTotal lookups (opt-in)
  cli.py          command line and report formatting
  lookalike.py    lookalike-domain detection (exercise, see ROADMAP.md)
tests/            unit tests and sample emails
exercises/        tests that fail until the matching feature is written
ROADMAP.md        status, backlog and change log
```
