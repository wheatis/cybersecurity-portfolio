# Roadmap and progress log

## How we work

- `python -m unittest` must stay green at all times. A change without a test is not done.
- New work starts as failing tests (see `exercises/`). When they pass, move the file to `tests/`.
- Every change gets a line in the log at the bottom: date, who, what.
- Commit small, one idea per commit, message in the imperative (`Add lookalike domain detection`).

## Status

| Area | State | Owner |
| --- | --- | --- |
| Header checks (SPF/DKIM/DMARC from Authentication-Results, Reply-To, Return-Path, display-name spoofing) | done, tested | Claude |
| Link checks (IP host, shortener, punycode, userinfo, deep subdomains, link text mismatch) | done, tested | Claude |
| Attachment checks (risky and double extensions, SHA-256) | done, tested | Claude |
| Scoring and verdict | done, tested | Claude |
| VirusTotal enrichment (opt-in, mocked in tests) | done, never run against the real API | Claude |
| **Lookalike domains (exercise 1)** | **to do** | **Eddy** |

## Your turn: exercise 1, lookalike domains

1. Read the docstring of `phishcheck/lookalike.py`. It lists the families of tricks and the order to attack them.
2. Run `python -m unittest exercises.test_lookalike -v`. Everything fails: that is the starting point.
3. Implement `find_lookalike`, one family at a time, until `NotALookalike` and `Lookalike` pass.
4. Wire it into `_check_url` in `phishcheck/analyzer.py` with a rule named `url_lookalike`. Pick the points yourself and be ready to justify them.
5. Check `python -m unittest` is still green (the legitimate sample must stay at 0).
6. Optional: the `Stretch` class.
7. Move `exercises/test_lookalike.py` to `tests/`, add a log line below, commit.

## Backlog

Pick the next one when exercise 1 is done.

| Item | Difficulty | Why it is worth doing |
| --- | --- | --- |
| DMARC alignment check: compare the `header.from` and `smtp.mailfrom` domains from Authentication-Results with the From domain | easy | Shows you understand what DMARC actually enforces |
| Batch mode: analyze a folder of `.eml` files, CSV summary | easy | Real triage is done in bulk |
| Move weights and word lists out of the code into a config file | medium | Detection engineers tune rules without touching code |
| Second enrichment provider (for example AbuseIPDB on the origin IP) | medium | Shows the provider boundary is clean |
| Received-chain analysis: hop count, time jumps, mismatched HELO | medium | The part analysts read by hand |
| ECS-style JSON output so a result can be ingested by Elastic | medium | Connects the tool to a SIEM workflow |
| Evaluate precision and recall on a public phishing corpus and report it in the README | hard | The only way to know whether the weights are any good |
| QR codes in image attachments (quishing) | hard | Current, and a known gap of text-based filters |

## Log

| Date | Who | Change |
| --- | --- | --- |
| 2026-10-19 | Claude | v0.1: analyzer, VirusTotal enrichment, CLI, two sample emails, 38 tests |
| 2026-10-19 | Claude | Added exercise 1 scaffold (`lookalike.py` stub and `exercises/test_lookalike.py`) |
