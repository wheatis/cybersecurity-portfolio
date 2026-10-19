"""EXERCISE 1 (yours): detect lookalike domains.

Phishing links rarely use the real brand domain. They imitate it. Given the
host of a link and the brand domains you want to protect, decide whether the
host *imitates* a brand without *being* that brand.

    find_lookalike("c0ntoso.com")      -> "contoso.com"   (imitation)
    find_lookalike("www.contoso.com")  -> None            (the brand itself)
    find_lookalike("example.org")      -> None            (unrelated)

Tests are already written: they live in exercises/test_lookalike.py.

    python -m unittest exercises.test_lookalike -v

Work in this order, one family of tricks at a time, and let the tests tell
you when a family is done:

1. Is the host the brand itself (or one of its subdomains)? Then it is NOT a
   lookalike. Get this right first, it is the false-positive guard.
2. Same name, other TLD (contoso.net), and the brand name embedded in a longer
   name (contoso-secure-login.com).
3. The brand used as a prefix or subdomain of someone else's domain
   (contoso.com.evil.test, contoso.evil.test).
4. Small typos: digit for a letter (c0ntoso), one letter changed (contosa).
   You need an edit distance for this. Write it yourself.
5. Wire it into phishcheck/analyzer.py (rule "url_lookalike", your choice of
   points) so the last test class passes, and keep `python -m unittest`
   green: the legitimate sample must still score 0.
6. Stretch: transpositions (cnotoso) and confusable sequences ("rn" looks like
   "m"). Plain Levenshtein distance cannot see a transposition as one edit.

Why not the obvious shortcuts, so you can defend your choices:

- "host contains the brand name": flags www.contoso.com, the real thing, so
  you must exclude the brand's own domain and subdomains first.
- Edit distance alone: misses contoso-secure-login.com (distance 13) and
  contoso.com.evil.test, which are the most common real-world patterns.
- Edit distance with a loose threshold on short names: "ebay" vs "bay" would
  fire all the time. Decide a policy for short brand names and write a test
  for it.

Hint: analyzer.base_domain() already gives you the registrable domain, which
is where an attacker's typo lives.
"""
from __future__ import annotations

from typing import Iterable, Optional

# Domains you want to protect. Extend with the brands your users are exposed to.
BRANDS = ("contoso.com", "fabrikam.com")


def find_lookalike(host: str, brands: Iterable[str] = BRANDS) -> Optional[str]:
    """Return the brand domain that `host` imitates, or None."""
    raise NotImplementedError("Exercise 1: see the module docstring")
