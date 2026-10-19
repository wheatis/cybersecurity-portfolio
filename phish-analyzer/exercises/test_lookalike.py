"""Tests for exercise 1. They fail until phishcheck/lookalike.py is implemented.

Run:  python -m unittest exercises.test_lookalike -v
When everything passes (the stretch class is optional), move this file to
tests/ so it becomes part of the normal suite.
"""
import unittest
from email.message import EmailMessage

from phishcheck import analyzer, lookalike

BRANDS = ("contoso.com", "fabrikam.com")


class NotALookalike(unittest.TestCase):
    def test_the_brand_itself_and_unrelated_hosts(self):
        hosts = (
            "contoso.com",
            "www.contoso.com",
            "login.mail.contoso.com",
            "fabrikam.com",
            "example.org",
            "contest.com",  # two letters away from "contoso": must not fire
        )
        for host in hosts:
            with self.subTest(host=host):
                self.assertIsNone(lookalike.find_lookalike(host, BRANDS))


class Lookalike(unittest.TestCase):
    CASES = {
        "c0ntoso.com": "contoso.com",                # digit instead of a letter
        "contosa.com": "contoso.com",                # one letter changed
        "contoso.net": "contoso.com",                # same name, other TLD
        "contoso-secure-login.com": "contoso.com",   # brand embedded in a longer name
        "contoso.com.evil.test": "contoso.com",      # brand domain used as a prefix
        "contoso.evil.test": "contoso.com",          # brand name as a subdomain
        "CONTOSO.NET": "contoso.com",                # case does not matter
    }

    def test_each_trick_is_detected_and_the_right_brand_is_returned(self):
        for host, brand in self.CASES.items():
            with self.subTest(host=host):
                self.assertEqual(lookalike.find_lookalike(host, BRANDS), brand)

    def test_the_right_brand_is_picked_among_several(self):
        self.assertEqual(lookalike.find_lookalike("fabrikan.com", BRANDS), "fabrikam.com")


class Stretch(unittest.TestCase):
    """Optional: these need more than plain Levenshtein distance."""

    def test_transposition(self):
        self.assertEqual(lookalike.find_lookalike("cnotoso.com", BRANDS), "contoso.com")

    def test_confusable_sequences(self):
        self.assertEqual(lookalike.find_lookalike("fabrikarn.com", BRANDS), "fabrikam.com")


class WiredIntoTheAnalyzer(unittest.TestCase):
    def analyze(self, text):
        msg = EmailMessage()
        msg["From"] = "Alice <alice@example.org>"
        msg["Subject"] = "hello"
        msg.set_content(text)
        return analyzer.analyze_message(msg)

    def test_lookalike_link_is_reported(self):
        report = self.analyze("Please sign in: https://c0ntoso.com/login")
        self.assertIn("url_lookalike", {f.rule for f in report.findings})

    def test_the_real_brand_link_is_not_reported(self):
        report = self.analyze("Please sign in: https://www.contoso.com/login")
        self.assertNotIn("url_lookalike", {f.rule for f in report.findings})


if __name__ == "__main__":
    unittest.main()
