import unittest
from email.message import EmailMessage
from pathlib import Path

from phishcheck import analyzer

SAMPLES = Path(__file__).parent / "samples"


def rules(report):
    return {f.rule for f in report.findings}


def finding(report, rule):
    return next(f for f in report.findings if f.rule == rule)


def make_message(plain=None, html=None, **headers):
    msg = EmailMessage()
    msg["From"] = headers.pop("From", "Alice <alice@contoso.com>")
    msg["To"] = "bob@example.org"
    msg["Subject"] = headers.pop("Subject", "hello")
    for key, value in headers.items():
        msg[key.replace("_", "-")] = value
    if plain is not None and html is not None:
        msg.set_content(plain)
        msg.add_alternative(html, subtype="html")
    elif html is not None:
        msg.set_content(html, subtype="html")
    else:
        msg.set_content(plain or "")
    return msg


class SampleEmails(unittest.TestCase):
    def test_phishing_sample_is_flagged_with_the_expected_rules(self):
        report = analyzer.analyze_file(str(SAMPLES / "phishing.eml"))
        self.assertEqual(report.verdict, "likely phishing")
        self.assertLessEqual(report.score, 100)
        expected = {
            "spf_fail", "dmarc_fail", "reply_to_mismatch", "return_path_mismatch",
            "display_name_spoof", "link_text_mismatch", "url_ip_host", "url_shortener",
            "urgent_language", "attachment_double_extension", "attachment_high_risk",
        }
        self.assertTrue(expected <= rules(report), expected - rules(report))

    def test_origin_ip_skips_private_hops(self):
        report = analyzer.analyze_file(str(SAMPLES / "phishing.eml"))
        # The earliest hop is 127.0.0.1 (skipped), the next one is the real client.
        self.assertEqual(report.origin_ip, "203.0.113.45")

    def test_attachment_is_hashed_not_executed(self):
        report = analyzer.analyze_file(str(SAMPLES / "phishing.eml"))
        (attachment,) = report.attachments
        self.assertEqual(attachment.filename, "invoice.pdf.exe")
        self.assertEqual(attachment.size, 5)  # b"hello"
        self.assertEqual(
            attachment.sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )

    def test_legitimate_newsletter_is_low_risk(self):
        report = analyzer.analyze_file(str(SAMPLES / "legitimate.eml"))
        self.assertEqual(report.verdict, "low risk")
        self.assertEqual(report.score, 0)
        self.assertEqual(report.findings, [])


class Headers(unittest.TestCase):
    def test_parse_auth_results(self):
        msg = make_message(
            plain="x",
            Authentication_Results="mx; spf=pass smtp.mailfrom=a@b; dkim=pass; dmarc=pass",
        )
        self.assertEqual(analyzer.parse_auth_results(msg),
                         {"spf": "pass", "dkim": "pass", "dmarc": "pass"})

    def test_missing_auth_results_is_reported_but_costs_nothing(self):
        report = analyzer.analyze_message(make_message(plain="hi"))
        self.assertEqual(finding(report, "auth_missing").points, 0)
        self.assertEqual(report.score, 0)

    def test_reply_to_on_another_domain(self):
        report = analyzer.analyze_message(make_message(plain="hi", Reply_To="x@freemail.test"))
        self.assertIn("reply_to_mismatch", rules(report))

    def test_display_name_with_the_same_domain_is_fine(self):
        msg = make_message(plain="hi", From='"alice@contoso.com" <alice@mail.contoso.com>')
        self.assertNotIn("display_name_spoof", rules(analyzer.analyze_message(msg)))

    def test_plain_display_name_is_fine(self):
        msg = make_message(plain="hi", From='"Dr. Jane Smith" <jane@contoso.com>')
        self.assertNotIn("display_name_spoof", rules(analyzer.analyze_message(msg)))

    def test_base_domain(self):
        self.assertEqual(analyzer.base_domain("a.b.contoso.com"), "contoso.com")
        self.assertEqual(analyzer.base_domain("mail.contoso.co.uk"), "contoso.co.uk")
        self.assertEqual(analyzer.base_domain("contoso.com"), "contoso.com")


class Links(unittest.TestCase):
    def analyze_plain(self, text):
        return analyzer.analyze_message(make_message(plain=text))

    def test_link_text_pointing_elsewhere(self):
        html = '<a href="http://evil.test/x">https://www.contoso.com/login</a>'
        report = analyzer.analyze_message(make_message(html=html))
        self.assertIn("link_text_mismatch", rules(report))

    def test_link_text_on_same_registrable_domain_is_fine(self):
        html = '<a href="https://login.contoso.com/x">https://www.contoso.com</a>'
        report = analyzer.analyze_message(make_message(html=html))
        self.assertNotIn("link_text_mismatch", rules(report))

    def test_userinfo_trick(self):
        report = self.analyze_plain("Go to http://www.contoso.com@evil.test/login now")
        self.assertIn("url_userinfo", rules(report))

    def test_punycode(self):
        self.assertIn("url_punycode", rules(self.analyze_plain("see http://xn--pypal-4ve.test/")))

    def test_shortener(self):
        self.assertIn("url_shortener", rules(self.analyze_plain("see https://bit.ly/abc")))

    def test_deep_subdomain_chain(self):
        report = self.analyze_plain("see https://login.contoso.com.secure.verify.evil-site.test/")
        self.assertIn("url_deep_subdomain", rules(report))

    def test_decimal_ip_host(self):
        self.assertIn("url_ip_host", rules(self.analyze_plain("see http://3232235777/login")))

    def test_suspicious_tld_and_http(self):
        report = self.analyze_plain("see http://contoso-login.xyz/")
        self.assertTrue({"url_suspicious_tld", "url_http"} <= rules(report))

    def test_repeated_hits_add_evidence_not_points(self):
        report = self.analyze_plain("http://a.test/ http://b.test/ http://c.test/")
        self.assertEqual(finding(report, "url_http").points, 5)
        self.assertEqual(len(finding(report, "url_http").evidence), 3)

    def test_trailing_punctuation_is_stripped(self):
        report = self.analyze_plain("Visit https://www.contoso.com/page.")
        self.assertEqual(report.urls, ["https://www.contoso.com/page"])


class Language(unittest.TestCase):
    def test_points_are_capped(self):
        text = ("urgent immediately verify your account unusual activity click here "
                "final notice act now")
        report = analyzer.analyze_message(make_message(plain=text))
        self.assertEqual(finding(report, "urgent_language").points, 15)

    def test_french_phrases(self):
        report = analyzer.analyze_message(
            make_message(plain="Votre compte a été suspendu, cliquez ici immédiatement")
        )
        self.assertIn("urgent_language", rules(report))

    def test_neutral_text_has_no_finding(self):
        report = analyzer.analyze_message(make_message(plain="Lunch at noon?"))
        self.assertNotIn("urgent_language", rules(report))


class Attachments(unittest.TestCase):
    def with_attachment(self, filename):
        msg = make_message(plain="see attached")
        msg.add_attachment(b"data", maintype="application", subtype="octet-stream",
                           filename=filename)
        return analyzer.analyze_message(msg)

    def test_plain_pdf_is_not_flagged(self):
        report = self.with_attachment("report.pdf")
        self.assertEqual([r for r in rules(report) if r.startswith("attachment")], [])

    def test_macro_document(self):
        self.assertIn("attachment_macro_or_html", rules(self.with_attachment("budget.xlsm")))

    def test_archive(self):
        self.assertIn("attachment_archive", rules(self.with_attachment("files.zip")))

    def test_double_extension(self):
        report = self.with_attachment("photo.jpg.scr")
        self.assertTrue({"attachment_double_extension", "attachment_high_risk"} <= rules(report))


class Scoring(unittest.TestCase):
    def test_thresholds(self):
        def score(points):
            return analyzer.score_findings([analyzer.Finding("r", points, "m")])

        self.assertEqual(score(19), (19, "low risk"))
        self.assertEqual(score(20), (20, "suspicious"))
        self.assertEqual(score(49), (49, "suspicious"))
        self.assertEqual(score(50), (50, "likely phishing"))
        self.assertEqual(score(250), (100, "likely phishing"))

    def test_findings_are_sorted_by_weight(self):
        report = analyzer.analyze_file(str(SAMPLES / "phishing.eml"))
        points = [f.points for f in report.findings]
        self.assertEqual(points, sorted(points, reverse=True))


if __name__ == "__main__":
    unittest.main()
