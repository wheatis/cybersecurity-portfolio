import json
import unittest
import urllib.error

from phishcheck import analyzer, enrich


class FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def vt_payload(malicious=0, suspicious=0):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious, "harmless": 60, "undetected": 10}}}}


def make_report(urls):
    return analyzer.Report(
        subject="s", sender="a@b.test", origin_ip=None, urls=urls, attachments=[], findings=[]
    )


class VtLookup(unittest.TestCase):
    def test_url_id_is_urlsafe_base64_without_padding(self):
        self.assertEqual(enrich.vt_url_id("http://example.com/"), "aHR0cDovL2V4YW1wbGUuY29tLw")

    def test_known_url_returns_counts_and_sends_api_key(self):
        seen = []

        def opener(request, timeout=None):
            seen.append(request)
            return FakeResponse(vt_payload(malicious=3, suspicious=1))

        result = enrich.vt_lookup("http://evil.test/", "KEY123", opener=opener)
        self.assertEqual(result, {"status": "known", "malicious": 3, "suspicious": 1})
        self.assertEqual(seen[0].get_header("X-apikey"), "KEY123")
        self.assertTrue(seen[0].full_url.endswith(enrich.vt_url_id("http://evil.test/")))

    def test_404_means_never_seen(self):
        def opener(request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

        self.assertEqual(enrich.vt_lookup("http://x.test/", "k", opener=opener),
                         {"status": "unknown"})

    def test_other_http_errors_and_network_errors_return_none(self):
        def http_429(request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {}, None)

        def offline(request, timeout=None):
            raise urllib.error.URLError("no network")

        self.assertIsNone(enrich.vt_lookup("http://x.test/", "k", opener=http_429))
        self.assertIsNone(enrich.vt_lookup("http://x.test/", "k", opener=offline))

    def test_unexpected_payload_returns_none(self):
        def opener(request, timeout=None):
            return FakeResponse({"unexpected": True})

        self.assertIsNone(enrich.vt_lookup("http://x.test/", "k", opener=opener))


class EnrichReport(unittest.TestCase):
    def test_malicious_link_raises_score_and_verdict(self):
        report = make_report(["http://ok.test/", "http://evil.test/"])
        results = {"http://ok.test/": {"status": "known", "malicious": 0, "suspicious": 0},
                   "http://evil.test/": {"status": "known", "malicious": 7, "suspicious": 0}}
        enrich.enrich_report(report, "k", delay=0, lookup=lambda url, key: results[url])
        self.assertEqual(report.score, 40)
        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.findings[0].rule, "vt_malicious")
        self.assertIn("http://evil.test/", report.findings[0].evidence[0])

    def test_max_lookups_is_respected(self):
        calls = []

        def lookup(url, key):
            calls.append(url)
            return {"status": "unknown"}

        report = make_report([f"http://{i}.test/" for i in range(10)])
        enrich.enrich_report(report, "k", max_lookups=3, delay=0, lookup=lookup)
        self.assertEqual(len(calls), 3)

    def test_failed_lookup_does_not_change_the_score(self):
        report = make_report(["http://x.test/"])
        enrich.enrich_report(report, "k", delay=0, lookup=lambda url, key: None)
        self.assertEqual(report.score, 0)
        self.assertEqual(report.enrichment, {"http://x.test/": None})

    def test_delay_between_lookups_but_not_before_the_first(self):
        sleeps = []
        report = make_report(["http://a.test/", "http://b.test/", "http://c.test/"])
        enrich.enrich_report(report, "k", delay=15, sleep=sleeps.append,
                             lookup=lambda url, key: {"status": "unknown"})
        self.assertEqual(sleeps, [15, 15])


if __name__ == "__main__":
    unittest.main()
