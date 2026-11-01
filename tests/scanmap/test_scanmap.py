import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
import urllib.error

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "..", "scripts",
                      "sniffit-ng-scanmap.py")
spec = importlib.util.spec_from_file_location("scanmap", SCRIPT)
scanmap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanmap)

PRIVATE = "10.0.0.5"
GLOBAL = "8.8.8.8"
GLOBAL2 = "1.1.1.1"

LOG_LINES = [
    '{"ts":"2026-11-01T21:12:05.959Z","proto":"tcp","src":"8.8.8.8","sport":40000,"dst":"192.0.2.10","dport":22,"flags":"S","len":40}',
    '{"ts":"2026-11-01T21:12:06.100Z","proto":"tcp","src":"8.8.8.8","sport":40000,"dst":"192.0.2.10","dport":22,"flags":"A","len":40}',
    '{"ts":"2026-11-01T21:13:00.000Z","proto":"udp","src":"1.1.1.1","sport":5000,"dst":"192.0.2.10","dport":53,"flags":"","len":28}',
    '{"ts":"2026-11-01T21:14:00.000Z","proto":"tcp","src":"10.0.0.5","sport":1,"dst":"192.0.2.10","dport":23,"flags":"S","len":40}',
    "not json",
    '{"ts":"bad","proto":"tcp","src":"8.8.8.8","dport":22}',
    '{"ts":"2026-11-01T21:15:00.000Z","proto":"tcp","src":"999.1.1.1","dport":22,"flags":"S"}',
]

IPWHOIS = {"ip": "8.8.8.8", "success": True, "country": "United States",
           "country_code": "US", "region": "California", "city": "San Jose",
           "latitude": 37.33, "longitude": -121.89,
           "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google LLC"}}

RDAP = {
    "name": "GOGL", "handle": "NET-8-8-8-0-2", "country": "US",
    "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
    "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
    "entities": [{
        "roles": ["registrant"],
        "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
        "entities": [{
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.net"]]],
        }],
    }],
}


def write_log(directory):
    path = os.path.join(directory, "priority.jsonl")
    with open(path, "w", encoding="utf-8") as stream:
        stream.write("\n".join(LOG_LINES) + "\n")
    return path


class ParseTests(unittest.TestCase):
    def test_aggregates_and_skips_malformed(self):
        with tempfile.TemporaryDirectory() as directory:
            sources, stats = scanmap.parse_log([write_log(directory)])
        self.assertEqual(stats["malformed"], 3)
        self.assertEqual(stats["records"], 4)
        google = sources[GLOBAL]
        self.assertEqual(google["packets"], 2)
        self.assertEqual(google["syn_packets"], 1)
        self.assertEqual(google["ports"], {"22/tcp": 2})
        self.assertEqual(google["first_seen"], "2026-11-01T21:12:05.959Z")
        self.assertEqual(google["last_seen"], "2026-11-01T21:12:06.100Z")

    def test_classification_threshold(self):
        self.assertEqual(scanmap.classify({"packets": 20}, 20), "sustained")
        self.assertEqual(scanmap.classify({"packets": 3}, 20), "probe")


class SummaryTests(unittest.TestCase):
    def test_rdap_summary(self):
        summary = scanmap.summarize_rdap(RDAP)
        self.assertEqual(summary["name"], "GOGL")
        self.assertEqual(summary["cidr"], ["8.8.8.0/24"])
        self.assertEqual(summary["org"], "Google LLC")
        self.assertEqual(summary["abuse_email"], "abuse@example.net")

    def test_ipwhois_failure_raises(self):
        with self.assertRaises(ValueError):
            scanmap.summarize_ipwhois({"success": False, "message": "Invalid IP address"})


class EnricherTests(unittest.TestCase):
    def make(self, fetch, providers=("rdap", "ipwhois"), max_lookups=100, cache_path=None):
        self.sleeps = []
        cache = scanmap.Cache(cache_path, 86400.0)
        return scanmap.Enricher(list(providers), cache, fetch, max_lookups, 1.0, 5.0,
                                clock=lambda: 1000.0, sleep=self.sleeps.append)

    def test_non_global_addresses_are_never_fetched(self):
        calls = []
        enricher = self.make(lambda url, timeout: calls.append(url))
        for address in ("198.18.0.1", PRIVATE, "192.168.1.1", "127.0.0.1"):
            self.assertEqual(enricher.enrich(address), {})
        self.assertEqual(calls, [])

    def test_fetch_cache_and_rate_limit(self):
        calls = []

        def fetch(url, timeout):
            calls.append(url)
            return IPWHOIS if "ipwho.is" in url else RDAP

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cache.json")
            enricher = self.make(fetch, cache_path=path)
            result = enricher.enrich(GLOBAL)
            enricher.cache.save()
            self.assertEqual(len(calls), 2)
            self.assertEqual(result["ipwhois"]["asn"], 15169)
            self.assertEqual(len(self.sleeps), 1)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

            calls.clear()
            again = self.make(fetch, cache_path=path)
            self.assertEqual(again.enrich(GLOBAL)["rdap"]["name"], "GOGL")
            self.assertEqual(calls, [])

    def test_max_lookups_bounds_requests(self):
        calls = []
        enricher = self.make(lambda url, timeout: calls.append(url) or IPWHOIS,
                             providers=("ipwhois",), max_lookups=1)
        enricher.enrich(GLOBAL)
        enricher.enrich(GLOBAL2)
        self.assertEqual(len(calls), 1)

    def test_provider_disabled_after_repeated_failures(self):
        calls = []

        def fetch(url, timeout):
            calls.append(url)
            raise urllib.error.URLError("down")

        enricher = self.make(fetch, providers=("ipwhois",))
        for address in ("8.8.8.8", "8.8.4.4", "9.9.9.9", "1.1.1.1", "1.0.0.1"):
            self.assertEqual(enricher.enrich(address), {})
        self.assertEqual(len(calls), 3)


class MainTests(unittest.TestCase):
    def run_main(self, extra, fetch=None):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        log = write_log(directory)
        output = os.path.join(directory, "map.geojson")
        stdin = io.StringIO("")
        stdin.isatty = lambda: False
        stderr = io.StringIO()
        code = scanmap.main([log, "-o", output, "--cache", os.path.join(directory, "c.json"),
                             "--min-interval", "0"] + extra,
                            fetch=fetch or (lambda url, timeout: self.fail("network used")),
                            stdin=stdin, stderr=stderr, sleep=lambda s: None)
        data = None
        if os.path.exists(output):
            with open(output, encoding="utf-8") as stream:
                data = json.load(stream)
        return code, data, stderr.getvalue()

    def test_offline_default_makes_no_requests(self):
        code, data, _ = self.run_main([])
        self.assertEqual(code, 0)
        self.assertEqual(data["features"], [])
        self.assertEqual(len(data["unlocated"]), 3)
        self.assertEqual(data["summary"]["malformed_lines"], 3)
        self.assertIn("spoofed", data["summary"]["notice"])

    def test_lookup_requires_confirmation_when_not_a_tty(self):
        code, data, errors = self.run_main(["--lookup", "all"])
        self.assertEqual(code, 2)
        self.assertIsNone(data)
        self.assertIn("--yes", errors)

    def test_lookup_builds_geojson_point(self):
        seen = []

        def fetch(url, timeout):
            seen.append(url)
            if "ipwho.is/8.8.8.8" in url:
                return IPWHOIS
            if "rdap.org/ip/8.8.8.8" in url:
                return RDAP
            raise urllib.error.URLError("unreachable")

        code, data, _ = self.run_main(["--lookup", "all", "--yes"], fetch=fetch)
        self.assertEqual(code, 0)
        self.assertFalse(any(PRIVATE in url for url in seen))
        feature = data["features"][0]
        self.assertEqual(feature["geometry"]["coordinates"], [-121.89, 37.33])
        self.assertEqual(feature["properties"]["ip"], GLOBAL)
        self.assertEqual(feature["properties"]["org"], "Google LLC")
        self.assertEqual(feature["properties"]["rdap"]["abuse_email"], "abuse@example.net")
        self.assertEqual(data["summary"]["located"], 1)
        self.assertEqual({p["ip"] for p in data["unlocated"]}, {GLOBAL2, PRIVATE})


if __name__ == "__main__":
    unittest.main()
