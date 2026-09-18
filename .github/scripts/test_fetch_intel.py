#!/usr/bin/env python3
"""Unit tests for fetch_intel.py. Run: python3 .github/scripts/test_fetch_intel.py -v"""
import datetime as dt
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("fetch_intel", HERE / "fetch_intel.py")
fi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fi)


def rss(items):
    body = "".join(
        f"<item><title>{t}</title><link>{u}</link><pubDate>{d}</pubDate><description>{s}</description></item>"
        for t, u, d, s in items
    )
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>{body}</channel></rss>'.encode()


def kev(entries):
    return json.dumps({"vulnerabilities": entries}).encode()


def record(source, n, date):
    return {"source": source, "label": fi.LABELS[source], "title": f"{source} {n}",
            "url": f"https://example.test/{source}/{n}", "date": date, "summary": ""}


class Selection(unittest.TestCase):
    def test_two_per_source_then_newest_first(self):
        per_source = []
        for offset, src in enumerate(fi.SOURCES):
            per_source.append([
                record(src["id"], n, (dt.date(2026, 9, 17) - dt.timedelta(days=n * 7 + offset)).isoformat())
                for n in range(5)
            ])
        picked = fi.choose(per_source)
        self.assertEqual(len(picked), 10)
        counts = {}
        for item in picked:
            counts[item["source"]] = counts.get(item["source"], 0) + 1
        self.assertEqual(set(counts.values()), {2})
        dates = [item["date"] for item in picked]
        self.assertEqual(dates, sorted(dates, reverse=True))

    def test_short_source_frees_slots_for_others(self):
        per_source = [[record("cisa", 0, "2026-01-01")]] + [
            [record(src["id"], n, f"2026-09-{10 + n:02d}") for n in range(6)] for src in fi.SOURCES[1:]
        ]
        picked = fi.choose(per_source)
        self.assertEqual(len(picked), 10)
        self.assertEqual(sum(1 for item in picked if item["source"] == "cisa"), 1)
        self.assertEqual(picked[-1]["source"], "cisa")

    def test_fewer_than_ten_when_everything_is_short(self):
        picked = fi.choose([[record("kev", 0, "2026-09-01")], [], [], [], []])
        self.assertEqual(len(picked), 1)


class Links(unittest.TestCase):
    def test_allowlist(self):
        self.assertTrue(fi.link_ok("https://www.cisa.gov/x", ("cisa.gov",)))
        self.assertTrue(fi.link_ok("https://cisa.gov/x", ("cisa.gov",)))
        self.assertFalse(fi.link_ok("http://www.cisa.gov/x", ("cisa.gov",)))
        self.assertFalse(fi.link_ok("https://cisa.gov.evil.example/", ("cisa.gov",)))
        self.assertFalse(fi.link_ok("https://evil.example/cisa.gov", ("cisa.gov",)))
        self.assertFalse(fi.link_ok("javascript:alert(1)", ("cisa.gov",)))
        self.assertFalse(fi.link_ok("", ("cisa.gov",)))

    def test_prepare_drops_foreign_links_and_duplicates(self):
        src = fi.SOURCES[3]  # talos
        data = rss([
            ("A", "https://blog.talosintelligence.com/a/", "Wed, 16 Sep 2026 10:00:00 GMT", "one"),
            ("B", "https://attacker.example/b/", "Thu, 17 Sep 2026 10:00:00 GMT", "two"),
            ("A again", "https://blog.talosintelligence.com/a/", "Thu, 17 Sep 2026 10:00:00 GMT", "dup"),
        ])
        records = fi.prepare(src, fi.parse_rss(data))
        self.assertEqual([r["title"] for r in records], ["A"])


class Parsing(unittest.TestCase):
    def test_two_digit_year_and_zone_names(self):
        self.assertEqual(fi.parse_date("Thu, 17 Sep 26 12:00:00 +0000").date(), dt.date(2026, 9, 17))
        self.assertEqual(fi.parse_date("Fri, 04 Sep 2026 12:12:28 EDT").date(), dt.date(2026, 9, 4))
        self.assertEqual(fi.parse_date("2026-09-16").date(), dt.date(2026, 9, 16))
        self.assertIsNone(fi.parse_date("not a date"))

    def test_isc_drops_stormcast_and_strips_suffix(self):
        self.assertIsNone(fi.tidy("isc", "ISC Stormcast For Friday, September 18th, 2026", ""))
        title, _ = fi.tidy("isc", "LausivLoader analysis, or how to pass data between malware stages, (Thu, Sep 17th)", "")
        self.assertEqual(title, "LausivLoader analysis, or how to pass data between malware stages")

    def test_cisa_and_wordpress_cleanup(self):
        _, summary = fi.tidy("cisa", "t", "Advisory at a Glance Title X Original Publication May 1 Executive Summary Real text here.")
        self.assertEqual(summary, "Real text here.")
        _, summary = fi.tidy("unit42", "t", "Real text. The post Real text appeared first on Unit 42.")
        self.assertEqual(summary, "Real text.")

    def test_kev_newest_first_links_nvd_and_flags_ransomware(self):
        data = kev([
            {"cveID": "CVE-2026-0001", "vulnerabilityName": "Old Bug", "dateAdded": "2026-09-01", "shortDescription": "a"},
            {"cveID": "CVE-2026-0002", "vulnerabilityName": "New Bug", "dateAdded": "2026-09-16", "shortDescription": "b",
             "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-2026-0003", "vulnerabilityName": "Newer Same Day", "dateAdded": "2026-09-16", "shortDescription": "c"},
            {"cveID": "not-a-cve", "vulnerabilityName": "Junk", "dateAdded": "2026-09-17", "shortDescription": "d"},
        ])
        records = fi.prepare(fi.SOURCES[1], fi.parse_kev(data))
        self.assertEqual([r["title"] for r in records],
                         ["Newer Same Day (CVE-2026-0003)", "New Bug (CVE-2026-0002)", "Old Bug (CVE-2026-0001)"])
        self.assertEqual(records[0]["url"], "https://nvd.nist.gov/vuln/detail/CVE-2026-0003")
        self.assertTrue(records[1]["summary"].startswith("Known ransomware use. "))

    def test_upstream_mojibake_is_repaired(self):
        self.assertEqual(fi.clean_text("not especially remarkable â€“ it asked"), "not especially remarkable – it asked")
        self.assertEqual(fi.clean_text("cafÃ© and â€œquotedâ€\x9d"), "café and “quoted”")
        self.assertEqual(fi.clean_text("café stays, so does → and 東京"), "café stays, so does → and 東京")

    def test_snippet_truncates_on_word_boundary(self):
        text = "word " * 100
        cut = fi.truncate(text.strip(), 50)
        self.assertTrue(cut.endswith("…"))
        self.assertLessEqual(len(cut), 51)
        self.assertNotIn("wor…", cut)


class Rendering(unittest.TestCase):
    def test_escapes_untrusted_text(self):
        item = {"source": "talos", "label": "talos", "title": '<script>alert(1)</script>',
                "url": 'https://blog.talosintelligence.com/a/?q="><img src=x>', "date": "2026-09-17",
                "summary": "a & b <b>c</b>"}
        out = fi.render([item], "2026-09-18T00:00:00Z", ["kev"])
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("&quot;&gt;&lt;img", out)
        self.assertIn("a &amp; b &lt;b&gt;c&lt;/b&gt;", out)
        self.assertIn("unavailable on last check: cisa kev", out)

    def test_inject_touches_only_the_marker_region(self):
        page = f"<p>before</p>\n{fi.START}\nold rows\n{fi.END}\n<p>after</p>\n"
        out = fi.inject(page, "new rows")
        self.assertEqual(out, f"<p>before</p>\n{fi.START}\nnew rows\n{fi.END}\n<p>after</p>\n")
        with self.assertRaises(ValueError):
            fi.inject("no markers here", "x")
        with self.assertRaises(ValueError):
            fi.inject(f"{fi.START}{fi.END}{fi.START}{fi.END}", "x")


class Gathering(unittest.TestCase):
    def test_failed_source_keeps_previous_items(self):
        good = {
            fi.SOURCES[0]["url"]: rss([("CSA", "https://www.cisa.gov/a", "Fri, 04 Sep 2026 12:00:00 EDT", "s")]),
            fi.SOURCES[1]["url"]: kev([{"cveID": "CVE-2026-0001", "vulnerabilityName": "N", "dateAdded": "2026-09-16", "shortDescription": "d"}]),
            fi.SOURCES[2]["url"]: rss([("Diary, (Thu, Sep 17th)", "https://isc.sans.edu/diary/rss/1", "Thu, 17 Sep 2026 15:06:44 GMT", "s")]),
            fi.SOURCES[4]["url"]: rss([("U", "https://unit42.paloaltonetworks.com/u/", "Thu, 17 Sep 2026 22:00:33 +0000", "s")]),
        }

        def fetcher(url):
            if url not in good:
                raise OSError("connection refused")
            return good[url]

        previous = [record("talos", 1, "2026-09-10"), record("talos", 2, "2026-09-03"), record("kev", 9, "2026-01-01")]
        per_source, failed = fi.gather(fetcher, previous)
        self.assertEqual(failed, ["talos"])
        self.assertEqual([r["title"] for r in per_source[3]], ["talos 1", "talos 2"])
        self.assertEqual([r["title"] for r in per_source[1]], ["N (CVE-2026-0001)"])
        self.assertEqual(per_source[2][0]["title"], "Diary")


if __name__ == "__main__":
    unittest.main()
