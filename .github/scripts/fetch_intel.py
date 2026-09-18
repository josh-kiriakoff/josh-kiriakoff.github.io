#!/usr/bin/env python3
"""Refresh the intel page.

Fetches five public threat-intelligence feeds, keeps the ten newest items
across them (sources take turns, so no single feed fills the list) and writes
the result to intel/feed.json and into intel/index.html between the
intel:start and intel:end markers. Standard library only.

Exit codes: 0 ok, 1 every source failed, 2 the page or state is unusable.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "intel" / "index.html"
STATE = ROOT / "intel" / "feed.json"
START = "<!-- intel:start -->"
END = "<!-- intel:end -->"

TOTAL = 10
SNIPPET_CHARS = 220
MAX_BYTES = 8 * 1024 * 1024
TIMEOUT_SECONDS = 20
HEARTBEAT_DAYS = 30
USER_AGENT = "josh-kiriakoff.github.io intel fetcher (+https://josh-kiriakoff.github.io/intel/)"

NS = {
    "content": "http://purl.org/rss/1.0/modules/content/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "atom": "http://www.w3.org/2005/Atom",
}

SOURCES = [
    {
        "id": "cisa",
        "label": "cisa advisory",
        "kind": "rss",
        "url": "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml",
        "hosts": ("cisa.gov",),
    },
    {
        "id": "kev",
        "label": "cisa kev",
        "kind": "kev",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "hosts": ("nvd.nist.gov",),
    },
    {
        "id": "isc",
        "label": "sans isc",
        "kind": "rss",
        "url": "https://isc.sans.edu/rssfeed.xml",
        "hosts": ("isc.sans.edu",),
    },
    {
        "id": "talos",
        "label": "talos",
        "kind": "rss",
        "url": "https://blog.talosintelligence.com/rss/",
        "hosts": ("blog.talosintelligence.com",),
    },
    {
        "id": "unit42",
        "label": "unit 42",
        "kind": "rss",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "hosts": ("unit42.paloaltonetworks.com",),
    },
]
SOURCE_ORDER = {src["id"]: n for n, src in enumerate(SOURCES)}
LABELS = {src["id"]: src["label"] for src in SOURCES}

TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")
# UTF-8 text that some upstream step decoded as Windows-1252 ("â€“" where "–" was meant).
MOJIBAKE_RUN = re.compile(
    r"(?:[\u00C2\u00C3\u00E2\u00F0][\u0080-\u00FF\u0152\u0153\u0160\u0161\u0178\u017D\u017E\u0192\u02C6\u02DC"
    r"\u2013\u2014\u2018\u2019\u201A\u201C\u201D\u201E\u2020\u2021\u2022\u2026\u2030\u2039\u203A\u20AC\u2122]{1,3})+"
)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
ISC_STORMCAST = "ISC Stormcast"
ISC_SUFFIX = re.compile(
    r",?\s*\((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s*[A-Za-z]{3}\s+\d{1,2}(?:st|nd|rd|th)?\)\s*$"
)
CISA_LEAD = re.compile(r"^(?:Advisory at a Glance.*?Executive Summary|Executive Summary|Summary)\s*", re.I)
WORDPRESS_TAIL = re.compile(r"\s*The post .*? appeared first on .*?\.\s*$")


def log(message: str) -> None:
    print(message, file=sys.stderr)


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ----------------------------------------------------------------- fetching

def fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, application/json;q=0.9, */*;q=0.5",
        },
    )
    chunks: list[bytes] = []
    total = 0
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BYTES:
                raise ValueError(f"response larger than {MAX_BYTES} bytes")
            chunks.append(chunk)
    return b"".join(chunks)


def fixture_fetcher(directory: str):
    """Read feeds from DIR/<source id>.<xml|json> instead of the network."""
    by_url = {src["url"]: src for src in SOURCES}

    def read(url: str) -> bytes:
        src = by_url[url]
        ext = "json" if src["kind"] == "kev" else "xml"
        return (Path(directory) / f"{src['id']}.{ext}").read_bytes()

    return read


# ------------------------------------------------------------------ parsing

class Candidate:
    __slots__ = ("title", "url", "ts", "summary", "order")

    def __init__(self, title: str, url: str, ts: dt.datetime, summary: str, order: int) -> None:
        self.title = title
        self.url = url
        self.ts = ts
        self.summary = summary
        self.order = order


def fix_mojibake(text: str) -> str:
    def repair(match: re.Match) -> str:
        run = match.group(0)
        raw = bytearray()
        for char in run:
            try:
                raw += char.encode("cp1252")
            except UnicodeEncodeError:
                if ord(char) > 0xFF:  # not something a cp1252 decoder could have produced
                    return run
                raw.append(ord(char))  # bytes undefined in cp1252 come through as C1 controls
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return run

    return MOJIBAKE_RUN.sub(repair, text)


def clean_text(value: str | None) -> str:
    text = TAG_RE.sub(" ", value or "")
    text = fix_mojibake(html.unescape(text))
    return WS_RE.sub(" ", text).strip()


def truncate(text: str, limit: int = SNIPPET_CHARS) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:.")
    return cut + "…"


def parse_date(value: str | None) -> dt.datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    parsed = None
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        try:
            parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def parse_rss(data: bytes) -> list[Candidate]:
    root = ET.fromstring(data)
    out: list[Candidate] = []
    for item in root.iter("item"):
        ts = parse_date(item.findtext("pubDate") or item.findtext("dc:date", namespaces=NS))
        if ts is None:
            continue
        summary = item.findtext("description") or item.findtext("content:encoded", namespaces=NS)
        out.append(Candidate(
            title=clean_text(item.findtext("title")),
            url=(item.findtext("link") or "").strip(),
            ts=ts,
            summary=clean_text(summary),
            order=len(out),
        ))
    if out:
        return out
    for entry in root.iter("{%s}entry" % NS["atom"]):
        link = ""
        for candidate in entry.findall("atom:link", NS):
            if candidate.get("rel", "alternate") == "alternate" and candidate.get("href"):
                link = candidate.get("href", "")
                break
        ts = parse_date(entry.findtext("atom:published", namespaces=NS) or entry.findtext("atom:updated", namespaces=NS))
        if ts is None:
            continue
        summary = entry.findtext("atom:summary", namespaces=NS) or entry.findtext("atom:content", namespaces=NS)
        out.append(Candidate(
            title=clean_text(entry.findtext("atom:title", namespaces=NS)),
            url=link.strip(),
            ts=ts,
            summary=clean_text(summary),
            order=len(out),
        ))
    return out


def parse_kev(data: bytes) -> list[Candidate]:
    catalogue = json.loads(data)
    out: list[Candidate] = []
    for index, entry in enumerate(catalogue.get("vulnerabilities", [])):
        cve = str(entry.get("cveID", "")).strip()
        if not CVE_RE.match(cve):
            continue
        ts = parse_date(entry.get("dateAdded"))
        if ts is None:
            continue
        name = clean_text(entry.get("vulnerabilityName")) or clean_text(
            f"{entry.get('vendorProject', '')} {entry.get('product', '')}"
        )
        summary = clean_text(entry.get("shortDescription"))
        if str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known":
            summary = "Known ransomware use. " + summary
        out.append(Candidate(
            title=f"{name} ({cve})",
            url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            ts=ts,
            summary=summary,
            order=-index,  # later catalogue entries are newer within a day
        ))
    return out


# ---------------------------------------------------------------- selecting

def tidy(source_id: str, title: str, summary: str) -> tuple[str, str] | None:
    if source_id == "isc":
        if title.startswith(ISC_STORMCAST):
            return None
        title = ISC_SUFFIX.sub("", title).strip()
    elif source_id == "cisa":
        summary = CISA_LEAD.sub("", summary)
    elif source_id == "unit42":
        summary = WORDPRESS_TAIL.sub("", summary)
    return title, summary


def link_ok(url: str, hosts: tuple[str, ...]) -> bool:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parts.scheme != "https" or not parts.hostname:
        return False
    host = parts.hostname.lower()
    return any(host == allowed or host.endswith("." + allowed) for allowed in hosts)


def prepare(src: dict, candidates: list[Candidate]) -> list[dict]:
    """Tidy, validate, dedupe and order one source's items, newest first."""
    kept: list[Candidate] = []
    seen: set[str] = set()
    for cand in candidates:
        tidied = tidy(src["id"], cand.title, cand.summary)
        if tidied is None:
            continue
        cand.title, cand.summary = tidied
        if not cand.title or cand.url in seen or not link_ok(cand.url, src["hosts"]):
            continue
        seen.add(cand.url)
        kept.append(cand)
    kept.sort(key=lambda c: c.order)
    kept.sort(key=lambda c: c.ts, reverse=True)
    return [
        {
            "source": src["id"],
            "label": src["label"],
            "title": cand.title,
            "url": cand.url,
            "date": cand.ts.date().isoformat(),
            "summary": truncate(cand.summary),
        }
        for cand in kept[:TOTAL]
    ]


def gather(fetcher, previous_items: list[dict]) -> tuple[list[list[dict]], list[str]]:
    """Fetch every source. A failed source keeps its previously shown items."""
    per_source: list[list[dict]] = []
    failed: list[str] = []
    for src in SOURCES:
        try:
            data = fetcher(src["url"])
            candidates = parse_kev(data) if src["kind"] == "kev" else parse_rss(data)
            records = prepare(src, candidates)
            if not records:
                raise ValueError("no usable items")
            log(f"{src['id']}: {len(records)} items")
        except Exception as exc:  # network, parse or empty feed: keep what we had
            records = [item for item in previous_items if item.get("source") == src["id"]]
            failed.append(src["id"])
            log(f"{src['id']}: FAILED ({type(exc).__name__}: {exc}); keeping {len(records)} cached items")
        per_source.append(records)
    return per_source, failed


def choose(per_source: list[list[dict]], total: int = TOTAL) -> list[dict]:
    """Take turns across sources, newest first, then order the picks by date."""
    queues = [list(items) for items in per_source]
    picked: list[dict] = []
    while len(picked) < total and any(queues):
        for queue in queues:
            if queue and len(picked) < total:
                picked.append(queue.pop(0))
    picked.sort(key=lambda item: (SOURCE_ORDER.get(item["source"], 99), item["title"]))
    picked.sort(key=lambda item: item["date"], reverse=True)
    return picked


# ---------------------------------------------------------------- rendering

def render(items: list[dict], updated: str, failed: list[str]) -> str:
    attr = html.escape                                  # attribute values: also escape quotes
    text = lambda value: html.escape(value, quote=False)  # text nodes: & < > only
    rows: list[str] = []
    for item in items:
        row = [
            '            <div class="row">',
            f'              <a class="ttl" href="{attr(item["url"])}" rel="noopener noreferrer" target="_blank">{text(item["title"])} ↗</a>',
            f'              <span class="date">(<time datetime="{attr(item["date"])}">{text(item["date"])}</time> · {text(item["label"])})</span>',
        ]
        if item.get("summary"):
            row.append(f'              <span class="desc">{text(item["summary"])}</span>')
        row.append("            </div>")
        rows.append("\n".join(row))
    note = f"updated {updated[:10]}"
    if failed:
        note += " · unavailable on last check: " + ", ".join(LABELS.get(f, f) for f in failed)
    rows.append(f'            <span class="updated">{text(note)}</span>')
    return "\n".join(rows)


def inject(page: str, body: str) -> str:
    if page.count(START) != 1 or page.count(END) != 1:
        raise ValueError("page must contain exactly one intel:start and one intel:end marker")
    head, rest = page.split(START, 1)
    _, tail = rest.split(END, 1)
    return f"{head}{START}\n{body}\n{END}{tail}"


# --------------------------------------------------------------------- state

def load_state() -> dict:
    if not STATE.exists():
        return {}
    try:
        state = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log(f"state unreadable ({exc}); starting fresh")
        return {}
    return state if isinstance(state, dict) else {}


def last_commit_age_days() -> float | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "log", "-1", "--format=%ct"],
            capture_output=True, text=True, check=True, timeout=20,
        )
        return (time.time() - int(result.stdout.strip())) / 86400
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def write_outputs(state: dict, page: str, dry_run: bool) -> None:
    new_page = inject(page, render(state["items"], state["updated"], state["failed"]))
    if dry_run:
        print(json.dumps(state, indent=2, ensure_ascii=False))
        return
    STATE.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if new_page != page:
        PAGE.write_text(new_page, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh the intel page from its five feeds.")
    parser.add_argument("--force", action="store_true", help="write even if nothing changed (heartbeat)")
    parser.add_argument("--fixtures", metavar="DIR", help="read feeds from DIR/<source>.<xml|json> instead of the network")
    parser.add_argument("--dry-run", action="store_true", help="print the resulting state instead of writing")
    args = parser.parse_args(argv)
    force = args.force or bool(os.environ.get("INTEL_FORCE"))

    try:
        page = PAGE.read_text(encoding="utf-8")
        inject(page, "")
    except (OSError, ValueError) as exc:
        log(f"page unusable: {exc}")
        return 2

    previous = load_state()
    fetcher = fixture_fetcher(args.fixtures) if args.fixtures else fetch
    per_source, failed = gather(fetcher, previous.get("items") or [])
    items = choose(per_source)

    changed = items != previous.get("items") or failed != previous.get("failed", [])
    age = last_commit_age_days()
    heartbeat = force or (age is not None and age >= HEARTBEAT_DAYS)
    now = utcnow()

    if changed or heartbeat:
        state = {
            "updated": now if changed else (previous.get("updated") or now),
            "checked": now,
            "failed": failed,
            "items": items,
        }
        write_outputs(state, page, args.dry_run)
        reason = "content changed" if changed else ("forced" if force else f"heartbeat, last commit {age:.0f} days ago")
        log(f"{'would write' if args.dry_run else 'wrote'} {len(items)} items ({reason})")
    else:
        log("no change; nothing written")

    if len(failed) == len(SOURCES):
        log("every source failed")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
