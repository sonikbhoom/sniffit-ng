#!/usr/bin/env python3
"""Summarize a Sniffit NG priority-port log and build a GeoJSON map of sources.

Reads the JSON Lines file written when ``priority_log`` is configured. Without
``--lookup`` it works entirely offline. With ``--lookup`` it sends the observed
source addresses to third-party services (RDAP via rdap.org and the RIR
servers it redirects to, and ipwho.is from ipwhois.io), so it asks for
confirmation first. Only globally routable IPv4 addresses are ever looked up.

Source addresses of SYN-only packets can be spoofed; treat results as
unauthenticated claims, not proof of who is scanning you.
"""

import argparse
import ipaddress
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime

CACHE_VERSION = 1
MAX_RESPONSE_BYTES = 1 << 20
RDAP_URL = "https://rdap.org/ip/{ip}"
IPWHOIS_URL = "https://ipwho.is/{ip}"
USER_AGENT = "sniffit-ng-scanmap/1.0"
NOTICE = ("Source addresses are unauthenticated claims; SYN-only traffic can "
          "be spoofed. Geolocation is approximate.")


def expand_logs(paths, include_rotated=True):
    """Return the given logs plus rotated siblings (PATH.1, PATH.2, ...), oldest first.

    Duplicates are dropped, so passing both PATH and PATH.1 never double counts.
    """
    ordered = []
    seen = set()

    def add(path):
        real = os.path.realpath(path)
        if real not in seen:
            seen.add(real)
            ordered.append(path)

    for path in paths:
        if include_rotated:
            rotated = []
            index = 1
            while os.path.isfile("%s.%d" % (path, index)):
                rotated.append("%s.%d" % (path, index))
                index += 1
            for name in reversed(rotated):
                add(name)
        add(path)
    return ordered


def parse_log(paths):
    """Aggregate log lines per source address. Returns (sources, stats)."""
    sources = {}
    stats = {"lines": 0, "records": 0, "malformed": 0}
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                stats["lines"] += 1
                record = _parse_record(line)
                if record is None:
                    stats["malformed"] += 1
                    continue
                stats["records"] += 1
                entry = sources.setdefault(record["src"], {
                    "packets": 0, "syn_packets": 0, "ports": {},
                    "first_seen": record["ts"], "last_seen": record["ts"],
                })
                entry["packets"] += 1
                if "S" in record["flags"] and "A" not in record["flags"]:
                    entry["syn_packets"] += 1
                key = "%d/%s" % (record["dport"], record["proto"])
                entry["ports"][key] = entry["ports"].get(key, 0) + 1
                entry["first_seen"] = min(entry["first_seen"], record["ts"])
                entry["last_seen"] = max(entry["last_seen"], record["ts"])
    return sources, stats


def _parse_record(line):
    try:
        data = json.loads(line)
        ts = data["ts"]
        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
        src = str(ipaddress.IPv4Address(data["src"]))
        proto = data["proto"]
        dport = int(data["dport"])
        flags = data.get("flags", "")
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None
    if proto not in ("tcp", "udp") or not 0 < dport < 65536 or not isinstance(flags, str):
        return None
    return {"ts": ts, "src": src, "proto": proto, "dport": dport, "flags": flags}


def classify(entry, sustained_packets):
    return "sustained" if entry["packets"] >= sustained_packets else "probe"


def is_lookup_candidate(address):
    return ipaddress.IPv4Address(address).is_global


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError("refusing non-HTTPS redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get_json(url, timeout):
    opener = urllib.request.build_opener(_HttpsOnlyRedirects)
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/rdap+json, application/json",
    })
    with opener.open(request, timeout=timeout) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("response too large")
    return json.loads(body.decode("utf-8"))


def _vcard_value(entity, field):
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list)):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            return item[3] if isinstance(item[3], str) else None
    return None


def _walk_entities(entities):
    for entity in entities or []:
        if isinstance(entity, dict):
            yield entity
            yield from _walk_entities(entity.get("entities"))


def summarize_rdap(data):
    """Reduce an RDAP IP network response to the fields worth keeping."""
    cidrs = []
    for block in data.get("cidr0_cidrs", []) or []:
        if isinstance(block, dict) and "v4prefix" in block and "length" in block:
            cidrs.append("%s/%s" % (block["v4prefix"], block["length"]))
    result = {
        "name": data.get("name"),
        "handle": data.get("handle"),
        "country": data.get("country"),
        "range": "%s - %s" % (data.get("startAddress"), data.get("endAddress"))
        if data.get("startAddress") else None,
        "cidr": cidrs,
        "org": None,
        "abuse_email": None,
    }
    for entity in _walk_entities(data.get("entities")):
        roles = entity.get("roles") or []
        if result["org"] is None and "registrant" in roles:
            result["org"] = _vcard_value(entity, "fn") or _vcard_value(entity, "org")
        if result["abuse_email"] is None and "abuse" in roles:
            result["abuse_email"] = _vcard_value(entity, "email")
    return result


def summarize_ipwhois(data):
    if not isinstance(data, dict) or not data.get("success"):
        raise ValueError(str(data.get("message", "lookup failed")) if isinstance(data, dict)
                         else "unexpected response")
    connection = data.get("connection") or {}
    return {
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "asn": connection.get("asn"),
        "org": connection.get("org"),
        "isp": connection.get("isp"),
    }


class Cache:
    def __init__(self, path, ttl_seconds):
        self.path = path
        self.ttl = ttl_seconds
        self.entries = {}
        self.dirty = False
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as stream:
                    data = json.load(stream)
                if data.get("version") == CACHE_VERSION and isinstance(data.get("entries"), dict):
                    self.entries = data["entries"]
            except (OSError, ValueError):
                self.entries = {}

    def get(self, provider, address, now):
        item = self.entries.get(address, {}).get(provider)
        if item and now - item.get("fetched", 0) < self.ttl:
            return item["data"]
        return None

    def put(self, provider, address, data, now):
        self.entries.setdefault(address, {})[provider] = {"fetched": now, "data": data}
        self.dirty = True

    def save(self):
        if not self.path or not self.dirty:
            return
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, mode=0o700, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=".scanmap-cache-")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump({"version": CACHE_VERSION, "entries": self.entries}, stream)
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        except BaseException:
            if os.path.exists(temporary):
                os.unlink(temporary)
            raise


class Enricher:
    """Bounded, rate-limited, cached lookups. Never contacts non-global addresses."""

    PROVIDERS = {
        "rdap": (RDAP_URL, summarize_rdap),
        "ipwhois": (IPWHOIS_URL, summarize_ipwhois),
    }

    def __init__(self, providers, cache, fetch, max_lookups, min_interval, timeout,
                 clock=time.time, sleep=time.sleep, log=lambda message: None):
        self.providers = providers
        self.cache = cache
        self.fetch = fetch
        self.remaining = max_lookups
        self.min_interval = min_interval
        self.timeout = timeout
        self.clock = clock
        self.sleep = sleep
        self.log = log
        self.last_request = None
        self.failures = {name: 0 for name in providers}
        self.network_requests = 0

    def enrich(self, address):
        result = {}
        if not is_lookup_candidate(address):
            return result
        for name in self.providers:
            cached = self.cache.get(name, address, self.clock())
            if cached is not None:
                result[name] = cached
                continue
            if self.remaining <= 0 or self.failures[name] >= 3:
                continue
            url, summarize = self.PROVIDERS[name]
            if self.last_request is not None:
                wait = self.min_interval - (self.clock() - self.last_request)
                if wait > 0:
                    self.sleep(wait)
            self.remaining -= 1
            self.last_request = self.clock()
            self.network_requests += 1
            try:
                summary = summarize(self.fetch(url.format(ip=address), self.timeout))
            except (OSError, ValueError, urllib.error.URLError) as error:
                self.failures[name] += 1
                self.log("%s lookup failed for %s: %s" % (name, address, error))
                if self.failures[name] >= 3:
                    self.log("disabling %s for this run after repeated failures" % name)
                continue
            self.failures[name] = 0
            self.cache.put(name, address, summary, self.clock())
            result[name] = summary
        return result


def build_geojson(sources, enrichment, sustained_packets, stats):
    features = []
    unlocated = []
    for address in sorted(sources, key=lambda key: (-sources[key]["packets"], key)):
        entry = sources[address]
        properties = {
            "ip": address,
            "classification": classify(entry, sustained_packets),
            "packets": entry["packets"],
            "syn_packets": entry["syn_packets"],
            "ports": dict(sorted(entry["ports"].items())),
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
        }
        details = enrichment.get(address, {})
        geo = details.get("ipwhois")
        if geo:
            for key in ("country", "region", "city", "asn", "org", "isp"):
                properties[key] = geo.get(key)
        if "rdap" in details:
            properties["rdap"] = details["rdap"]
        if (geo and isinstance(geo.get("latitude"), (int, float))
                and isinstance(geo.get("longitude"), (int, float))):
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point",
                             "coordinates": [geo["longitude"], geo["latitude"]]},
                "properties": properties,
            })
        else:
            unlocated.append(properties)
    return {
        "type": "FeatureCollection",
        "features": features,
        "unlocated": unlocated,
        "summary": {
            "sources": len(sources),
            "located": len(features),
            "records": stats["records"],
            "malformed_lines": stats["malformed"],
            "notice": NOTICE,
        },
    }


def write_text_atomic(path, text):
    if path == "-":
        sys.stdout.write(text)
        return
    directory = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=".scanmap-out-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def print_summary(collection, out):
    summary = collection["summary"]
    print("%d source(s), %d record(s), %d malformed line(s), %d located"
          % (summary["sources"], summary["records"], summary["malformed_lines"],
             summary["located"]), file=out)
    rows = [f["properties"] for f in collection["features"]] + collection["unlocated"]
    rows.sort(key=lambda row: (-row["packets"], row["ip"]))
    for row in rows[:20]:
        print("  %-15s %-9s %6d pkts  %s  %s" % (
            row["ip"], row["classification"], row["packets"],
            ",".join(row["ports"]), row.get("org") or row.get("isp") or ""), file=out)
    print(NOTICE, file=out)


def confirm_lookup(providers, count, assume_yes, stdin, stderr):
    names = {"rdap": "rdap.org (and the regional registry it redirects to)",
             "ipwhois": "ipwho.is (ipwhois.io)"}
    print("Lookup will send up to %d observed source address(es) to: %s."
          % (count, ", ".join(names[p] for p in providers)), file=stderr)
    if assume_yes:
        return True
    if not stdin.isatty():
        print("error: non-interactive lookup requires --yes", file=stderr)
        return False
    print("Continue? [y/N] ", end="", file=stderr, flush=True)
    return stdin.readline().strip().lower() in ("y", "yes")


def default_cache_path():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "sniffit-ng", "scanmap-cache.json")


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("logs", nargs="+", metavar="LOG",
                        help="priority log file(s); rotated PATH.1, PATH.2, ... are "
                             "included automatically")
    parser.add_argument("--no-rotated", action="store_true",
                        help="read only the files named, not their rotated siblings")
    parser.add_argument("-o", "--output", default="scanmap.geojson",
                        help="GeoJSON output path, or - for stdout (default: %(default)s)")
    parser.add_argument("--lookup", choices=("none", "rdap", "ipwhois", "all"),
                        default="none", help="third-party lookups (default: none, offline)")
    parser.add_argument("--yes", action="store_true",
                        help="confirm the third-party disclosure non-interactively")
    parser.add_argument("--cache", default=None,
                        help="lookup cache file (default: %s)" % default_cache_path())
    parser.add_argument("--cache-ttl-days", type=float, default=30.0)
    parser.add_argument("--max-lookups", type=int, default=100,
                        help="network requests per run (default: %(default)s)")
    parser.add_argument("--min-interval", type=float, default=1.0,
                        help="seconds between requests (default: %(default)s)")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--sustained-packets", type=int, default=20,
                        help="packets from one source that mark it sustained rather "
                             "than a probe (default: %(default)s)")
    return parser.parse_args(argv)


def main(argv=None, fetch=http_get_json, stdin=None, stderr=None,
         clock=time.time, sleep=time.sleep):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    stdin = stdin or sys.stdin
    stderr = stderr or sys.stderr
    try:
        sources, stats = parse_log(expand_logs(args.logs, not args.no_rotated))
    except OSError as error:
        print("error: %s" % error, file=stderr)
        return 1

    enrichment = {}
    if args.lookup != "none":
        providers = ["rdap", "ipwhois"] if args.lookup == "all" else [args.lookup]
        candidates = [a for a in sources if is_lookup_candidate(a)]
        if candidates:
            if not confirm_lookup(providers, min(len(candidates) * len(providers),
                                                 args.max_lookups),
                                  args.yes, stdin, stderr):
                return 2
            cache = Cache(args.cache or default_cache_path(),
                          args.cache_ttl_days * 86400.0)
            enricher = Enricher(providers, cache, fetch, args.max_lookups,
                                args.min_interval, args.timeout, clock, sleep,
                                lambda message: print(message, file=stderr))
            for address in sorted(candidates, key=lambda key: -sources[key]["packets"]):
                enrichment[address] = enricher.enrich(address)
            try:
                cache.save()
            except OSError as error:
                print("warning: could not save cache: %s" % error, file=stderr)

    collection = build_geojson(sources, enrichment, args.sustained_packets, stats)
    write_text_atomic(args.output, json.dumps(collection, indent=2) + "\n")
    print_summary(collection, stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
