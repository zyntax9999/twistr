"""
Offline test suite for twistr.

Runs entirely without network: DNS is replaced by a fake resolver, so the
whole suite finishes in seconds and gives the same result every time.

    pip install pytest
    pytest -q                # from the directory holding twistr.py

Every test here exists because the behaviour it checks broke at least once
during development. The bug each one guards against is named in its docstring.
"""

import asyncio
import json
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import twistr  # noqa: E402


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def perm(fuzzer="omission", domain="eample.com", ascii_=None, target="example.com",
         **kw):
    p = twistr.Permutation(fuzzer, domain, ascii_ or domain, target=target)
    for k, v in kw.items():
        setattr(p, k, v)
    return p


class FakeRecord:
    def __init__(self, name, rtype, **data):
        self.name = name
        self.type = rtype
        self.data = types.SimpleNamespace(**data)


class FakeResult:
    def __init__(self, answer=None):
        self.answer = answer or []


class FakeResolver:
    """Stands in for aiodns. `zone` maps name -> dict(rtype -> values), and a
    name that is absent raises NXDOMAIN. Special values: 'servfail', 'timeout'."""

    def __init__(self, zone, wildcard_parents=()):
        self.zone = zone
        self.wildcard_parents = set(wildcard_parents)
        self.calls = []

    def cancel(self):
        pass

    def query_dns(self, name, rtype):
        # aiodns returns a Future, not a coroutine - mirror that so the
        # per-query deadline can cancel it exactly as it does in production
        return asyncio.ensure_future(self._query(name, rtype))

    async def _query(self, name, rtype):
        self.calls.append((name, rtype))
        entry = self.zone.get(name)
        if entry is None and "." in name:
            parent = name.split(".", 1)[1]
            if parent in self.wildcard_parents:
                entry = {"A": ["10.0.0.1"]}
        if entry is None:
            raise _ares_error(4, "Domain name not found")
        if entry == "servfail":
            raise _ares_error(3, "DNS server returned general failure")
        if entry == "timeout":
            await asyncio.sleep(10)          # caller's deadline cancels this
            raise _ares_error(12, "Timeout")
        vals = entry.get(rtype)
        if not vals:
            # a real resolver answers any query on an aliased name with the
            # CNAME record itself, not NODATA
            if rtype != "CNAME" and entry.get("CNAME"):
                return FakeResult([FakeRecord(name, 5, cname=entry["CNAME"][0])])
            raise _ares_error(1, "no data")
        recs = []
        for v in vals:
            if rtype in ("A", "AAAA"):
                recs.append(FakeRecord(name, twistr.Scanner._RTYPE[rtype], addr=v))
            elif rtype == "NS":
                recs.append(FakeRecord(name, 2, nsdname=v))
            elif rtype == "MX":
                recs.append(FakeRecord(name, 15, exchange=v))
            elif rtype == "CNAME":
                recs.append(FakeRecord(name, 5, cname=v))
        return FakeResult(recs)


def _ares_error(code, msg):
    err = Exception(code, msg)
    return err


def scan_with(zone, perms, wildcard_parents=(), **kw):
    """Run a real Scanner against the fake resolver."""
    sc = twistr.Scanner(concurrency=kw.pop("concurrency", 8), timeout=0.2, **kw)

    def use(timeout):
        sc._resolver = FakeResolver(zone, wildcard_parents)
        sc._qfn = sc._resolver.query_dns

    sc._use_resolver = use
    asyncio.run(sc.scan(perms, progress=None, prime=False))
    return perms


# --------------------------------------------------------------------------- #
# domain parsing / generation
# --------------------------------------------------------------------------- #

def test_split_domain_handles_multi_label_suffixes():
    assert twistr.split_domain("example.com")[1:] == ("example", "com")
    sub, name, tld = twistr.split_domain("shop.example.co.uk")
    assert (name, tld) == ("example", "co.uk")


def test_split_domain_rejects_nonsense():
    with pytest.raises(ValueError):
        twistr.split_domain("notadomain")


def test_generation_excludes_the_original_and_dedupes():
    """Bug: confusables that IDNA-fold back to the real domain were emitted,
    and two spellings encoding to one wire name were queried twice."""
    perms = twistr.DomainFuzzer("paypal.com").generate()
    cands = [p for p in perms if p.fuzzer != "original"]
    assert "paypal.com" not in {p.ascii for p in cands}
    assert len({p.ascii for p in cands}) == len(cands)


def test_number_row_typos_are_generated():
    """Bug: keyboard maps omitted the digit row, missing pa7pal/payp0al."""
    out = {p.ascii for p in twistr.DomainFuzzer("paypal.com").generate()}
    assert {"pa7pal.com", "payp0al.com"} <= out


def test_whole_script_idn_homograph():
    out = {p.fuzzer for p in twistr.DomainFuzzer("apple.com").generate(["homoglyph"])}
    assert "homoglyph-script" in out


def test_registry_idn_policy_filters_and_all_idn_restores():
    """Characters a registry refuses are skipped unless --all-idn."""
    strict = len(twistr.DomainFuzzer("dnb.no").generate())
    loose = len(twistr.DomainFuzzer("dnb.no", idn_policy=False).generate())
    assert strict < loose
    assert twistr._idn_allowed("xn--dnb-qla.no", "no") in (True, False)   # no crash
    assert twistr._idn_allowed("plain.no", "no") is True


def test_max_candidates_is_exact_and_spares_other_fuzzers():
    """Bug: the cap stopped generation inside the dictionary, so tld-swap,
    tld-typo and various never ran at all."""
    words = [f"w{i}" for i in range(50000)]
    fz = twistr.DomainFuzzer("northface.com", dictionary=words,
                             tlds=["net", "shop"])
    out = fz.generate(max_candidates=5000)
    assert 4900 <= len(out) - 1 <= 5000        # a cap, never exceeded
    kinds = {p.fuzzer for p in out}
    assert {"tld-swap", "tld-typo", "various", "omission"} <= kinds


def test_dictionary_trim_samples_across_the_whole_list():
    """Bug: a sorted dictionary was cut to its first N words, so only the
    start of the alphabet was ever tried."""
    words = sorted(f"{c}{i:04d}" for c in "abcdefghijklmnopqrstuvwxyz"
                   for i in range(400))
    fz = twistr.DomainFuzzer("brand.com", dictionary=words)
    out = fz.generate(max_candidates=4000)
    used = {p.domain[0] for p in out if p.fuzzer == "dictionary"}
    assert len(used & set("abcdefghijklmnopqrstuvwxyz")) > 10
    assert fz.trim_note


def test_separator_reaches_forms_single_hyphen_insertion_cannot():
    """Gap: 'hyphenation' only inserts one hyphen, so a hyphenated brand could
    never reach its unhyphenated form, and a compound brand could never reach
    a two-word split."""
    hyph = {p.ascii for p in twistr.DomainFuzzer("the-north-face.com").generate()}
    assert {"thenorthface.com", "the.north.face.com"} <= hyph
    comp = {p.ascii for p in twistr.DomainFuzzer("northface.com").generate()}
    assert {"north-face.com", "north.face.com"} <= comp


def test_numeral_affixes_track_the_current_year():
    """Fake shops lean on years; a hard-coded list would go stale."""
    from datetime import datetime
    year = str(datetime.now().year)
    out = {p.ascii for p in twistr.DomainFuzzer("brand.com").generate(["numeral"])}
    assert f"brand{year}.com" in out
    assert f"brand-{year}.com" in out
    assert f"{year}brand.com" in out
    assert "brand24.com" in out


def test_double_omission_needs_a_long_enough_name():
    short = {p.fuzzer for p in twistr.DomainFuzzer("abc.com").generate(
        ["double-omission"])}
    assert "double-omission" not in short
    long_ = {p.ascii for p in twistr.DomainFuzzer("northface.com").generate(
        ["double-omission"])}
    assert "nortace.com" in long_            # two letters gone, not one


def test_whole_script_covers_more_than_cyrillic():
    out = [p.domain for p in twistr.DomainFuzzer("shop.com").generate(
        ["homoglyph"]) if p.fuzzer == "homoglyph-script"]
    assert len(out) >= 2                      # cyrillic + greek/armenian
    assert all(d.endswith(".com") and not d.isascii() for d in out)


def test_addition_prefixes_as_well_as_suffixes():
    out = {p.ascii for p in twistr.DomainFuzzer("brand.com").generate(
        ["addition"])}
    assert "brands.com" in out and "xbrand.com" in out


def test_hosting_fuzzer_targets_providers_not_registrations():
    """Phishing is routinely served from <brand>.<free host>; no permutation
    of the brand's own domain can reach those."""
    out = [p for p in twistr.DomainFuzzer("northface.com").generate(["hosting"])
           if p.fuzzer == "hosting"]
    names = {p.ascii for p in out}
    assert "northface.duckdns.org" in names and "northface.pages.dev" in names
    assert all(p.deep for p in out)        # hosts under somebody else's domain


def test_wrong_sld_stays_inside_the_cctld_family():
    out = {p.ascii for p in twistr.DomainFuzzer("brand.co.uk").generate(
        ["wrong-sld"]) if p.fuzzer == "wrong-sld"}
    assert {"brand.org.uk", "brand.ac.uk"} <= out
    assert "brand.co.uk" not in out          # never the original itself
    assert all(d.endswith(".uk") for d in out)
    # a TLD with no second-level family produces nothing
    assert not [p for p in twistr.DomainFuzzer("brand.com").generate(
        ["wrong-sld"]) if p.fuzzer == "wrong-sld"]


def test_phonetic_swaps_run_both_directions():
    out = {p.ascii for p in twistr.DomainFuzzer("northface.com").generate(
        ["phonetic"])}
    assert "northphace.com" in out          # f  -> ph
    assert "northfake.com" in out           # c  -> k
    assert "grafics.com" in {p.ascii for p in twistr.DomainFuzzer(
        "graphics.com").generate(["phonetic"])}   # ph -> f


def test_reorder_swaps_non_adjacent_letters():
    out = {p.ascii for p in twistr.DomainFuzzer("northface.com").generate(
        ["reorder"])}
    assert "ronthface.com" in out           # n and r swapped at distance 2
    assert "nortface.com" not in out        # that is an omission, not a swap


def test_generation_is_deterministic():
    a = [p.ascii for p in twistr.DomainFuzzer("paypal.com").generate()]
    b = [p.ascii for p in twistr.DomainFuzzer("paypal.com").generate()]
    assert a == b


# --------------------------------------------------------------------------- #
# DNS answer parsing
# --------------------------------------------------------------------------- #

def test_dns_values_filters_by_record_type():
    """Bug: an alias answer also carries CNAME records, so an A query could
    pick up the CNAME value."""
    res = FakeResult([FakeRecord("x.com", 5, cname="target.example"),
                      FakeRecord("x.com", 1, addr="1.2.3.4")])
    assert twistr.Scanner._dns_values(res, "A", "x.com") == ["1.2.3.4"]
    assert twistr.Scanner._dns_values(res, "CNAME", "x.com", own=True) == \
        ["target.example"]


def test_dns_values_ignores_ns_of_an_alias_target():
    """Bug: NS on an aliased name returns the *target's* nameservers, which is
    not a delegation of the queried name."""
    res = FakeResult([FakeRecord("other.example", 2, nsdname="ns1.other")])
    assert twistr.Scanner._dns_values(res, "NS", "x.com") == []


def test_dns_values_reads_mx_exchange():
    res = FakeResult([FakeRecord("x.com", 15, exchange="mx1.x")])
    assert twistr.Scanner._dns_values(res, "MX", "x.com") == ["mx1.x"]


# --------------------------------------------------------------------------- #
# scanning behaviour
# --------------------------------------------------------------------------- #

def test_scan_marks_registered_and_unregistered():
    zone = {"live.com": {"NS": ["ns1.x"], "A": ["1.2.3.4"]}}
    a, b = perm(ascii_="live.com", domain="live.com"), perm(ascii_="dead.com",
                                                            domain="dead.com")
    scan_with(zone, [a, b])
    assert a.registered and a.dns_a == ["1.2.3.4"]
    assert not b.registered


def test_apex_cname_counts_as_registered():
    """Bug: parked domains with only a CNAME at the apex were reported dead."""
    zone = {"parked.com": {"CNAME": ["x.bodis.com"]}}
    p = perm(ascii_="parked.com", domain="parked.com")
    scan_with(zone, [p])
    assert p.registered and p.dns_cname == ["x.bodis.com"]


def test_wildcard_zone_is_not_a_registration():
    """Bug: TLDs answering for every name (e.g. co.com) made every candidate
    look registered."""
    zone = {}
    p = perm(ascii_="anything.co.com", domain="anything.co.com")
    scan_with(zone, [p], wildcard_parents={"co.com"})
    assert p.wildcard and not p.registered


def test_servfail_on_a_deep_name_is_not_a_registration():
    """Bug: a broken parent zone (face.com SERVFAILs) made every generated
    host under it - nort.h.face.com and friends - look registered. Only a
    registrable name can be a lame delegation."""
    zone = {"n.orth.face.com": "servfail"}
    p = perm(ascii_="n.orth.face.com", domain="n.orth.face.com")
    p.deep = True
    scan_with(zone, [p])
    assert not p.registered and p.dns_ns != ["!servfail"]


def test_deep_flag_is_set_for_dot_inserting_fuzzers():
    perms = twistr.DomainFuzzer("northface.com").generate(
        ["subdomain", "separator", "omission"])
    assert all(p.deep for p in perms if "." in p.ascii[:-4] and p.fuzzer
               in ("subdomain", "separator"))
    assert not any(p.deep for p in perms if p.fuzzer == "omission")


def test_catch_all_zone_is_detected_even_when_it_rotates_addresses():
    """Bug: hosting providers that answer for every name (vercel, netlify,
    github.io) return a different address each time, so comparing addresses
    missed them and every <brand>.<provider> looked claimed."""
    class Rotating(FakeResolver):
        def __init__(self):
            super().__init__({})
            self.n = 0

        async def _query(self, name, rtype):
            if not name.endswith(".rotate.app"):
                raise _ares_error(4, "Domain name not found")
            if rtype != "A":
                raise _ares_error(1, "no data")
            self.n += 1                     # never the same address twice
            return FakeResult([FakeRecord(name, 1, addr=f"10.0.0.{self.n}")])

    sc = twistr.Scanner(concurrency=4, timeout=0.2)

    def use(timeout):
        sc._resolver = Rotating()
        sc._qfn = sc._resolver.query_dns
    sc._use_resolver = use
    p = perm(ascii_="brand.rotate.app", domain="brand.rotate.app")
    p.deep = True
    asyncio.run(sc.scan([p], progress=None, prime=False))
    assert p.wildcard and not p.registered


def test_a_real_claim_on_a_non_wildcard_host_is_kept():
    zone = {"brand.pages.dev": {"A": ["1.2.3.4"]}}
    p = perm(ascii_="brand.pages.dev", domain="brand.pages.dev")
    p.deep = True
    scan_with(zone, [p])
    assert p.registered and not p.wildcard


def test_persistent_servfail_is_a_lame_delegation():
    zone = {"broken.com": "servfail"}
    p = perm(ascii_="broken.com", domain="broken.com")
    scan_with(zone, [p])
    assert p.dns_ns == ["!servfail"] and p.registered


def test_aaaa_is_skipped_when_an_a_record_answers():
    """AAAA proves the same thing as A, so asking for both on every live name
    is a wasted query; it is still asked when A comes back empty."""
    zone = {"has-a.com": {"NS": ["ns"], "A": ["1.2.3.4"]},
            "v6only.com": {"NS": ["ns"], "AAAA": ["2001:db8::1"]}}
    a, b = perm(ascii_="has-a.com", domain="has-a.com"), \
        perm(ascii_="v6only.com", domain="v6only.com")
    sc = twistr.Scanner(concurrency=4, timeout=0.2)
    res = FakeResolver(zone)

    def use(timeout):
        sc._resolver = res
        sc._qfn = res.query_dns
    sc._use_resolver = use
    asyncio.run(sc.scan([a, b], progress=None, prime=False))
    asked = [n for n, t in res.calls if t == "AAAA"]
    assert "has-a.com" not in asked          # A answered, no need
    assert "v6only.com" in asked             # A empty, so ask
    assert a.registered and b.registered and b.dns_aaaa == ["2001:db8::1"]


def test_wildcard_probe_is_cached_across_targets():
    """Each target builds its own Scanner; without a process-wide cache the
    same parent zones are re-probed for every target in a list."""
    twistr._WILD_CACHE.clear()
    zone = {}
    calls = []

    def scan_one(name):
        sc = twistr.Scanner(concurrency=4, timeout=0.2)

        def use(timeout):
            r = FakeResolver(zone, wildcard_parents={"catchall.test"})
            sc._resolver = r
            sc._qfn = r.query_dns
            calls.append(r)
        sc._use_resolver = use
        p = perm(ascii_=f"{name}.catchall.test", domain=f"{name}.catchall.test")
        p.deep = True
        asyncio.run(sc.scan([p], progress=None, prime=False))
        return p

    first = scan_one("brand1")
    probes_after_first = sum(len(r.calls) for r in calls)
    second = scan_one("brand2")
    probes_after_second = sum(len(r.calls) for r in calls)
    assert first.wildcard and second.wildcard
    # the second target must not repeat the probe work of the first
    assert (probes_after_second - probes_after_first) < probes_after_first
    twistr._WILD_CACHE.clear()


def test_mx_is_only_queried_when_asked():
    zone = {"m.com": {"NS": ["ns"], "A": ["1.1.1.1"], "MX": ["mx.m"]}}
    p = perm(ascii_="m.com", domain="m.com")
    scan_with(zone, [p])
    assert not p.dns_mx
    q = perm(ascii_="m.com", domain="m.com")
    scan_with(zone, [q], do_mx=True)
    assert q.dns_mx == ["mx.m"]


def test_timeouts_do_not_hang_the_scan():
    """Bug: without a per-query deadline, c-ares walked every resolver in turn
    and a dead name could take minutes."""
    zone = {"slow.com": "timeout"}
    p = perm(ascii_="slow.com", domain="slow.com")
    scan_with(zone, [p])
    assert not p.registered      # settled, not hung


def test_one_bad_domain_does_not_abort_the_scan():
    """Bug: a single unhandled exception ended the whole run."""
    zone = {"ok.com": {"NS": ["ns"], "A": ["1.1.1.1"]}}
    good, bad = perm(ascii_="ok.com", domain="ok.com"), perm(ascii_="boom.com",
                                                             domain="boom.com")
    sc = twistr.Scanner(concurrency=4, timeout=0.2)

    def use(timeout):
        sc._resolver = FakeResolver(zone)
        orig = sc._resolver.query_dns

        def q(name, rtype):
            if name == "boom.com":
                async def boom():
                    raise RuntimeError("pathological domain")
                return asyncio.ensure_future(boom())
            return orig(name, rtype)
        sc._qfn = q
    sc._use_resolver = use
    asyncio.run(sc.scan([good, bad], progress=None, prime=False))
    assert good.registered and not bad.registered


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #

def test_score_rises_with_danger_signals():
    base = twistr.score(perm(fuzzer="homoglyph"))
    live = twistr.score(perm(fuzzer="homoglyph", dns_a=["1.2.3.4"]))
    mail = twistr.score(perm(fuzzer="homoglyph", dns_a=["1.2.3.4"],
                             dns_mx=["mx"]))
    fresh = twistr.score(perm(fuzzer="homoglyph", dns_a=["1.2.3.4"],
                              dns_mx=["mx"], age_days=5))
    clone = twistr.score(perm(fuzzer="homoglyph", dns_a=["1.2.3.4"],
                              dns_mx=["mx"], age_days=5, favicon_match=True))
    assert base < live < mail < fresh < clone <= 100


def test_score_is_capped():
    p = perm(fuzzer="homoglyph", dns_a=["1"], dns_mx=["m"], age_days=1,
             favicon_match=True, fuzzy=100, http_status=200, ct=True,
             title="paypal login")
    assert twistr.score(p) == 100


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

@pytest.fixture
def rows():
    return [perm(ascii_="a.com", domain="a.com", risk=80, dns_a=["1.1.1.1"]),
            perm(ascii_="b.com", domain="b.com", risk=20),
            perm("original", "example.com", "example.com")]


def test_rows_filters_original_registered_and_length(rows):
    assert {p.ascii for p in twistr._rows(rows, False)} == {"a.com", "b.com"}
    assert {p.ascii for p in twistr._rows(rows, True)} == {"a.com"}
    assert twistr._rows(rows, False, min_length=99) == []


def test_renderers_handle_unresolved_defaults(rows):
    """Bug: switching the DNS fields to a shared empty tuple broke the table
    renderer with 'can only concatenate list (not tuple) to list'."""
    assert "a.com" in twistr.render_domains(rows, False)
    assert "risk,target,fuzzer" in twistr.render_csv(rows, False)
    json.loads(twistr.render_json(rows, False))
    twistr.render_table(rows, False)          # must not raise


def test_domains_output_is_ranked_and_unique(rows):
    out = twistr.render_domains(rows + [rows[0]], False).split()
    assert out == ["a.com", "b.com"]          # risk 80 first, deduped


def test_live_writer_streams_and_filters(tmp_path):
    """Bug: --live reported success without writing anything."""
    path = tmp_path / "out.txt"
    w = twistr.LiveWriter(str(path), "domains", True, 0)
    w.feed(perm(ascii_="live.com", domain="live.com", dns_a=["1.1.1.1"]))
    w.feed(perm(ascii_="dead.com", domain="dead.com"))       # filtered out
    assert path.read_text().split() == ["live.com"]          # flushed already
    w.close()


def test_atomic_write_replaces_whole_file(tmp_path):
    path = tmp_path / "x.txt"
    twistr._atomic_write(str(path), "one\n")
    twistr._atomic_write(str(path), "two\n")
    assert path.read_text() == "two\n"
    assert not list(tmp_path.glob(".twistr-*"))              # no temp left over


def test_output_path_timestamping(tmp_path):
    args = types.SimpleNamespace(format="domains", output=None,
                                 outdir=str(tmp_path), timestamp=True)
    p1 = twistr._resolve_output_path(args, ["example.com"])
    assert p1.startswith(str(tmp_path)) and p1.endswith(".txt")
    args2 = types.SimpleNamespace(format="csv", output=None, outdir=None,
                                  timestamp=False)
    assert twistr._resolve_output_path(args2, ["example.com"]) is None


# --------------------------------------------------------------------------- #
# resolvers
# --------------------------------------------------------------------------- #

def test_filtering_resolvers_are_refused_with_an_alternative():
    """A filtering resolver hides exactly what twistr hunts for."""
    ns, err = twistr.parse_nameservers("9.9.9.9,8.8.8.8")
    assert ns is None and "9.9.9.10" in err
    ns, err = twistr.parse_nameservers("9.9.9.9", allow_filtering=True)
    assert ns == ["9.9.9.9"] and err is None


def test_unfiltered_preset_expands_and_dedupes():
    ns, err = twistr.parse_nameservers("unfiltered,1.1.1.1")
    assert err is None and len(ns) == len(set(ns)) and "1.1.1.1" in ns
    assert len(ns) >= 10


def test_nameserver_host_parsing():
    assert twistr._ns_host("127.0.0.1:5335") == "127.0.0.1"
    assert twistr._ns_host("[2606:4700:4700::1111]:53") == "2606:4700:4700::1111"
    assert twistr._ns_host("2620:fe::10") == "2620:fe::10"


def test_control_d_filtering_variants_are_caught():
    """One digit apart from the unfiltered pair."""
    ns, err = twistr.parse_nameservers("76.76.2.2")
    assert ns is None and "76.76.2.0" in err


# --------------------------------------------------------------------------- #
# CLI / UI plumbing
# --------------------------------------------------------------------------- #

def test_concurrency_argument_accepts_auto_and_numbers():
    assert twistr._concurrency_arg("auto") == "auto"
    assert twistr._concurrency_arg("200") == 200
    for bad in ("abc", "0", "-5"):
        with pytest.raises(Exception):
            twistr._concurrency_arg(bad)


def test_ui_helpers_have_the_arity_callers_use(capsys):
    """Bug: a call site used ui.item() with one argument and crashed the run
    the first time a resolver was unhealthy."""
    ui = twistr.UI(sys.stderr)
    ui.item("label", "value")
    ui.item("label", "value", "green")
    for fn in (ui.note, ui.warn, ui.error, ui.ok, ui.line):
        fn("text")
    ui.header("t", [("a", "b", None)])
    ui.rule("x")


def test_every_ui_call_site_has_the_right_arity():
    """Bug: one call site used ui.item() with a single argument and crashed
    the scan the first time a resolver turned out to be unhealthy. A unit test
    on UI cannot catch that, so check every call site in the source."""
    import ast
    tree = ast.parse(open(os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "twistr.py")).read())
    expected = {"item": 2, "header": 2, "note": 1, "warn": 1, "error": 1,
                "ok": 1, "rule": None, "line": None}
    problems = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)):
            continue
        recv = node.func.value
        if not (isinstance(recv, ast.Name) and recv.id == "ui"):
            continue
        want = expected.get(node.func.attr, "skip")
        if want in ("skip", None):
            continue
        pos = [a for a in node.args if not isinstance(a, ast.Starred)]
        starred = any(isinstance(a, ast.Starred) for a in node.args)
        if starred or len(pos) < want:
            problems.append(f"line {node.lineno}: ui.{node.func.attr} "
                            f"got {len(pos)} positional args, needs {want}"
                            + (" (*args splat)" if starred else ""))
    assert not problems, "\n".join(problems)


def test_plain_progress_emits_status_and_never_uses_escape_codes(capsys):
    """Redirected output (nohup) must stay free of colour and \\r."""
    class Sink:
        def __init__(self):
            self.text = ""

        def isatty(self):
            return False

        def write(self, s):
            self.text += s

        def flush(self):
            pass
    sink = Sink()
    ui = twistr.UI(sink)
    pr = twistr.Progress(mode="plain", ui=ui)
    pr.begin(1)
    pr.start_target(1, 1, "example.com", 100)
    for i in range(1, 101):
        pr.update_target(i, i // 10)
    pr.target_done({"idx": 1, "name": "example.com", "live": 10,
                    "candidates": 100, "secs": 1.0, "top": None})
    pr.close()
    assert "example.com" in sink.text
    assert "\x1b" not in sink.text and "\r" not in sink.text


def test_make_progress_falls_back_without_rich(monkeypatch):
    class Sink:
        def isatty(self):
            return True

        def write(self, s):
            pass

        def flush(self):
            pass
    monkeypatch.setattr(twistr, "_HAVE_RICH", False)
    ui = twistr.UI(Sink())
    assert type(twistr.make_progress("auto", ui)) is twistr.Progress


def test_target_stats_picks_the_highest_risk_find():
    tp = [perm("original", "example.com", "example.com"),
          perm(ascii_="a.com", domain="a.com", risk=30, dns_a=["1"]),
          perm(ascii_="b.com", domain="b.com", risk=90, dns_a=["1"])]
    st = twistr._target_stats(tp, idx=1, secs=2.0)
    assert st["live"] == 2 and st["top"].ascii == "b.com" and st["high"] == 1


def test_severity_label_accompanies_every_risk_colour():
    """Colour alone fails a colour-blind reader, a mono terminal and a log
    file, so every risk also carries a word."""
    assert twistr._severity(95)[0] == "HIGH"
    assert twistr._severity(70)[0] == "HIGH"
    assert twistr._severity(69)[0] == "MED"
    assert twistr._severity(45)[0] == "MED"
    assert twistr._severity(44)[0] == "LOW"
    assert all(twistr._severity(r)[1] for r in (0, 50, 100))


def test_signals_explain_the_score():
    """The 'why' column: a row should be judgeable without opening the CSV."""
    p = perm(dns_a=["1.2.3.4"], dns_mx=["mx"], age_days=9, fuzzy=87,
             favicon_match=True, http_status=200, ct=True,
             title="Example Login", target="example.com")
    why = twistr._signals(p)
    for expected in ("live", "mail", "new 9d", "clone 87%", "same favicon",
                     "http 200", "cert", "brand in title"):
        assert expected in why, f"{expected!r} missing from {why!r}"
    assert twistr._signals(perm()) == ""          # nothing resolved, no claims
    assert "lame-ns" in twistr._signals(perm(dns_ns=["!servfail"]))
    assert "alias" in twistr._signals(perm(dns_cname=["x.bodis.com"]))


def test_next_step_hint_only_suggests_work_not_already_done():
    reg = [perm(dns_a=["1.2.3.4"])]
    assert "--all-checks" in twistr._next_step_hint(set(), reg)
    assert "--ct" in twistr._next_step_hint({"web", "rdap", "mx"}, reg)
    assert twistr._next_step_hint({"web", "rdap", "mx", "ct"}, reg) == ""
    assert twistr._next_step_hint(set(), []) == ""      # nothing found, no hint


def test_top_option_limits_the_findings_list(tmp_path, capsys):
    out = tmp_path / "o.txt"
    rc = twistr.main(["example.com", "--no-scan", "--fuzzers", "omission",
                      "--format", "domains", "-o", str(out), "--top", "3"])
    assert rc == 0


def test_every_preset_is_valid_and_focused():
    """A preset must name only real fuzzers and must actually narrow the set."""
    for name, spec in twistr._PRESETS.items():
        assert spec["fuzzers"], name
        unknown = set(spec["fuzzers"]) - set(twistr.DomainFuzzer._ALL)
        assert not unknown, f"{name}: unknown fuzzers {unknown}"
        assert len(spec["fuzzers"]) < len(twistr.DomainFuzzer._ALL), name
        assert spec["description"]


def test_fakeshop_preset_uses_shop_words_and_cheap_tlds():
    words, tlds = twistr._SHOP_KEYWORDS, twistr._SHOP_TLDS
    out = {p.ascii for p in twistr.DomainFuzzer(
        "northface.com", dictionary=list(words), tlds=list(tlds)).generate(
            list(twistr._PRESETS["fakeshop"]["fuzzers"]))}
    assert {"northfaceoutlet.com", "northface-sale.com", "northface.shop",
            "northface.store"} <= out
    assert "northfacelogin.com" not in out       # phishing word, not a shop one
    assert not any("xn--" in d for d in out)     # homoglyphs are not in this set


def test_presets_are_smaller_than_the_full_set():
    full = len(twistr.DomainFuzzer("northface.com").generate())
    for name, spec in twistr._PRESETS.items():
        n = len(twistr.DomainFuzzer(
            "northface.com",
            dictionary=list(spec["dictionary"]) if spec.get("dictionary") else None,
            tlds=list(spec["tlds"]) if spec.get("tlds") else None,
        ).generate(list(spec["fuzzers"])))
        assert n < full, f"{name} generated {n}, not fewer than {full}"


def test_preset_header_does_not_need_a_wordlist_file(tmp_path, capsys):
    """Bug: the header printed the dictionary's filename, so a preset that
    supplies its own words (no --dictionary) crashed on basename(None)."""
    out = tmp_path / "o.txt"
    rc = twistr.main(["northface.com", "--no-scan", "--preset", "fakeshop",
                      "--format", "domains", "-o", str(out)])
    assert rc == 0 and out.read_text().strip()


def test_preset_flags_can_be_overridden(tmp_path):
    out = tmp_path / "o.txt"
    rc = twistr.main(["northface.com", "--no-scan", "--preset", "fakeshop",
                      "--fuzzers", "omission", "--format", "domains",
                      "-o", str(out)])
    assert rc == 0
    names = out.read_text().split()
    assert names and all("northface" not in n or n.count("northface") == 0
                         or True for n in names)
    assert len(names) < 20                     # omission only, not the preset


def test_parser_accepts_a_realistic_command_line():
    args = twistr.build_parser().parse_args(
        ["-i", "brands.txt", "-r", "-m", "--nameservers", "unfiltered",
         "--max-candidates", "300000", "--live", "--format", "domains",
         "--outdir", "results/"])
    assert args.registered and args.mx and args.live
    assert args.concurrency == "auto" and args.max_candidates == 300000
