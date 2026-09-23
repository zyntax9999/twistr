#!/usr/bin/env python3
#
# twistr - typosquatting / phishing lookalike domain scanner
# Copyright 2026 [YOUR NAME OR GITHUB HANDLE]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Inspired by and derives some data/methods from dnstwist
# (https://github.com/elceef/dnstwist), Copyright Marcin Ulikowski,
# licensed under Apache-2.0. See the NOTICE file for details.
"""
twistr - domain permutation & impersonation scanner

A modern, fully-async reimplementation inspired by dnstwist
(https://github.com/elceef/dnstwist). It generates lookalike variations of a
domain and checks which ones are live, to help defenders find typosquatting /
phishing domains impersonating a brand they own or are authorized to protect.

Improvements over the classic tool:
  * Fully asynchronous DNS + HTTP (asyncio) instead of a thread pool - far
    higher throughput on large permutation sets, with a hard concurrency cap.
  * Public-suffix-aware splitting, so multi-label TLDs (co.uk, com.au ...)
    permute correctly (uses tldextract when installed, heuristic otherwise).
  * Extra fuzzers: bitsquatting, homoglyph / IDN homograph, dictionary,
    TLD swap, multi-layout keyboard adjacency, vowel swap.
  * Risk scoring so the most dangerous candidates float to the top.
  * Structured output: pretty table, JSON, or CSV.
  * Degrades gracefully - runs on the stdlib alone; optional libs unlock more.

Optional dependencies (recommended):
    pip install aiodns aiohttp tldextract rich idna ppdeep mmh3 uvloop

Examples:
    python twistr.py example.com
    python twistr.py example.com brand.co.uk --registered   # several at once
    cat brands.txt | python twistr.py --registered --format csv
    python twistr.py example.com --all-checks --ct          # every signal
    python twistr.py -i brands.txt --nameservers 1.1.1.1,8.8.4.4 \
        --dictionary countries.txt --tld-file tlds.txt \
        --min-length 8 --format csv -o permutations.csv
    python twistr.py example.com --web --favicon --rdap --format json -o out.json
    python twistr.py example.com --fuzzers homoglyph,bitsquatting,tld-typo
    python twistr.py -i brands.txt --registered --format domains --outdir results/

Intended for defensive research on domains you own or are authorized to assess.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import concurrent.futures
import csv
import hashlib
import io
import itertools
import json
import math
import multiprocessing as mp
import os
import random
import re
import socket
import string
import sys
import tempfile
import time
import unicodedata
import urllib.parse
import urllib.request
import warnings
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

# --------------------------------------------------------------------------- #
# Optional dependencies (all soft; the tool works without any of them)
# --------------------------------------------------------------------------- #
try:
    import aiodns  # async DNS with MX/NS/AAAA support
    _HAVE_AIODNS = True
    # we prefer query_dns() below; silence the query() deprecation just in case
    warnings.filterwarnings("ignore", message=r".*query\(\) is deprecated.*",
                            category=DeprecationWarning)
except ImportError:
    _HAVE_AIODNS = False

try:
    import aiohttp  # async HTTP for banner grabbing
    _HAVE_AIOHTTP = True
except ImportError:
    _HAVE_AIOHTTP = False

try:
    import tldextract  # accurate public-suffix splitting
    _HAVE_TLDEXTRACT = True
except ImportError:
    _HAVE_TLDEXTRACT = False

try:
    from rich.console import Console
    from rich.table import Table
    _HAVE_RICH = True
except ImportError:
    _HAVE_RICH = False

try:
    import ppdeep  # pure-python fuzzy hashing (ssdeep-compatible)
    _fuzzy_hash = ppdeep.hash
    _fuzzy_compare = ppdeep.compare
    _HAVE_FUZZY = True
except ImportError:
    _HAVE_FUZZY = False

try:
    import mmh3  # Shodan-compatible favicon hashing
    _HAVE_MMH3 = True
except ImportError:
    _HAVE_MMH3 = False

try:
    import uvloop  # drop-in faster asyncio event loop (Linux/macOS)
    _HAVE_UVLOOP = True
except ImportError:
    _HAVE_UVLOOP = False


def _install_uvloop():
    if _HAVE_UVLOOP:
        try:
            uvloop.install()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Character maps
# --------------------------------------------------------------------------- #

# Adjacent keys across three common layouts (number row included, since a
# slipped finger hits digits too: paypal -> pa7pal, payp0al), merged per char.
def _layout(rows):
    """Build a key -> neighbours map from staggered keyboard rows."""
    adj: dict[str, set[str]] = {}
    for r, row in enumerate(rows):
        for c, key in enumerate(row):
            n = adj.setdefault(key, set())
            if c > 0:
                n.add(row[c - 1])
            if c < len(row) - 1:
                n.add(row[c + 1])
            # rows are staggered right by ~half a key per row: key c on row r
            # touches keys c-1 and c on the row below, c and c+1 on the row above
            if r + 1 < len(rows):
                below = rows[r + 1]
                for k in (c - 1, c):
                    if 0 <= k < len(below):
                        n.add(below[k])
                        adj.setdefault(below[k], set()).add(key)
    return {k: "".join(sorted(v)) for k, v in adj.items()}


_KEYBOARDS = [
    _layout(["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]),   # qwerty
    _layout(["1234567890", "qwertzuiop", "asdfghjkl", "yxcvbnm"]),   # qwertz
    _layout(["1234567890", "azertyuiop", "qsdfghjklm", "wxcvbn"]),   # azerty
]


def _adjacent(char: str) -> set[str]:
    out: set[str] = set()
    for kb in _KEYBOARDS:
        out.update(kb.get(char, ""))
    return out


# Visually confusable characters for homoglyph / IDN-homograph attacks: ASCII
# look-alikes, Latin diacritics, and Cyrillic/Greek confusables, plus a few
# multi-character mappings (rn<->m, cl<->d, vv<->w) applied both directions.
_GLYPHS = {
    "a": ["à", "á", "â", "ã", "ä", "å", "ā", "ă", "ą", "ǎ", "ȧ", "ạ", "ɑ",
          "ə", "а", "@"],
    "b": ["d", "lb", "ib", "ḃ", "ḅ", "ƀ", " b", "Ь", "ъ"],
    "c": ["ç", "ć", "ĉ", "ċ", "č", "ϲ", "с", "ⅽ", "ƈ"],
    "d": ["b", "cl", "dl", "ď", "đ", "ḋ", "ḍ", "ɗ", "ԁ"],
    "e": ["è", "é", "ê", "ë", "ē", "ĕ", "ė", "ę", "ě", "ẹ", "ẻ", " e", "е",
          "ε", "3"],
    "f": ["ƒ", "ḟ", " f"],
    "g": ["q", "ĝ", "ğ", "ġ", "ģ", "ǵ", "ɡ", "ǥ", "ḡ", " g"],
    "h": ["ĥ", "ħ", "ḣ", "ḥ", "ḧ", "һ"],
    "i": ["1", "l", "í", "ì", "î", "ï", "ĩ", "ī", "ĭ", "į", "ı", "ɩ", "ị",
          "і", "!"],
    "j": ["ĵ", "ǰ", "ȷ", "ј", "ʝ"],
    "k": ["ķ", "ĸ", "ǩ", "ḱ", "ḳ", "к"],
    "l": ["1", "i", "ĺ", "ļ", "ľ", "ł", "ŀ", "ɫ", "ǀ", "ⅼ", "|"],
    "m": ["n", "nn", "rn", "rri", "ṁ", "ṃ", "м"],
    "n": ["m", "r", "ń", "ņ", "ň", "ñ", "ṅ", "ṇ", "ŉ", "ŋ", "п"],
    "o": ["0", "ò", "ó", "ô", "õ", "ö", "ø", "ō", "ŏ", "ő", "ọ", "ơ", "ᴏ",
          "о", "σ"],
    "p": ["ṗ", "ṕ", "ƥ", "ƿ", "ρ", "р"],
    "q": ["g", "ǫ", "ɋ", " q"],
    "r": ["ŕ", "ŗ", "ř", "ṙ", "ṛ", "ɽ", "г"],
    "s": ["ś", "ŝ", "ş", "š", "ṡ", "ṣ", "ș", "ѕ", "5", "$"],
    "t": ["ţ", "ť", "ŧ", "ț", "ṫ", "ṭ", "т", "+"],
    "u": ["ù", "ú", "û", "ü", "ũ", "ū", "ŭ", "ů", "ű", "ų", "ụ", "ц", "µ",
          "υ"],
    "v": ["ѵ", "ν", "ṽ", "ṿ", "ʋ", "\\/"],
    "w": ["vv", "ŵ", "ẁ", "ẃ", "ẅ", "ẉ", "ѡ", "ω"],
    "x": ["х", "ẋ", "ẍ", "×"],
    "y": ["ý", "ÿ", "ŷ", "ȳ", "ẏ", "ỳ", "ỵ", "ỹ", "ƴ", "ʏ", "ɏ", "ỿ", "у"],
    "z": ["ź", "ż", "ž", "ẑ", "ẓ", "ẕ", "ʐ", "ᴢ"],
    "rn": ["m"],
    "cl": ["d"],
    "vv": ["w"],
    "nn": ["m"],
    "0": ["o", "O", "Ο", "О"],
    "1": ["l", "i", "I"],
    "3": ["8", "e"],
    "5": ["s", "S"],
    "6": ["9", "b"],
    "8": ["3", "B"],
    "9": ["6", "g"],
}

_VOWELS = "aeiou"
_TLDS = [
    "com", "net", "org", "info", "biz", "co", "io", "us", "app", "dev",
    "online", "site", "xyz", "top", "live", "shop", "store", "cloud",
    "cn", "ru", "de", "uk", "eu", "no", "se",
]

# Combosquatting keywords - brand+keyword is one of the most common phishing
# patterns in the wild (Kintis et al., "Hiding in Plain Sight", 2017).
_DICTIONARY = [
    "login", "signin", "secure", "security", "account", "accounts", "verify",
    "verification", "update", "confirm", "support", "help", "service",
    "services", "billing", "payment", "pay", "wallet", "mail", "webmail",
    "email", "portal", "auth", "my", "online", "web", "app", "apps", "mobile",
    "click", "link", "home", "official", "live", "admin", "user", "customer",
    "care", "center", "id", "access", "recovery", "reset", "password", "alert",
    "notice", "safe", "protect", "vip", "info", "net", "cloud", "download",
]

# Homophones for "soundsquatting" (Nikiforakis et al., 2014): swap a substring
# for a same-sounding one.
_HOMOPHONES = {
    "for": ["four", "fore"], "four": ["for", "fore"], "fore": ["for", "four"],
    "to": ["too", "two"], "too": ["to", "two"], "two": ["to", "too"],
    "you": ["u"], "your": ["ur"], "are": ["r"], "and": ["n"],
    "ate": ["eight"], "eight": ["ate"], "be": ["bee"], "bee": ["be"],
    "sea": ["see"], "see": ["sea"], "buy": ["by", "bye"], "by": ["buy", "bye"],
    "one": ["won"], "won": ["one"], "know": ["no"], "mail": ["male"],
    "male": ["mail"], "meet": ["meat"], "week": ["weak"], "site": ["sight"],
    "right": ["rite"], "night": ["nite"], "new": ["knew"], "hi": ["high"],
    "cent": ["sent"], "flour": ["flower"], "flower": ["flour"],
}

# Number <-> word and leet-style swaps ("cardinal"), applied both directions.
_CARDINAL = {
    "0": ["o", "zero"], "1": ["one", "l", "i"], "2": ["two", "to", "too"],
    "3": ["three", "e"], "4": ["four", "for", "a"], "5": ["five", "s"],
    "6": ["six", "g"], "7": ["seven", "t"], "8": ["eight", "ate", "b"],
    "9": ["nine", "g", "q"],
    "zero": ["0"], "one": ["1"], "two": ["2"], "three": ["3"], "four": ["4"],
    "five": ["5"], "six": ["6"], "seven": ["7"], "eight": ["8"], "nine": ["9"],
    "for": ["4"], "to": ["2"], "ate": ["8"],
}

# Curated high-value TLD typos, keyed by the real public suffix (the ".cm" /
# ".co" family is a classic, heavily-abused typo of ".com").
_TLD_TYPOS = {
    "com": ["cm", "co", "om", "con", "vom", "xom", "comm", "cpm", "coo",
            "cim", "col", "ocm", "cmo", "cxom", "ver", "org", "net", "co.com"],
    "net": ["nte", "ent", "ne", "nett", "met", "bet", "nrt", "het", "nte"],
    "org": ["ogr", "rg", "og", "orgg", "orh", "prg", "irg", "orf", "or"],
    "co": ["c", "cp", "vo", "xo", "col", "coo", "cl"],
    "io": ["oi", "ii", "oo"],
    "gov": ["gv", "go", "govv", "gob", "gof"],
    "edu": ["eud", "edy", "ed", "eedu", "esu"],
}

# Whole-script Cyrillic look-alikes for IDN homograph attacks (one confusable
# per Latin letter). If a whole label maps, the result is visually identical.
_CYRILLIC = {
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у",
    "i": "і", "j": "ј", "s": "ѕ", "h": "һ", "k": "к", "m": "м", "t": "т",
    "b": "ь", "n": "п", "d": "ԁ", "g": "ԍ", "l": "ӏ", "r": "г", "u": "ц",
    "v": "ѵ", "w": "ѡ", "z": "ᴢ", "f": "ғ",
}

# Registry IDN policy: which non-ASCII characters each ccTLD registry accepts.
# A lookalike using any other character cannot be registered there, so there
# is no point querying it. Only registries with a narrow, strictly enforced
# rule are listed; every other TLD (.com, .eu, .pl, ...) stays unrestricted,
# because they accept wider or multiple scripts (a mixed-script name like
# p\u0430ypal.com really is registered). "" means the TLD takes no IDNs at all.
_LATIN_EXT = ("àáâãäåæçèéêëìíîïñòóôõöøùúûüýÿāăąćĉċčďđēĕėęěĝğġģĥħĩīĭįĵķĸĺļľłńņňō"
              "ŏőœŕŗřśŝşšţťŧũūŭůűųŵŷźżž")
_IDN_POLICY = {
    "no": "àáäåæçèéêïñòóôöøüčđńŋšŧž",           # Norid
    "dk": "æøåäöüé",                          # DK Hostmaster
    "fi": "áâäåõöüčđŋšŧžǥǧǩǯʒ",                # Traficom
    "de": _LATIN_EXT,                         # DENIC
    "at": _LATIN_EXT,                         # nic.at
    "fr": "àáâãäåæçèéêëìíîïñòóôõöøùúûüýÿœ",   # AFNIC
    "ch": "àáâãäåæçèéêëìíîïñòóôõöøùúûüýÿœ",   # SWITCH
    "li": "àáâãäåæçèéêëìíîïñòóôõöøùúûüýÿœ",   # SWITCH
    "uk": "", "co.uk": "", "org.uk": "", "me.uk": "", "ltd.uk": "",
    "plc.uk": "", "us": "", "nl": "",         # no IDN registrations
}


def _idn_allowed(ascii_domain: str, tld: str) -> bool:
    """False if the registry for `tld` would refuse this name's characters."""
    allowed = _IDN_POLICY.get(tld)
    has_idn = ascii_domain.startswith("xn--") or ".xn--" in ascii_domain
    if allowed is None or not has_idn:
        return True
    try:
        label = ascii_domain.encode().decode("idna").rsplit("." + tld, 1)[0]
    except Exception:
        return False
    return all(ch.isascii() or ch in allowed for ch in label)


# Fuzzers weighted by how convincing / dangerous the result usually is.
_FUZZER_RISK = {
    "homoglyph": 5, "homoglyph-script": 6, "bitsquatting": 4, "dictionary": 4,
    "homophone": 3, "cardinal": 3, "tld-typo": 4, "hyphenation": 3,
    "subdomain": 3, "omission": 3, "replacement": 3, "insertion": 2,
    "transposition": 2, "repetition": 2, "vowel-swap": 2, "addition": 2,
    "tld-swap": 3, "various": 2, "ct-log": 4, "original": 0,
}


# --------------------------------------------------------------------------- #
# Domain splitting (public-suffix aware)
# --------------------------------------------------------------------------- #

# Minimal multi-label suffix set for the no-tldextract fallback.
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "com.br", "com.cn", "co.in", "co.za", "com.mx",
}


def split_domain(fqdn: str) -> tuple[str, str, str]:
    """Return (subdomain, registrable_name, public_suffix)."""
    fqdn = fqdn.strip().lower().rstrip(".")
    if _HAVE_TLDEXTRACT:
        ext = tldextract.extract(fqdn)
        if not ext.domain or not ext.suffix:
            raise ValueError(f"cannot parse a registrable domain from {fqdn!r}")
        return ext.subdomain, ext.domain, ext.suffix

    labels = fqdn.split(".")
    if len(labels) < 2:
        raise ValueError(f"{fqdn!r} is not a valid domain")
    for i in range(len(labels) - 2, 0, -1):
        candidate = ".".join(labels[i:])
        if candidate in _MULTI_SUFFIX:
            return ".".join(labels[:i - 1]), labels[i - 1], candidate
    return ".".join(labels[:-2]), labels[-2], labels[-1]


def to_ascii(name: str) -> str | None:
    """IDNA/punycode-encode a full domain, label by label. None if impossible."""
    try:
        return ".".join(
            lbl if lbl.isascii() else lbl.encode("idna").decode("ascii")
            for lbl in name.split(".")
        )
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Permutation engine
# --------------------------------------------------------------------------- #

@dataclass
class Permutation:
    fuzzer: str
    domain: str            # unicode form (what a human sees)
    ascii: str             # punycode form (what DNS resolves), may equal domain
    target: str = ""       # the input domain this permutation was derived from
    # Populated during scanning:
    dns_a: list[str] = field(default_factory=list)
    dns_aaaa: list[str] = field(default_factory=list)
    dns_mx: list[str] = field(default_factory=list)
    dns_cname: list[str] = field(default_factory=list)  # alias at the name
    dns_ns: list[str] = field(default_factory=list)
    http_status: int | None = None
    http_server: str | None = None
    title: str | None = None       # HTML <title> of the candidate homepage
    fuzzy: int | None = None       # 0-100 content similarity to the original
    favicon_match: bool = False    # favicon identical to the original's
    created: str | None = None     # domain registration date (RDAP)
    age_days: int | None = None    # days since registration (newly-reg = risky)
    registrar: str | None = None
    ct: bool = False               # seen in a Certificate Transparency log
    wildcard: bool = False         # only answers like a parent-zone wildcard
    risk: int = 0

    @property
    def registered(self) -> bool:
        if self.wildcard:
            return False
        return bool(self.dns_a or self.dns_aaaa or self.dns_ns or self.dns_mx
                    or self.dns_cname)


class _GenStop(Exception):
    """Raised internally to stop generation when a cap or memory budget is hit."""


def _rss_bytes():
    """Resident memory of this process in bytes (Linux); 0 if unavailable."""
    try:
        with open("/proc/self/statm") as fh:
            return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except Exception:
        return 0


def _avail_memory():
    """Available system memory in bytes (Linux); 0 if unavailable."""
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemAvailable"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    return 0


class DomainFuzzer:
    def __init__(self, domain: str, dictionary=None, tlds=None,
                 idn_policy=True):
        self.idn_policy = idn_policy
        self.sub, self.name, self.tld = split_domain(domain)
        self.original = f"{self.name}.{self.tld}"
        self.original_ascii = to_ascii(self.original) or self.original
        self.dictionary = dictionary or _DICTIONARY
        self.tlds = tlds or _TLDS
        self._seen: set[str] = set()
        self.results: list[Permutation] = []
        self.stopped_reason = None
        self.trim_note = None
        self._dict_budget = None
        self._limit = 0
        self._mem_budget = 0
        self._check_ctr = 0

    # -- helpers ---------------------------------------------------------- #
    def _add(self, fuzzer: str, new_name: str, tld: str | None = None):
        tld = tld or self.tld
        unicode_domain = f"{new_name}.{tld}"
        if unicode_domain == self.original or unicode_domain in self._seen:
            return
        # cheap registry pre-check before the (slow) IDNA encode: reject names
        # with characters the TLD's registry refuses, unless normalisation
        # would fold them to plain ASCII anyway (the full check runs below)
        if self.idn_policy and not new_name.isascii():
            allowed = _IDN_POLICY.get(tld)
            if allowed is not None and any(
                    not ch.isascii() and ch not in allowed and
                    not unicodedata.normalize("NFKC", ch).isascii()
                    for ch in new_name):
                self._seen.add(unicode_domain)
                return
        ascii_domain = to_ascii(unicode_domain)
        if ascii_domain is None or not _valid_domain(ascii_domain):
            return
        # a confusable can normalize back to the real domain - that's not a
        # lookalike, it IS the original; drop it
        if ascii_domain == self.original_ascii:
            return
        # skip names the TLD's registry would refuse to register
        if self.idn_policy and not _idn_allowed(ascii_domain, tld):
            return
        # different spellings can encode to the same wire name (IDNA folds
        # e.g. the roman numeral 'ⅼ' into 'l'); query each real name only once
        if ascii_domain in self._seen:
            self._seen.add(unicode_domain)
            return
        self._seen.add(unicode_domain)
        self._seen.add(ascii_domain)
        self.results.append(
            Permutation(fuzzer, unicode_domain, ascii_domain,
                        target=self.original)
        )
        # periodic guard so a giant dictionary can't OOM-kill the process:
        # stop generating (and scan what we have) when a cap is reached
        self._check_ctr += 1
        if self._check_ctr >= 20000:
            self._check_ctr = 0
            if self._limit and len(self.results) - 1 > self._limit:
                self.stopped_reason = (
                    f"reached --max-candidates ({self._limit:,})")
                raise _GenStop
            if self._mem_budget:
                rss = _rss_bytes()
                if rss and rss >= self._mem_budget:
                    self.stopped_reason = (
                        f"memory budget reached (~{rss // 2**20} MB) after "
                        f"{len(self.results):,} candidates")
                    raise _GenStop

    # -- individual fuzzers ---------------------------------------------- #
    def _omission(self):
        n = self.name
        for i in range(len(n)):
            self._add("omission", n[:i] + n[i + 1:])

    def _repetition(self):
        n = self.name
        for i, c in enumerate(n):
            self._add("repetition", n[:i] + c + n[i:])

    def _transposition(self):
        n = self.name
        for i in range(len(n) - 1):
            self._add("transposition", n[:i] + n[i + 1] + n[i] + n[i + 2:])

    def _replacement(self):
        n = self.name
        for i, c in enumerate(n):
            for r in _adjacent(c):
                self._add("replacement", n[:i] + r + n[i + 1:])

    def _insertion(self):
        n = self.name
        for i, c in enumerate(n):
            for r in _adjacent(c):
                self._add("insertion", n[:i] + r + n[i:])
                self._add("insertion", n[:i + 1] + r + n[i + 1:])

    def _addition(self):
        n = self.name
        for c in "abcdefghijklmnopqrstuvwxyz0123456789":
            self._add("addition", n + c)

    def _vowel_swap(self):
        n = self.name
        for i, c in enumerate(n):
            if c in _VOWELS:
                for v in _VOWELS:
                    if v != c:
                        self._add("vowel-swap", n[:i] + v + n[i + 1:])

    def _hyphenation(self):
        n = self.name
        for i in range(1, len(n)):
            self._add("hyphenation", n[:i] + "-" + n[i:])

    def _subdomain(self):
        n = self.name
        for i in range(1, len(n)):
            if n[i - 1] not in "-." and n[i] not in "-.":
                self._add("subdomain", n[:i] + "." + n[i:])

    def _bitsquatting(self):
        valid = set("abcdefghijklmnopqrstuvwxyz0123456789-")
        n = self.name
        for i, c in enumerate(n):
            for bit in range(8):
                flipped = chr(ord(c) ^ (1 << bit))
                if flipped != c and flipped in valid:
                    self._add("bitsquatting", n[:i] + flipped + n[i + 1:])

    def _homoglyph(self):
        n = self.name

        def mix(domain):
            out = set()
            for i, c in enumerate(domain):
                for g in _GLYPHS.get(c, ()):
                    out.add(domain[:i] + g + domain[i + 1:])
            # two-char windows catch rn->m, cl->d, vv->w and the reverse
            for i in range(len(domain) - 1):
                win = domain[i:i + 2]
                for key in {win, win[0], win[1]}:
                    for g in _GLYPHS.get(key, ()):
                        out.add(domain[:i] + win.replace(key, g) + domain[i + 2:])
            return out

        first = mix(n)
        for r in first:
            self._add("homoglyph", r)
        # second pass: two simultaneous substitutions (deduped by _add)
        for r in first:
            for r2 in mix(r):
                self._add("homoglyph", r2)
        # whole-script confusable: if every letter maps to a Cyrillic look-alike
        # the result is visually identical to the original (strong IDN attack)
        if n and all(c in _CYRILLIC or c in "-" for c in n) and any(
                c in _CYRILLIC for c in n):
            self._add("homoglyph-script",
                      "".join(_CYRILLIC.get(c, c) for c in n))

    def _dictionary(self):
        n = self.name
        words = self.dictionary
        budget = self._dict_budget
        if budget is not None:
            k = max(0, budget // 4)          # 4 candidate forms per word
            if k < len(words):
                # evenly spaced sample across the WHOLE list - a sorted
                # dictionary cut at the first k words would only ever try
                # words from the start of the alphabet
                step = len(words) / k if k else 0
                words = [words[int(i * step)] for i in range(k)]
                self.trim_note = (
                    f"dictionary trimmed to {len(words):,} of "
                    f"{len(self.dictionary):,} words (sampled evenly across "
                    f"the list) to fit --max-candidates {self._limit:,}; all "
                    f"other fuzzers ran in full")
        for w in words:
            self._add("dictionary", f"{n}{w}")
            self._add("dictionary", f"{n}-{w}")
            self._add("dictionary", f"{w}{n}")
            self._add("dictionary", f"{w}-{n}")

    def _tld_swap(self):
        for t in self.tlds:
            if t != self.tld:
                self._add("tld-swap", self.name, tld=t)

    def _various(self):
        n, t = self.name, self.tld
        # tld baked into the label, www-noise, and simple plural
        self._add("various", n + t)             # paypalcom.com
        self._add("various", n + "-" + t)       # paypal-com.com
        self._add("various", "www" + n)         # wwwpaypal.com
        self._add("various", "www-" + n)        # www-paypal.com
        if n.endswith("s"):
            self._add("various", n[:-1])
        else:
            self._add("various", n + "s")

    def _tld_typo(self):
        t = self.tld
        variants: set[str] = set(_TLD_TYPOS.get(t, []))
        if "." not in t:  # char-level typos on a single-label suffix
            for i in range(len(t)):
                variants.add(t[:i] + t[i + 1:])                     # omission
            for i in range(len(t) - 1):
                variants.add(t[:i] + t[i + 1] + t[i] + t[i + 2:])   # transpose
            for i, c in enumerate(t):
                for r in _adjacent(c):
                    variants.add(t[:i] + r + t[i + 1:])             # replace
                variants.add(t[:i] + c + t[i:])                     # repeat
        for v in variants:
            if v and v != t:
                self._add("tld-typo", self.name, tld=v)

    def _homophone(self):
        n = self.name
        for sub, repls in _HOMOPHONES.items():
            start = 0
            while (pos := n.find(sub, start)) != -1:
                for r in repls:
                    self._add("homophone",
                              n[:pos] + r + n[pos + len(sub):])
                start = pos + 1

    def _cardinal(self):
        n = self.name
        for sub, repls in _CARDINAL.items():
            start = 0
            while (pos := n.find(sub, start)) != -1:
                for r in repls:
                    self._add("cardinal",
                              n[:pos] + r + n[pos + len(sub):])
                start = pos + 1

    _ALL = {
        "omission": _omission, "repetition": _repetition,
        "transposition": _transposition, "replacement": _replacement,
        "insertion": _insertion, "addition": _addition,
        "vowel-swap": _vowel_swap, "hyphenation": _hyphenation,
        "subdomain": _subdomain, "bitsquatting": _bitsquatting,
        "homoglyph": _homoglyph, "dictionary": _dictionary,
        "homophone": _homophone, "cardinal": _cardinal,
        "tld-swap": _tld_swap, "tld-typo": _tld_typo, "various": _various,
    }

    def generate(self, fuzzers=None, max_candidates=0, mem_budget=0):
        self.results.clear()
        self._seen.clear()
        self.stopped_reason = None
        self._limit = max_candidates
        self._mem_budget = mem_budget
        self._check_ctr = 0
        # keep the original first so scans can diff against it
        self.results.append(
            Permutation("original", self.original,
                        to_ascii(self.original) or self.original,
                        target=self.original)
        )
        self._seen.add(self.original)
        chosen = fuzzers or list(self._ALL)
        for name in chosen:
            if name not in self._ALL:
                raise ValueError(f"unknown fuzzer: {name}")
        # the dictionary can be orders of magnitude larger than everything
        # else combined, so it runs LAST and only gets the budget the other
        # fuzzers leave - a cap must never starve tld-swap, tld-typo etc.
        order = [f for f in chosen if f != "dictionary"]
        if "dictionary" in chosen:
            order.append("dictionary")
        self._dict_budget = None
        self.trim_note = None
        try:
            for name in order:
                if name == "dictionary" and self._limit:
                    self._dict_budget = max(
                        0, self._limit - (len(self.results) - 1))
                self._ALL[name](self)
        except _GenStop:
            pass          # hit the candidate/memory cap; scan what we have
        # exact cap enforcement (the in-loop check only fires periodically);
        # the cap counts candidates, not the original entry at index 0
        if self._limit and len(self.results) - 1 > self._limit:
            self.results = self.results[:self._limit + 1]
            if not self.stopped_reason:
                self.stopped_reason = (
                    f"reached --max-candidates ({self._limit:,})")
        return self.results


def _valid_domain(ascii_domain: str) -> bool:
    if len(ascii_domain) > 253:
        return False
    for label in ascii_domain.split("."):
        if not 1 <= len(label) <= 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in label):
            return False
    return True


# --------------------------------------------------------------------------- #
# Progress reporting (adaptive: animated bar on a TTY, log lines to a file)
# --------------------------------------------------------------------------- #

class Progress:
    """Renders scan progress differently depending on where output goes.

    * Terminal + rich installed -> animated rich progress bar.
    * Terminal only             -> in-place ASCII bar with %, rate and ETA.
    * Redirected to a file / nohup / pipe -> periodic timestamped lines,
      throttled so the log stays readable, flushed so `tail -f` works live.
    """

    def __init__(self, mode="auto", stream=None, label="scanning"):
        self.stream = stream or sys.stderr
        self.label = label
        tty = self.stream.isatty()
        if mode == "none":
            self.kind = "none"
        elif mode == "plain":
            self.kind = "plain"
        elif mode == "bar":
            self.kind = "rich" if _HAVE_RICH else "ascii"
        else:  # auto
            self.kind = ("rich" if (tty and _HAVE_RICH)
                         else "ascii" if tty else "plain")
        # an in-place \r bar only makes sense on a real terminal; if output is
        # redirected (file / nohup / pipe) fall back to readable log lines
        if self.kind == "ascii" and not tty:
            self.kind = "plain"
        self.total = 0
        self.start_t = 0.0
        self.last_emit = 0.0
        self.last_pct = -1
        self._rich = None
        self._task = None

    @staticmethod
    def _fmt(seconds):
        seconds = int(max(0, seconds))
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

    def start(self, total):
        self.total = total
        self.start_t = time.monotonic()
        self.last_emit = self.start_t
        self.last_pct = -1
        if self.kind == "rich":
            try:
                from rich.progress import (
                    Progress as RP, SpinnerColumn, BarColumn, TextColumn,
                    MofNCompleteColumn, TimeElapsedColumn, TimeRemainingColumn)
                self._rich = RP(
                    SpinnerColumn(),
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    MofNCompleteColumn(),
                    TextColumn("live:[green]{task.fields[live]}"),
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    console=Console(file=self.stream),
                )
                self._rich.start()
                self._task = self._rich.add_task(self.label, total=total, live=0)
                return
            except Exception:
                self.kind = "ascii"  # fall back if the rich API differs
        if self.kind == "plain":
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            self.stream.write(
                f"[{ts}] {self.label} started: {total} to check\n")
            self.stream.flush()

    def update(self, done, live):
        if self.kind == "none":
            return
        if self.kind == "rich" and self._rich is not None:
            self._rich.update(self._task, completed=done, live=live)
        elif self.kind == "ascii":
            self._draw_bar(done, live)
        else:  # plain
            self._emit_line(done, live)

    def finish(self, done, live):
        if self.kind == "rich" and self._rich is not None:
            self._rich.update(self._task, completed=done, live=live)
            self._rich.stop()
        elif self.kind == "ascii":
            self._draw_bar(done, live)
            self.stream.write("\n")
            self.stream.flush()
        elif self.kind == "plain":
            self._emit_line(done, live, force=True, tag="done")

    # -- ASCII terminal bar ---------------------------------------------- #
    def _draw_bar(self, done, live):
        width = 32
        frac = done / self.total if self.total else 1.0
        filled = int(width * frac)
        bar = "#" * filled + "." * (width - filled)
        elapsed = time.monotonic() - self.start_t
        rate = done / elapsed if elapsed > 0 else 0.0
        eta = (self.total - done) / rate if rate > 0 else 0.0
        self.stream.write(
            f"\r{self.label} [{bar}] {frac * 100:3.0f}% "
            f"{done}/{self.total} live:{live} "
            f"{rate:5.0f}/s ETA {self._fmt(eta)} ")
        self.stream.flush()

    # -- file / nohup log lines (throttled) ------------------------------ #
    def _emit_line(self, done, live, force=False, tag=None):
        now = time.monotonic()
        pct = int(done / self.total * 100) if self.total else 100
        if not force and pct < self.last_pct + 2 and (now - self.last_emit) < 10:
            return
        self.last_pct = pct
        self.last_emit = now
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        elapsed = self._fmt(now - self.start_t)
        if tag == "done":
            self.stream.write(
                f"[{ts}] {self.label} done: {done}/{self.total} checked, "
                f"{live} live, elapsed {elapsed}\n")
        else:
            self.stream.write(
                f"[{ts}] {self.label} {done}/{self.total} ({pct}%) "
                f"live:{live} elapsed {elapsed}\n")
        self.stream.flush()


# --------------------------------------------------------------------------- #
# Scanning (async DNS + optional HTTP)
# --------------------------------------------------------------------------- #

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def _extract_title(body: bytes) -> str | None:
    m = _TITLE_RE.search(body or b"")
    if not m:
        return None
    try:
        text = m.group(1).decode("utf-8", "ignore")
    except Exception:
        return None
    text = re.sub(r"\s+", " ", text).strip()
    return text[:120] or None


def _favicon_hash(data: bytes) -> str | None:
    """Shodan-compatible mmh3 hash when available, else a sha1 of the bytes."""
    if not data:
        return None
    if _HAVE_MMH3:
        return str(mmh3.hash(base64.encodebytes(data)))
    return "sha1:" + hashlib.sha1(data).hexdigest()


def _rdap_created(data: dict):
    for ev in data.get("events") or []:
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            s = ev["eventDate"].replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(s)
            except Exception:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
    return None


def _rdap_registrar(data: dict) -> str | None:
    for ent in data.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            vcard = ent.get("vcardArray")
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        return item[3]
    return None


def _ct_query(name: str, timeout: float):
    url = ("https://crt.sh/?q=%25" + urllib.parse.quote(name)
           + "%25&output=json")
    req = urllib.request.Request(url, headers={"User-Agent": "twistr/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def ct_discover(original: str, name: str, seen: set, timeout=20.0):
    """Passive discovery: pull lookalike domains from Certificate Transparency
    logs (crt.sh). Finds real, cert-bearing impersonations that no permutation
    algorithm would generate. Returns a list of Permutation(fuzzer='ct-log')."""
    out = []
    try:
        rows = _ct_query(name, timeout)
    except Exception as e:
        print(f"ct: lookup for {name!r} failed: {e}", file=sys.stderr)
        return out
    found = set()
    for row in rows or []:
        for nm in (row.get("name_value", "") or "").split("\n"):
            nm = nm.strip().lower().lstrip("*.")
            if not nm or name not in nm:
                continue
            try:
                _, rn, rt = split_domain(nm)
                reg = f"{rn}.{rt}"
            except Exception:
                continue
            if reg == original or reg in seen or reg in found:
                continue
            found.add(reg)
    for reg in sorted(found):
        asc = to_ascii(reg)
        if not asc or not _valid_domain(asc):
            continue
        seen.add(reg)
        out.append(Permutation("ct-log", reg, asc, target=original, ct=True))
    return out


# --------------------------------------------------------------------------- #

class Scanner:
    def __init__(self, concurrency=64, timeout=5.0, nameservers=None,
                 do_web=False, do_rdap=False, do_favicon=False, do_mx=False,
                 base_fuzzy=None, base_favicon=None):
        self.concurrency = concurrency
        self.do_mx = do_mx
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.do_web = do_web and _HAVE_AIOHTTP
        self.do_rdap = do_rdap and _HAVE_AIOHTTP
        self.do_favicon = do_favicon and _HAVE_AIOHTTP
        self._resolver = None
        self.nameservers = nameservers
        # baselines captured from each target's real site, keyed by target;
        # may be supplied by the caller so sharded workers don't re-fetch them
        self.base_fuzzy: dict[str, str] = base_fuzzy or {}
        self.base_favicon: dict[str, str] = base_favicon or {}

    _RTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "AAAA": 28}

    @classmethod
    def _dns_values(cls, res, rtype=None, name=None, own=False):
        """Extract host/address strings from either aiodns API shape:
        new query_dns() -> DNSResult(answer=[DNSRecord(data=...)]);
        old query()     -> [record.host, ...].
        Only records of the queried type count (an alias answer also carries
        CNAME records), and NS records must belong to `name` itself - for an
        alias the resolver returns the *target's* nameservers, which is not a
        delegation of this name."""
        answer = getattr(res, "answer", None)
        if answer is not None:                       # new query_dns() shape
            want = cls._RTYPE.get(rtype) if rtype else None
            out = []
            for rec in answer:
                rt = getattr(rec, "type", None)
                if want is not None and rt is not None and rt != want:
                    continue
                if (rtype == "NS" or own) and name and \
                        getattr(rec, "name", None) and \
                        rec.name.rstrip(".").lower() != name.lower():
                    continue
                d = getattr(rec, "data", None)
                for attr in ("addr", "host", "exchange", "nsdname", "cname"):
                    v = getattr(d, attr, None)
                    if v:
                        out.append(v)
                        break
            return out
        try:                                         # old query() shape
            return [a.host for a in res if getattr(a, "host", None)]
        except TypeError:
            return []

    async def _query(self, name, rtype, attempts):
        """One record lookup with retries. Returns (status, values, cnames) -
        cnames are aliases owned by `name` itself - where
        status is ok | nx (NXDOMAIN) | nodata | servfail | fail (timeout etc)."""
        status = "fail"
        for attempt in range(attempts):
            try:
                res = await asyncio.wait_for(self._qfn(name, rtype),
                                             self.timeout)
                return ("ok", self._dns_values(res, rtype, name),
                        self._dns_values(res, "CNAME", name, own=True))
            except Exception as e:
                code = e.args[0] if getattr(e, "args", None) else None
                if code == 4:
                    return "nx", None, None     # definitive: does not exist
                if code == 1:
                    return "nodata", None, None  # exists, no such record
                status = ("servfail" if code == 3 or status == "servfail"
                          else "fail")
                if attempt + 1 < attempts:
                    await asyncio.sleep(0.2 * (attempt + 1))
        return status, None, None

    async def _resolve_aiodns(self, perm: Permutation, attempts=2):
        """Staged lookup. NS first: most candidates are NXDOMAIN, so they cost
        one query instead of three. Only names that exist get A/AAAA (+MX).
        Sets perm._dns to 'ok', 'nx', or a transient failure that the calm
        second pass will retry ('servfail' / 'fail')."""
        st, ns, cn = await self._query(perm.ascii, "NS", attempts)
        if st == "servfail" and getattr(self, "_calm", False):
            perm._sf = True       # SERVFAIL under low load: likely lame delegation
        if st == "nx":
            perm._dns = "nx"
            return
        if st in ("servfail", "fail"):
            perm._dns = st
            return
        if ns:
            perm.dns_ns = ns
        cnames = set(cn or [])
        qtypes = ["A", "AAAA"] + (["MX"] if self.do_mx else [])
        results = await asyncio.gather(
            *[self._query(perm.ascii, t, attempts) for t in qtypes])
        failed = False
        for rtype, (s, vals, cn) in zip(qtypes, results):
            cnames.update(cn or [])
            if s in ("servfail", "fail"):
                failed = True
            if not vals:
                continue
            if rtype == "A":
                perm.dns_a = vals
            elif rtype == "AAAA":
                perm.dns_aaaa = vals
            else:
                perm.dns_mx = vals
        # a name that exists only because its parent zone answers for *any*
        # name (wildcard DNS) is not a registration: no delegation of its own
        # and the same addresses as a random name in that zone
        perm.dns_cname = sorted(cnames)
        perm.wildcard = False
        if perm.dns_a or perm.dns_ns or perm.dns_cname:
            wa, wn, wc = await self._wildcard_addrs(perm.ascii.split(".", 1)[1])
            if wa or wn or wc:
                a_same = bool(set(perm.dns_a) & wa) if perm.dns_a else not wa
                ns_same = {n.lower() for n in perm.dns_ns} == wn
                c_same = {c.lower() for c in perm.dns_cname} == wc
                perm.wildcard = a_same and ns_same and c_same
        # name exists but we could not confirm anything -> worth a retry
        perm._dns = "fail" if (failed and not perm.registered
                               and not perm.wildcard) else "ok"

    async def _wildcard_addrs(self, parent):
        """(addresses, nameservers) a random label under `parent` gets - both
        empty if the zone has no wildcard. Probed once per zone and cached;
        concurrent callers share the same probe."""
        cache = self.__dict__.setdefault("_wild", {})
        fut = cache.get(parent)
        if fut is None:
            fut = cache[parent] = asyncio.ensure_future(self._probe_wild(parent))
        try:
            return await asyncio.shield(fut)
        except Exception:
            return set(), set(), set()

    async def _probe_wild(self, parent):
        addrs, ns, cn = set(), set(), set()
        for _ in range(2):                  # two random labels, union of answers
            name = "zq" + "".join(random.choices(
                string.ascii_lowercase + string.digits, k=14)) + "." + parent
            st, vals, c = await self._query(name, "A", 3)
            if st == "nx":
                break                       # no wildcard in this zone
            addrs.update(vals or [])
            cn.update(x.lower() for x in (c or []))
            st, vals, c = await self._query(name, "NS", 3)
            ns.update(v.lower() for v in (vals or []))
        return addrs, ns, cn

    async def _resolve_socket(self, perm: Permutation):
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(perm.ascii, None), self.timeout)
        except Exception:
            return
        addrs = {i[4][0] for i in infos}
        perm.dns_a = sorted(a for a in addrs if ":" not in a)
        perm.dns_aaaa = sorted(a for a in addrs if ":" in a)

    async def _fetch_body(self, host: str, session):
        for scheme in ("https", "http"):
            try:
                async with session.get(f"{scheme}://{host}/",
                                       timeout=self.timeout,
                                       allow_redirects=True,
                                       ssl=False) as resp:
                    return resp, await resp.read()
            except Exception:
                continue
        return None, None

    async def _favicon(self, host: str, session):
        for scheme in ("https", "http"):
            try:
                async with session.get(f"{scheme}://{host}/favicon.ico",
                                       timeout=self.timeout,
                                       ssl=False) as resp:
                    if resp.status == 200:
                        return _favicon_hash(await resp.read())
            except Exception:
                continue
        return None

    async def _web(self, perm: Permutation, session):
        if not perm.registered:
            return
        resp, body = await self._fetch_body(perm.ascii, session)
        if resp is not None:
            perm.http_status = resp.status
            perm.http_server = resp.headers.get("Server")
            perm.title = _extract_title(body)
            base = self.base_fuzzy.get(perm.target)
            if base and _HAVE_FUZZY and body:
                try:
                    perm.fuzzy = _fuzzy_compare(base, _fuzzy_hash(body))
                except Exception:
                    pass
        if self.do_favicon and self.base_favicon.get(perm.target):
            fh = await self._favicon(perm.ascii, session)
            perm.favicon_match = bool(fh and fh == self.base_favicon[perm.target])

    async def _rdap(self, perm: Permutation, session):
        if not perm.registered:
            return
        try:
            async with session.get(f"https://rdap.org/domain/{perm.ascii}",
                                   timeout=self.timeout) as resp:
                if resp.status != 200:
                    return
                data = await resp.json(content_type=None)
        except Exception:
            return
        created = _rdap_created(data)
        if created:
            perm.created = created.date().isoformat()
            perm.age_days = (datetime.now(timezone.utc) - created).days
        perm.registrar = _rdap_registrar(data)

    async def _prime(self, perms, session):
        """Capture each target's real content hash + favicon for comparison."""
        originals = {p.target: p for p in perms if p.fuzzer == "original"}
        for target, op in originals.items():
            resp, body = await self._fetch_body(op.ascii, session)
            if body and _HAVE_FUZZY:
                try:
                    self.base_fuzzy[target] = _fuzzy_hash(body)
                except Exception:
                    pass
            if self.do_favicon:
                fh = await self._favicon(op.ascii, session)
                if fh:
                    self.base_favicon[target] = fh

    def _make_session(self):
        connector = aiohttp.TCPConnector(
            limit=max(100, self.concurrency * 2),
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
        return aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": "twistr/1.0 (+defensive-scan)"})

    async def _warm(self, perms):
        """Populate baselines once (used before sharding across processes)."""
        if not (self.do_web or self.do_favicon):
            return
        session = self._make_session()
        try:
            await self._prime(perms, session)
        finally:
            await session.close()

    async def _scan_one(self, perm: Permutation, session, attempts=2):
        try:
            if _HAVE_AIODNS:
                await self._resolve_aiodns(perm, attempts)
            else:
                await self._resolve_socket(perm)
            if perm.registered:
                if self.do_web and session is not None:
                    await self._web(perm, session)
                if self.do_rdap and session is not None:
                    await self._rdap(perm, session)
        except Exception:
            pass          # one bad domain must never abort the whole scan
        perm.risk = score(perm)
        return perm

    @staticmethod
    def _unsettled(perm):
        return getattr(perm, "_dns", "") in ("servfail", "fail")

    async def _pool(self, items, session, width, attempts, on_done):
        """Bounded worker pool: only `width` scans in flight at any moment, so
        file descriptors / memory stay flat over long, large runs."""
        queue = asyncio.Queue()
        for p in items:
            queue.put_nowait(p)

        async def worker():
            while True:
                try:
                    perm = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                await self._scan_one(perm, session, attempts)
                on_done(perm)

        n = max(1, min(width, len(items)))
        await asyncio.gather(*[worker() for _ in range(n)])

    async def scan(self, perms, progress=None, prime=True, on_result=None):
        if _HAVE_AIODNS:
            kw = dict(timeout=self.timeout, tries=1)
            if self.nameservers and len(self.nameservers) > 1:
                kw["rotate"] = True     # spread load across all resolvers
            try:
                self._resolver = aiodns.DNSResolver(
                    nameservers=self.nameservers or None, **kw)
            except TypeError:            # older aiodns without these options
                self._resolver = aiodns.DNSResolver(
                    nameservers=self.nameservers or None, timeout=self.timeout)
            # prefer the non-deprecated query_dns() (aiodns >= 4.0)
            self._qfn = getattr(self._resolver, "query_dns", None) \
                or self._resolver.query
        else:
            # the socket resolver runs in the loop's thread pool, whose default
            # size (~min(32, cpus+4)) would otherwise cap --concurrency
            loop = asyncio.get_running_loop()
            loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(
                max_workers=min(self.concurrency, 256)))
        session = None
        if self.do_web or self.do_rdap or self.do_favicon:
            session = self._make_session()
        done = live = 0
        unsettled: list[Permutation] = []
        finished = False

        def emit(perm):
            if on_result:
                try:
                    on_result(perm)
                except Exception:
                    pass

        def first_pass_done(perm):
            nonlocal done, live
            done += 1
            if self._unsettled(perm):
                unsettled.append(perm)        # decided in the calm second pass
            else:
                if perm.registered and perm.fuzzer != "original":
                    live += 1
                emit(perm)
            if progress:
                progress.update(done, live)

        try:
            # prime unless baselines were supplied by the caller (sharded runs)
            if (prime and session is not None and (self.do_web or self.do_favicon)
                    and not self.base_fuzzy and not self.base_favicon):
                await self._prime(perms, session)
            if progress:
                progress.start(len(perms))
            await self._pool(perms, session, self.concurrency, 2,
                             first_pass_done)
            if progress:
                progress.finish(done, live)
            finished = True

            # calm second pass: transient failures from load spikes are retried
            # at low concurrency with more patience, so they no longer cost us
            # real domains. A SERVFAIL that survives this is a lame delegation:
            # the TLD delegated the name, so it is registered (dnstwist agrees).
            if unsettled:
                self._calm = True
                width = max(4, min(16, self.concurrency // 8))
                for rnd in range(3):
                    if not unsettled:
                        break
                    self.timeout *= 1.5
                    await self._pool(unsettled, session, width, 3,
                                     lambda p: None)
                    last = rnd == 2
                    remaining = []
                    for p in unsettled:
                        st = getattr(p, "_dns", "")
                        if st in ("servfail", "fail") and not last:
                            remaining.append(p)        # try again, calmer
                            continue
                        # never a definitive answer, but SERVFAIL while the
                        # resolver was idle -> lame delegation (registered)
                        if st in ("servfail", "fail") and getattr(p, "_sf", False):
                            p._dns = "servfail"
                            p.dns_ns = ["!servfail"]
                            p.risk = score(p)
                        emit(p)
                    unsettled = remaining
                    width = max(2, width // 2)
        finally:
            if progress and not finished:
                progress.finish(done, live)
            if session is not None:
                await session.close()
        return perms


def score(perm: Permutation) -> int:
    """Heuristic 0-100 risk score combining generation and detection signals;
    higher = more worth investigating."""
    s = _FUZZER_RISK.get(perm.fuzzer, 1) * 5
    if perm.registered:
        s += 18
    if perm.dns_a:
        s += 6
    if perm.dns_mx:
        s += 16            # can receive mail -> credential-phishing capable
    if perm.http_status and perm.http_status < 400:
        s += 6
    if perm.fuzzy is not None:
        s += int(perm.fuzzy * 0.35)      # homepage looks like the real site
    if perm.favicon_match:
        s += 25                          # reused favicon -> likely phishing kit
    if perm.ct:
        s += 8                           # has a TLS cert in CT logs
    # newly-registered domains are a very strong phishing indicator
    if perm.age_days is not None:
        if perm.age_days <= 30:
            s += 25
        elif perm.age_days <= 90:
            s += 15
        elif perm.age_days <= 365:
            s += 6
    # homepage title name-drops the brand
    if perm.title and perm.target:
        brand = perm.target.split(".", 1)[0]
        if len(brand) >= 3 and brand in perm.title.lower():
            s += 10
    return min(s, 100)


# --------------------------------------------------------------------------- #
# Execution: async by default; optional multi-process sharding
# --------------------------------------------------------------------------- #

def _scan_chunk(payload):
    """Worker process: scan one shard of permutations in its own event loop."""
    batch, opts, base_fuzzy, base_favicon, use_uvloop = payload
    if use_uvloop:
        _install_uvloop()
    scanner = Scanner(base_fuzzy=base_fuzzy, base_favicon=base_favicon, **opts)
    asyncio.run(scanner.scan(batch, progress=None, prime=False))
    return batch


def run_scan(perms, *, processes, concurrency, timeout, nameservers,
             do_web, do_rdap, do_favicon, do_mx, progress, on_result=None):
    """Scan every permutation. One event loop is enough for pure I/O; multiple
    processes help when CPU-bound work (ppdeep content hashing) or very high
    concurrency makes a single core the bottleneck. on_result(perm), if given,
    is called as each result arrives (single-process) or per batch (sharded)."""
    opts = dict(concurrency=concurrency, timeout=timeout,
                nameservers=nameservers, do_web=do_web, do_rdap=do_rdap,
                do_favicon=do_favicon, do_mx=do_mx)

    batch_size = max(25, math.ceil(len(perms) / (max(processes, 1) * 10)))
    batches = [perms[i:i + batch_size]
               for i in range(0, len(perms), batch_size)]

    # single-process async path (the default, and best for pure DNS)
    if processes <= 1 or len(batches) <= 1:
        _install_uvloop()
        asyncio.run(Scanner(**opts).scan(perms, progress=progress,
                                         on_result=on_result))
        return perms

    # prime per-target baselines once so each worker doesn't refetch originals
    base_fuzzy, base_favicon = {}, {}
    if do_web or do_favicon:
        _install_uvloop()
        warm = Scanner(**opts)
        try:
            asyncio.run(warm._warm(perms))
        except Exception:
            pass
        base_fuzzy, base_favicon = warm.base_fuzzy, warm.base_favicon

    payloads = [(b, opts, base_fuzzy, base_favicon, _HAVE_UVLOOP)
                for b in batches]
    results, done, live = [], 0, 0
    progress.start(len(perms))
    ctx = mp.get_context("fork" if sys.platform != "win32" else "spawn")
    with ctx.Pool(processes) as pool:
        for scanned in pool.imap_unordered(_scan_chunk, payloads):
            results.extend(scanned)
            done += len(scanned)
            live += sum(1 for p in scanned if p.registered and p.fuzzer != "original")
            if on_result:
                for p in scanned:
                    on_result(p)
            progress.update(done, live)
    progress.finish(done, live)
    return results


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def _passes(perm, only_registered, min_length=0):
    """Whether a result would appear in the output (excludes the original)."""
    if perm.fuzzer == "original":
        return False
    if only_registered and not perm.registered:
        return False
    if min_length and len(perm.domain) < min_length:
        return False
    return True


def _rows(perms, only_registered, min_length=0):
    rows = [p for p in perms if _passes(p, only_registered, min_length)]
    rows.sort(key=lambda x: (x.target, -x.risk, x.fuzzer, x.domain))
    return rows


def _generated_count(perms):
    return sum(1 for p in perms if p.fuzzer != "original")


def _multi_target(perms):
    return len({p.target for p in perms}) > 1


def render_table(perms, only_registered, min_length=0):
    rows = _rows(perms, only_registered, min_length)
    multi = _multi_target(perms)
    has_age = any(p.age_days is not None for p in rows)
    if _HAVE_RICH:
        console = Console()
        t = Table(show_lines=False, header_style="bold")
        cols = ["risk"]
        if multi:
            cols.append("target")
        cols += ["fuzzer", "domain", "A / AAAA", "MX", "http"]
        if has_age:
            cols.append("age")
        for col in cols:
            t.add_column(col)
        for p in rows:
            addrs = ", ".join(p.dns_a + p.dns_aaaa) or "-"
            mx = ", ".join(p.dns_mx) or "-"
            http = str(p.http_status) if p.http_status else "-"
            style = "red" if p.risk >= 70 else "yellow" if p.risk >= 45 else None
            cells = [str(p.risk)]
            if multi:
                cells.append(p.target)
            cells += [p.fuzzer, p.domain, addrs, mx, http]
            if has_age:
                cells.append(f"{p.age_days}d" if p.age_days is not None else "-")
            t.add_row(*cells, style=style)
        console.print(t)
        console.print(f"[dim]{len(rows)} shown / {_generated_count(perms)} "
                      f"generated[/dim]")
        return
    # plain fallback
    hdr_tgt = f"{'target':<20} " if multi else ""
    print(f"{'risk':>4}  {hdr_tgt}{'fuzzer':<13} {'domain':<34} addresses")
    print("-" * (78 + (21 if multi else 0)))
    for p in rows:
        addrs = ", ".join(p.dns_a + p.dns_aaaa) or "-"
        age = f" [{p.age_days}d]" if p.age_days is not None else ""
        tcol = f"{p.target:<20} " if multi else ""
        print(f"{p.risk:>4}  {tcol}{p.fuzzer:<13} {p.domain:<34} {addrs}{age}")
    print(f"\n{len(rows)} shown / {_generated_count(perms)} generated")


def render_json(perms, only_registered, min_length=0):
    rows = _rows(perms, only_registered, min_length)
    return json.dumps([asdict(p) for p in rows], ensure_ascii=False, indent=2)


_CSV_HEADER = ["risk", "target", "fuzzer", "domain", "ascii", "a", "aaaa",
               "mx", "ns", "cname", "http_status", "http_server", "title", "fuzzy",
               "favicon_match", "created", "age_days", "registrar", "ct",
               "wildcard"]


def _csv_row(p):
    return [p.risk, p.target, p.fuzzer, p.domain, p.ascii,
            " ".join(p.dns_a), " ".join(p.dns_aaaa),
            " ".join(p.dns_mx), " ".join(p.dns_ns), " ".join(p.dns_cname),
            p.http_status or "", p.http_server or "",
            p.title or "", p.fuzzy if p.fuzzy is not None else "",
            "yes" if p.favicon_match else "",
            p.created or "", p.age_days if p.age_days is not None else "",
            p.registrar or "", "yes" if p.ct else "",
            "yes" if p.wildcard else ""]


def render_csv(perms, only_registered, min_length=0):
    rows = _rows(perms, only_registered, min_length)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_CSV_HEADER)
    for p in rows:
        w.writerow(_csv_row(p))
    return buf.getvalue()


def render_domains(perms, only_registered, min_length=0):
    """One domain per line, most-suspicious first, de-duplicated. Emits the
    ASCII/punycode form so every line is directly usable in a resolver,
    blocklist, or another tool (IDN/homoglyph domains show as xn--...)."""
    rows = _rows(perms, only_registered, min_length)
    seen, out = set(), []
    for p in rows:
        if p.ascii in seen:
            continue
        seen.add(p.ascii)
        out.append(p.ascii)
    return "\n".join(out) + ("\n" if out else "")


class LiveWriter:
    """Streams qualifying results to the output file the moment each one is
    scanned, so the file can be tailed / copied from mid-run. Line-based
    formats only ('domains', 'csv'). Filters that depend on a single result
    (registered, min-length) are applied here; global risk-sorting is done by
    a final atomic rewrite once the scan completes."""

    def __init__(self, path, fmt, only_registered, min_length):
        self.path = path
        self.fmt = fmt
        self.only_registered = only_registered
        self.min_length = min_length
        self.seen = set()
        self.fh = open(path, "w", encoding="utf-8", newline="")
        self._csv = csv.writer(self.fh) if fmt == "csv" else None
        if self._csv:
            self._csv.writerow(_CSV_HEADER)
            self.fh.flush()

    def feed(self, perm):
        if perm.fuzzer == "original":
            return
        if self.only_registered and not perm.registered:
            return
        if self.min_length and len(perm.domain) < self.min_length:
            return
        if self.fmt == "domains":
            if perm.ascii in self.seen:
                return
            self.seen.add(perm.ascii)
            self.fh.write(perm.ascii + "\n")
        else:  # csv
            self._csv.writerow(_csv_row(perm))
        self.fh.flush()

    def close(self):
        try:
            self.fh.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        description="Generate and scan lookalike domains (dnstwist-style).")
    p.add_argument("domain", nargs="*",
                   help="one or more target domains, e.g. example.com "
                        "brand.co.uk. Omit to read from --input or stdin.")
    p.add_argument("-i", "--input", metavar="FILE",
                   help="read target domains from FILE (one per line; "
                        "blank lines and #comments ignored). Use '-' for stdin.")
    p.add_argument("--fuzzers", help="comma-separated subset of fuzzers "
                   f"(default all: {','.join(DomainFuzzer._ALL)})")
    p.add_argument("--all-idn", action="store_true",
                   help="generate IDN lookalikes even with characters the "
                        "TLD's registry does not accept (default: skip them)")
    p.add_argument("--list-fuzzers", action="store_true",
                   help="print available fuzzers and exit")
    p.add_argument("--dictionary", metavar="FILE",
                   help="wordlist for the 'dictionary' fuzzer, one word per "
                        "line (replaces the built-in list)")
    p.add_argument("--tld-file", metavar="FILE",
                   help="wordlist of TLDs for the 'tld-swap' fuzzer, one per "
                        "line (replaces the built-in list)")
    p.add_argument("-r", "--registered", action="store_true",
                   help="only output domains that resolve / are registered")
    p.add_argument("--min-length", type=int, default=0, metavar="N",
                   help="only output permutations whose full domain is "
                        ">= N characters (like `awk 'length >= N'`)")
    p.add_argument("--web", action="store_true",
                   help="fetch each live homepage: HTTP status, Server banner, "
                        "<title>, and content similarity to the real site "
                        "(needs aiohttp; content diff needs ppdeep)")
    p.add_argument("--favicon", action="store_true",
                   help="compare each candidate's favicon to the real site's "
                        "(reused favicons flag phishing kits; implies --web)")
    p.add_argument("--rdap", action="store_true",
                   help="look up registration date + registrar via RDAP and "
                        "flag newly-registered domains (needs aiohttp)")
    p.add_argument("-m", "--mx", action="store_true",
                   help="also look up MX records (mail-interception signal); "
                        "off by default to save a lookup per domain")
    p.add_argument("--ct", action="store_true",
                   help="also discover lookalikes from Certificate Transparency "
                        "logs (crt.sh) - finds real cert-bearing impersonations")
    p.add_argument("--all-checks", action="store_true",
                   help="shortcut for --web --favicon --rdap --mx")
    p.add_argument("--max-candidates", type=int, default=0, metavar="N",
                   help="stop generating a target's permutations after N "
                        "candidates (0 = unlimited). Protects against giant "
                        "dictionaries; twistr also self-limits near memory "
                        "exhaustion.")
    p.add_argument("--no-scan", action="store_true",
                   help="only generate permutations, do not query DNS")
    p.add_argument("--concurrency", type=int, default=64,
                   help="max in-flight lookups per process (I/O-bound, so this "
                        "can be high: 200-1000 with fast resolvers)")
    p.add_argument("-P", "--processes", type=int, default=1,
                   help="split the scan across N worker processes to use "
                        "multiple cores (helps most with --web/ppdeep or very "
                        "high concurrency; try your core count, e.g. 6)")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--nameservers", help="comma-separated resolvers "
                   "(needs aiodns), e.g. 1.1.1.1,8.8.4.4")
    p.add_argument("--progress", choices=["auto", "bar", "plain", "none"],
                   default="auto",
                   help="progress style: auto (bar on a terminal, log lines "
                        "when redirected), bar, plain (timestamped lines), "
                        "or none")
    p.add_argument("--format", choices=["table", "json", "csv", "domains"],
                   default="table",
                   help="output format; 'domains' = one domain per line, "
                        "ranked worst-first (for blocklists / further tools)")
    p.add_argument("-o", "--output",
                   help="write results to this file. strftime tokens are "
                        "expanded, e.g. -o 'twistr-%%Y%%m%%d-%%H%%M%%S.txt'")
    p.add_argument("--outdir", metavar="DIR",
                   help="write to DIR with an auto, timestamped, unique "
                        "filename (twistr_<target>_<YYYYmmdd-HHMMSS>.<ext>)")
    p.add_argument("--timestamp", action="store_true",
                   help="add a date-time stamp to the output filename so each "
                        "run is unique (auto-names one if -o is omitted)")
    p.add_argument("--live", action="store_true",
                   help="write matches to the output file as they are found "
                        "(tail it / copy mid-run); domains & csv formats. The "
                        "file is risk-sorted with a final atomic rewrite at end")
    return p


def _load_wordlist(path):
    with open(path, encoding="utf-8") as fh:
        return [ln.strip().lower() for ln in fh
                if ln.strip() and not ln.lstrip().startswith("#")]


def _slug(targets):
    base = targets[0] if targets else "scan"
    base = re.sub(r"[^a-z0-9]+", "-", base.lower()).strip("-") or "scan"
    if len(targets) > 1:
        base += f"_and{len(targets) - 1}more"
    return base[:40]


def _atomic_write(path, text):
    """Write text so a concurrent reader/copier never sees a partial file."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".twistr-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _resolve_output_path(args, targets):
    """Work out the final output filename, applying timestamp / outdir rules."""
    ext = {"domains": "txt", "csv": "csv", "json": "json",
           "table": "csv"}[args.format]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = datetime.now().strftime(args.output) if args.output else None
    if args.timestamp:
        if out:
            root, e = os.path.splitext(out)
            out = f"{root}_{stamp}{e or '.' + ext}"
        else:
            out = f"twistr_{_slug(targets)}_{stamp}.{ext}"
    elif args.outdir and not out:
        out = f"twistr_{_slug(targets)}_{stamp}.{ext}"
    if args.outdir and out:
        os.makedirs(args.outdir, exist_ok=True)
        out = os.path.join(args.outdir, os.path.basename(out))
    return out


def _collect_targets(args):
    targets = list(args.domain)
    if args.input:
        if args.input == "-":
            targets += [ln.strip() for ln in sys.stdin]
        else:
            with open(args.input, encoding="utf-8") as fh:
                targets += [ln.strip() for ln in fh]
    # if nothing on the CLI and something is piped in, read stdin
    if not targets and not sys.stdin.isatty():
        targets += [ln.strip() for ln in sys.stdin]
    # clean: drop blanks, comments, dedupe while preserving order
    seen, cleaned = set(), []
    for t in targets:
        t = t.strip()
        if not t or t.startswith("#") or t in seen:
            continue
        seen.add(t)
        cleaned.append(t)
    return cleaned


def _warn_missing():
    missing = []
    if not _HAVE_AIODNS:
        missing.append("aiodns (MX/NS lookups + custom resolvers disabled)")
    if not _HAVE_TLDEXTRACT:
        missing.append("tldextract (using heuristic suffix splitting)")
    if not _HAVE_RICH:
        missing.append("rich (plain table output)")
    if missing:
        print("note: optional libs not found -> " + "; ".join(missing),
              file=sys.stderr)


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.list_fuzzers:
        for name in DomainFuzzer._ALL:
            print(f"  {name:<14} risk weight {_FUZZER_RISK.get(name, 1)}")
        return 0

    targets = _collect_targets(args)
    if not targets:
        print("error: no target domains given (pass domains, --input FILE, "
              "or pipe them in; or use --list-fuzzers)", file=sys.stderr)
        return 2

    _warn_missing()

    # optional custom wordlists (shared across all targets)
    try:
        dictionary = _load_wordlist(args.dictionary) if args.dictionary else None
        tlds = _load_wordlist(args.tld_file) if args.tld_file else None
    except OSError as e:
        print(f"error: cannot read wordlist: {e}", file=sys.stderr)
        return 2

    selected = None
    if args.fuzzers:
        selected = [f.strip() for f in args.fuzzers.split(",") if f.strip()]

    # resolve which detection checks are on
    do_web = args.web or args.favicon or args.all_checks
    do_favicon = args.favicon or args.all_checks
    do_rdap = args.rdap or args.all_checks
    do_mx = args.mx or args.all_checks
    if (do_web or do_rdap) and not _HAVE_AIOHTTP:
        print("warning: web/favicon/rdap checks need aiohttp (not installed); "
              "skipping them", file=sys.stderr)
    if do_web and not _HAVE_FUZZY:
        print("note: install ppdeep for homepage content-similarity scoring",
              file=sys.stderr)

    # generation guards: stop well before the OS OOM-killer fires (SIGKILL,
    # which we could not otherwise report), and honour an explicit cap
    avail = _avail_memory()
    mem_budget = int(avail * 0.80) if avail else 0
    max_cand = args.max_candidates
    if dictionary and len(dictionary) * 4 > 500_000:
        cap = (f", or at --max-candidates ({max_cand:,})" if max_cand else "")
        print(f"note: dictionary has {len(dictionary):,} words -> up to "
              f"~{len(dictionary) * 4:,} combosquatting candidates per target. "
              f"twistr will cap generation near ~{mem_budget // 2**30} GB RAM"
              f"{cap}.", file=sys.stderr)

    # validate targets cheaply (constructing a fuzzer parses/splits but does
    # not generate), so an invalid target is reported before any heavy work
    valid = []
    for t in targets:
        try:
            DomainFuzzer(t, dictionary=dictionary, tlds=tlds,
                         idn_policy=not args.all_idn)
            valid.append(t)
        except ValueError as e:
            print(f"skip {t!r}: {e}", file=sys.stderr)
    targets = valid
    if not targets:
        print("error: no valid targets to scan", file=sys.stderr)
        return 2

    ml = args.min_length
    out_path = _resolve_output_path(args, targets)

    def gen(target):
        fz = DomainFuzzer(target, dictionary=dictionary, tlds=tlds,
                          idn_policy=not args.all_idn)
        tp = fz.generate(selected, max_candidates=max_cand,
                         mem_budget=mem_budget)
        if fz.stopped_reason:
            print(f"  note: {fz.original}: generation stopped early - "
                  f"{fz.stopped_reason}; scanning the {_generated_count(tp):,} "
                  f"generated so far", file=sys.stderr)
        elif fz.trim_note:
            print(f"  note: {fz.original}: {fz.trim_note}", file=sys.stderr)
        return fz, tp

    # set up live streaming to the output file, if requested and supported
    writer = None
    live_ok = (args.live and out_path and not args.no_scan
               and args.format in ("domains", "csv"))
    if args.live and not live_ok:
        if not out_path:
            print("note: --live needs an output file (-o / --outdir / "
                  "--timestamp); ignoring --live", file=sys.stderr)
        elif args.no_scan:
            print("note: --live has no effect with --no-scan", file=sys.stderr)
        else:
            print(f"note: --live supports domains/csv only; {args.format} is "
                  "written at the end", file=sys.stderr)
    if live_ok:
        try:
            writer = LiveWriter(out_path, args.format, args.registered, ml)
        except OSError as e:
            print(f"error: cannot open {out_path} for live output: {e}",
                  file=sys.stderr)
            return 2
        print(f"live: streaming matches to {out_path}", file=sys.stderr)

    # Stream target-by-target when there are several: each is generated, scanned
    # and then reduced to just the rows we'll output, so memory stays flat and a
    # crash keeps every finished target (in the --live file). The single-pool
    # path is used for one target, for --ct (needs the shared set), or for -P
    # multiprocess sharding.
    per_target = (not args.no_scan and args.processes <= 1 and not args.ct
                  and len(targets) > 1)

    live = lame = wild = unresolved = total_generated = 0

    def tally(tp):
        nonlocal live, lame, wild, unresolved, total_generated
        for p in tp:
            if p.fuzzer == "original":
                continue
            total_generated += 1
            if p.registered:
                live += 1
            if p.dns_ns == ["!servfail"]:
                lame += 1
            if p.wildcard:
                wild += 1
            if getattr(p, "_dns", "") == "fail":
                unresolved += 1

    try:
        if not args.no_scan:
            nameservers = (args.nameservers.split(",")
                           if args.nameservers else None)
            progress = Progress(mode=args.progress)
            t0 = time.monotonic()

            if per_target:
                print(f"streaming {len(targets)} targets one at a time "
                      f"(memory-bounded)", file=sys.stderr)
                perms = []
                for idx, target in enumerate(targets, 1):
                    try:
                        fz, tp = gen(target)
                    except ValueError as e:
                        print(f"error: {e} (use --list-fuzzers to see valid "
                              f"names)", file=sys.stderr)
                        return 2
                    run_scan(tp, processes=1, concurrency=args.concurrency,
                             timeout=args.timeout, nameservers=nameservers,
                             do_web=do_web, do_rdap=do_rdap,
                             do_favicon=do_favicon, do_mx=do_mx, progress=None,
                             on_result=writer.feed if writer else None)
                    tally(tp)
                    lv = sum(1 for p in tp
                             if p.registered and p.fuzzer != "original")
                    # keep only rows that will be output, then drop the rest so
                    # millions of non-matches do not accumulate across targets
                    perms.extend(p for p in tp
                                 if _passes(p, args.registered, ml))
                    print(f"  [{idx}/{len(targets)}] {fz.original}: {lv} live "
                          f"/ {_generated_count(tp):,}", file=sys.stderr)
                    del tp
            else:
                perms = []
                for target in targets:
                    try:
                        fz, tp = gen(target)
                    except ValueError as e:
                        print(f"error: {e} (use --list-fuzzers to see valid "
                              f"names)", file=sys.stderr)
                        return 2
                    perms += tp
                    print(f"generated {_generated_count(tp):,} permutations of "
                          f"{fz.original}", file=sys.stderr)
                if not perms:
                    print("error: no valid targets to scan", file=sys.stderr)
                    return 2
                # passive discovery via Certificate Transparency logs (crt.sh)
                if args.ct:
                    seen_reg = {p.domain for p in perms}
                    added = 0
                    for target in {p.target for p in perms
                                   if p.fuzzer == "original"}:
                        name = target.split(".", 1)[0]
                        found = ct_discover(target, name, seen_reg,
                                            timeout=max(20.0, args.timeout))
                        perms += found
                        added += len(found)
                    print(f"ct: added {added} domains from Certificate "
                          f"Transparency logs", file=sys.stderr)
                perms = run_scan(perms, processes=max(1, args.processes),
                                 concurrency=args.concurrency,
                                 timeout=args.timeout, nameservers=nameservers,
                                 do_web=do_web, do_rdap=do_rdap,
                                 do_favicon=do_favicon, do_mx=do_mx,
                                 progress=progress,
                                 on_result=writer.feed if writer else None)
                tally(perms)

            pnote = (f" across {args.processes} processes"
                     if args.processes > 1 else "")
            print(f"scan complete{pnote}: {live} live / {total_generated} "
                  f"checked in {Progress._fmt(time.monotonic() - t0)}",
                  file=sys.stderr)
            if wild:
                print(f"  {wild} ignored: only resolve because the parent zone "
                      f"answers for any name (wildcard DNS; flagged in "
                      f"csv/json)", file=sys.stderr)
            if lame:
                print(f"  {lame} registered with broken nameservers (SERVFAIL, "
                      f"lame delegation) - counted as live", file=sys.stderr)
            if unresolved:
                print(f"  warning: {unresolved} domains could not be resolved "
                      f"even after retry rounds; results may be incomplete. Use "
                      f"better --nameservers or lower --concurrency",
                      file=sys.stderr)
        else:
            perms = []
            for target in targets:
                try:
                    fz, tp = gen(target)
                except ValueError as e:
                    print(f"error: {e} (use --list-fuzzers to see valid names)",
                          file=sys.stderr)
                    return 2
                perms += tp
                print(f"generated {_generated_count(tp):,} permutations of "
                      f"{fz.original}", file=sys.stderr)
            if not perms:
                print("error: no valid targets to scan", file=sys.stderr)
                return 2
            for p in perms:
                p.risk = score(p)
    except MemoryError:
        print("error: ran out of memory. Reduce the --dictionary size, scan "
              "fewer targets at once, or set --max-candidates. (twistr tries "
              "to self-limit, but a hard cap is safest for very large runs.)",
              file=sys.stderr)
        if writer:
            writer.close()
        return 2

    if writer:
        writer.close()

    # final output: for a live run this atomically rewrites the streamed file,
    # risk-sorted, so the finished file is ordered worst-first
    if args.format == "json":
        out = render_json(perms, args.registered, ml)
    elif args.format == "csv":
        out = render_csv(perms, args.registered, ml)
    elif args.format == "domains":
        out = render_domains(perms, args.registered, ml)
    else:  # table
        if out_path:
            out = render_csv(perms, args.registered, ml)  # table isn't a file
        else:
            render_table(perms, args.registered, ml)
            return 0

    if out_path:
        _atomic_write(out_path, out)
        print(f"wrote {out_path}", file=sys.stderr)
    else:
        print(out, end="" if args.format == "domains" else "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        # a downstream pipe (head, cut, ...) closed early; exit quietly
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except Exception:
            pass
        sys.exit(0)
