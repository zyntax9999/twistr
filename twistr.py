#!/usr/bin/env python3
#
# twistr - typosquatting / phishing lookalike domain scanner
# Copyright 2026 zyntax9999
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
import collections
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
import shutil
import socket
import string
import sys
import tempfile
import threading
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


# Greek and Armenian look-alikes, used the same way as _CYRILLIC: if a whole
# label maps, the result is visually identical but a different registration.
_GREEK = {
    "a": "\u03b1", "b": "\u03b2", "e": "\u03b5", "i": "\u03b9", "k": "\u03ba", "m": "\u03bc", "n": "\u03b7",
    "o": "\u03bf", "p": "\u03c1", "r": "\u03b3", "t": "\u03c4", "u": "\u03c5", "v": "\u03bd", "x": "\u03c7",
    "y": "\u03b3", "z": "\u03b6", "c": "\u03c2", "h": "\u03b7", "s": "\u03c3", "w": "\u03c9",
}
_ARMENIAN = {
    "a": "\u0561", "b": "\u0562", "g": "\u0563", "d": "\u0564", "e": "\u0565", "h": "\u0570", "i": "\u056b",
    "l": "\u056c", "n": "\u0576", "o": "\u0585", "p": "\u0570", "s": "\u057d", "t": "\u057f", "u": "\u0578",
    "j": "\u0571", "q": "\u0584", "f": "\u0586", "m": "\u0574", "r": "\u0580", "k": "\u056f",
}
_SCRIPTS = (("cyrillic", _CYRILLIC), ("greek", _GREEK), ("armenian", _ARMENIAN))

# Numbers that show up on fake-shop and campaign domains. Years are generated
# relative to the current year, so the list never goes stale.
_NUMERALS = ("1", "2", "3", "7", "01", "02", "24", "247", "365", "360", "100",
             "123", "99", "2000")


def _numeral_affixes():
    year = datetime.now().year
    years = [str(y) for y in range(year - 1, year + 3)]
    years += [y[2:] for y in years]
    seen, out = set(), []
    for v in list(_NUMERALS) + years:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


# Dynamic-DNS and free-hosting suffixes. Phishing pages are routinely served
# from <brand>.<provider>, which costs the attacker nothing and needs no
# registration, so no permutation of the brand's own domain would ever find
# them. A name here that resolves is a host somebody actually created.
_HOSTING_SUFFIXES = (
    # dynamic DNS
    "duckdns.org", "no-ip.org", "no-ip.com", "ddns.net", "hopto.org",
    "zapto.org", "serveo.net", "sytes.net", "myftp.org", "dynu.net",
    "freeddns.org", "chickenkiller.com",
    # free app / page hosting
    "github.io", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
    "herokuapp.com", "web.app", "firebaseapp.com", "glitch.me", "repl.co",
    "surge.sh", "onrender.com", "azurewebsites.net", "cloudfront.net",
    # free site builders / blogs
    "weebly.com", "wixsite.com", "blogspot.com", "000webhostapp.com",
    "square.site", "godaddysites.com",
    # tunnels, often used for short-lived phishing
    "ngrok.io", "ngrok.app", "trycloudflare.com", "loca.lt",
)

# Second-level domains a ccTLD registry offers. A brand on co.uk is squatted
# on org.uk; these are real, separate registrations (unlike a wrong TLD).
_SLD_FAMILIES = {
    "uk": ("co.uk", "org.uk", "me.uk", "ac.uk", "net.uk", "ltd.uk", "plc.uk"),
    "au": ("com.au", "net.au", "org.au", "id.au", "asn.au"),
    "nz": ("co.nz", "net.nz", "org.nz", "ac.nz", "geek.nz"),
    "jp": ("co.jp", "ne.jp", "or.jp", "ac.jp", "gr.jp"),
    "br": ("com.br", "net.br", "org.br", "ind.br"),
    "cn": ("com.cn", "net.cn", "org.cn", "gov.cn"),
    "za": ("co.za", "org.za", "net.za", "web.za"),
    "in": ("co.in", "net.in", "org.in", "firm.in", "gen.in"),
    "mx": ("com.mx", "org.mx", "net.mx"),
    "tw": ("com.tw", "net.tw", "org.tw", "idv.tw"),
    "kr": ("co.kr", "ne.kr", "or.kr", "re.kr"),
    "il": ("co.il", "org.il", "net.il", "ac.il"),
    "tr": ("com.tr", "net.tr", "org.tr", "biz.tr"),
    "ar": ("com.ar", "net.ar", "org.ar"),
    "ru": ("com.ru", "net.ru", "org.ru", "spb.ru"),
    "pl": ("com.pl", "net.pl", "org.pl", "info.pl"),
    "es": ("com.es", "org.es", "nom.es"),
    "pt": ("com.pt", "org.pt", "net.pt"),
}

# Spelling / phonetic swaps behind "common misspelling" squats. Applied both
# ways at every occurrence.
_PHONETIC = (
    ("ph", "f"), ("ck", "k"), ("c", "k"), ("s", "z"), ("ie", "ei"),
    ("ee", "ea"), ("oo", "u"), ("ou", "o"), ("qu", "kw"), ("x", "ks"),
    ("gh", "g"), ("tion", "sion"), ("ance", "ence"), ("able", "ible"),
    ("y", "ie"), ("i", "y"), ("er", "or"), ("ll", "l"), ("mm", "m"),
    ("nn", "n"), ("tt", "t"), ("ss", "s"),
)

# Words that show up on counterfeit / fake-shop domains, as opposed to the
# credential-phishing words in _DICTIONARY.
_SHOP_KEYWORDS = (
    "shop", "store", "outlet", "sale", "sales", "clearance", "discount",
    "discounts", "cheap", "deal", "deals", "offer", "offers", "official",
    "originals", "factory", "wholesale", "buy", "online", "shopping", "mall",
    "market", "bargain", "promo", "promotion", "blackfriday", "cybermonday",
    "vip", "club", "world", "global", "direct", "warehouse", "surplus",
    "liquidation", "new", "best", "top", "pro", "plus", "us", "uk", "eu",
    "de", "fr", "es", "it", "nl", "no", "se", "dk", "fi", "pl",
)

# TLDs that counterfeit shops favour: cheap, fast to register, weak vetting.
_SHOP_TLDS = (
    "shop", "store", "online", "site", "xyz", "top", "vip", "club", "icu",
    "cyou", "buzz", "sbs", "cfd", "bond", "quest", "monster", "beauty",
    "boutique", "sale", "deals", "discount", "fashion", "clothing", "shoes",
    "outlet", "company", "life", "live", "world", "website", "space", "fun",
    "net", "org", "co", "us", "eu", "de", "uk", "com",
)

# Named scan profiles. Each picks the fuzzers that matter for one kind of
# abuse, and may supply its own keyword list, TLD list, or extra checks.
# Anything given explicitly on the command line still wins.
_PRESETS = {
    "fakeshop": {
        "description": "counterfeit / fake web shops: brand + shop words, "
                       "cheap TLDs, free hosting",
        "fuzzers": ["dictionary", "numeral", "separator", "hyphenation",
                    "tld-swap", "various", "hosting", "omission",
                    "transposition"],
        "dictionary": _SHOP_KEYWORDS,
        "tlds": _SHOP_TLDS,
    },
    "phishing": {
        "description": "credential phishing: lookalikes, login/verify words, "
                       "free hosting",
        "fuzzers": ["homoglyph", "dictionary", "hosting", "separator",
                    "subdomain", "tld-typo", "tld-swap", "bitsquatting",
                    "numeral"],
    },
    "typo": {
        "description": "genuine typing mistakes: traffic interception and "
                       "drive-by mistypes",
        "fuzzers": ["omission", "repetition", "transposition", "replacement",
                    "insertion", "addition", "vowel-swap", "double-omission",
                    "reorder", "phonetic", "cardinal", "homophone",
                    "tld-typo"],
    },
    "homograph": {
        "description": "visual impersonation only: homoglyphs and IDN "
                       "whole-script look-alikes",
        "fuzzers": ["homoglyph", "cardinal"],
    },
    "bec": {
        "description": "business email compromise: mail-capable lookalikes "
                       "(turns on MX lookups)",
        "fuzzers": ["omission", "transposition", "replacement", "homoglyph",
                    "separator", "hyphenation", "tld-typo", "tld-swap",
                    "double-omission"],
        "mx": True,
    },
    "quick": {
        "description": "fast triage: the highest-yield fuzzers, smallest "
                       "candidate set",
        "fuzzers": ["omission", "transposition", "replacement", "tld-typo",
                    "tld-swap", "hosting", "various"],
    },
}


# Fuzzers weighted by how convincing / dangerous the result usually is.
_FUZZER_RISK = {
    "homoglyph": 5, "homoglyph-script": 6, "bitsquatting": 4, "dictionary": 4,
    "separator": 4, "numeral": 3, "double-omission": 2,
    "hosting": 5, "wrong-sld": 3, "phonetic": 3, "reorder": 2,
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
    # DNS answers. Default is one shared empty tuple: most candidates never
    # get any, and five fresh lists per candidate cost ~40% of the memory on
    # multi-million-candidate targets. Values are always replaced, never
    # mutated in place.
    dns_a: list[str] | tuple = ()
    dns_aaaa: list[str] | tuple = ()
    dns_mx: list[str] | tuple = ()
    dns_cname: list[str] | tuple = ()  # alias at the name
    dns_ns: list[str] | tuple = ()
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
    deep: bool = False             # extra dot: a host under a domain we do
                                   # not control, not a registration of its own
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
    def _add(self, fuzzer: str, new_name: str, tld: str | None = None,
             deep: bool | None = None):
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
                        target=self.original,
                        deep=("." in new_name) if deep is None else deep)
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
            self._add("addition", c + n)

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
        # whole-script confusables: if every letter of the label maps into one
        # alphabet, the result is visually identical but a separate domain
        for _script, table in _SCRIPTS:
            if n and all(c in table or c in "-." for c in n) and any(
                    c in table for c in n):
                self._add("homoglyph-script",
                          "".join(table.get(c, c) for c in n))

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

    def _separator(self):
        """Hyphen/dot edits. Brands that already contain a separator are
        squatted by dropping or swapping it (the-north-face -> thenorthface,
        the.north.face); brands that do not are squatted by splitting them
        into more than one word, which single-hyphen insertion cannot do."""
        n = self.name
        seps = [i for i, c in enumerate(n) if c in "-."]
        if seps:
            for i in seps:                       # drop one separator
                self._add("separator", n[:i] + n[i + 1:])
                other = "." if n[i] == "-" else "-"
                self._add("separator", n[:i] + other + n[i + 1:])
            if len(seps) > 1:                    # drop / swap all of them
                self._add("separator", "".join(c for c in n if c not in "-."))
                for sep in ("-", "."):
                    self._add("separator",
                              "".join(sep if c in "-." else c for c in n))
        # split into two extra words: covers the-north-face from thenorthface,
        # which the single-hyphen 'hyphenation' fuzzer can never reach
        if not seps and 4 <= len(n) <= 24:
            for i in range(1, len(n)):
                for j in range(i + 1, len(n)):
                    for sep in ("-", "."):
                        self._add("separator",
                                  n[:i] + sep + n[i:j] + sep + n[j:])

    def _numeral(self):
        """Numbers and years appended or prepended - the signature of
        fake-shop and seasonal campaign domains (brand2026, brand-24)."""
        n = self.name
        for v in _numeral_affixes():
            self._add("numeral", f"{n}{v}")
            self._add("numeral", f"{n}-{v}")
            self._add("numeral", f"{v}{n}")
            self._add("numeral", f"{v}-{n}")

    def _double_omission(self):
        """Two characters dropped: common in long brand names, where one
        missing letter is often accompanied by another."""
        n = self.name
        if len(n) < 6:
            return
        for i in range(len(n)):
            for j in range(i + 1, len(n)):
                self._add("double-omission", n[:i] + n[i + 1:j] + n[j + 1:])

    def _hosting(self):
        """<brand>.<dynamic-DNS or free-hosting provider>. Costs an attacker
        nothing, needs no registration, and is a standard way to serve a
        phishing page - so no permutation of the brand's own domain finds it."""
        for suffix in _HOSTING_SUFFIXES:
            if not self.original.endswith("." + suffix):
                # a host under somebody else's domain, not a registration
                self._add("hosting", self.name, tld=suffix, deep=True)

    def _wrong_sld(self):
        """Another second-level domain in the same ccTLD family: a brand on
        co.uk squatted on org.uk. Unlike a wrong TLD these are separate, real
        registrations under the same registry."""
        last = self.tld.rsplit(".", 1)[-1]
        for sld in _SLD_FAMILIES.get(last, ()):
            if sld != self.tld:
                self._add("wrong-sld", self.name, tld=sld)

    def _phonetic(self):
        """Common-misspelling squats: spelling and sound swaps such as
        ph/f and ck/k, applied in both directions."""
        n = self.name
        for a, b in _PHONETIC:
            for src, dst in ((a, b), (b, a)):
                start = 0
                while (pos := n.find(src, start)) != -1:
                    self._add("phonetic", n[:pos] + dst + n[pos + len(src):])
                    start = pos + 1

    def _reorder(self):
        """Letters swapped at a distance, not just adjacent ones - the
        'change order' typo that transposition alone cannot produce."""
        n = self.name
        for i in range(len(n)):
            for j in range(i + 2, min(i + 5, len(n))):
                if n[i] != n[j]:
                    self._add("reorder",
                              n[:i] + n[j] + n[i + 1:j] + n[i] + n[j + 1:])

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
        "separator": _separator, "numeral": _numeral,
        "double-omission": _double_omission, "hosting": _hosting,
        "wrong-sld": _wrong_sld, "phonetic": _phonetic, "reorder": _reorder,
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
# Terminal UI: header / notes / summary, plus adaptive live progress
# --------------------------------------------------------------------------- #

def _human(n):
    """Compact count: 9,999 / 123.4k / 3.62M."""
    n = int(n)
    if n < 10_000:
        return f"{n:,}"
    if n < 1_000_000:
        return f"{n / 1000:.1f}k"
    return f"{n / 1_000_000:.2f}M"


def _fmt_dur(seconds):
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h >= 24:
        d, h = divmod(h, 24)
        return f"{d}d{h:02d}h{m:02d}m"
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def _rstyle(style):
    """Map this module's style names onto rich style names."""
    return {"grey": "dim", None: ""}.get(style, style)


class UI:
    """All human-facing output (stderr).

    * real terminal: colour, and rich panels/tables when `rich` is installed
    * redirected (file / nohup / pipe): plain timestamped lines, no escape codes
    While a live dashboard is on screen, lines are routed through its console
    so they print above it instead of corrupting it.
    """

    _CODES = {
        "reset": "0", "bold": "1", "dim": "2",
        "red": "31", "green": "32", "yellow": "33", "blue": "34",
        "magenta": "35", "cyan": "36", "grey": "90",
    }

    def __init__(self, stream=None):
        self.stream = stream or sys.stderr
        self.tty = self.stream.isatty()
        # honour NO_COLOR (https://no-color.org) and dumb terminals
        self.color = (self.tty and os.environ.get("NO_COLOR") is None
                      and os.environ.get("TERM") != "dumb")
        self.rich = _HAVE_RICH and self.color
        self.live_console = None
        self._console = None

    @property
    def console(self):
        if self._console is None:
            self._console = Console(file=self.stream, highlight=False)
        return self._console

    def c(self, text, *styles):
        if not self.color or not styles:
            return text
        codes = ";".join(self._CODES[s] for s in styles if s in self._CODES)
        return f"\033[{codes}m{text}\033[0m" if codes else text

    def _emit(self, text):
        if self.live_console is not None:
            from rich.text import Text
            self.live_console.print(Text.from_ansi(text))
            return
        if self.tty or not text.strip():
            self.stream.write(text + "\n")
        else:
            ts = time.strftime("%H:%M:%S")
            self.stream.write(f"[{ts}] {text}\n")
        self.stream.flush()

    def print_rich(self, renderable):
        (self.live_console or self.console).print(renderable)

    def rule(self, title=""):
        if not self.tty:
            if title:
                self._emit("== " + title + " ==")
            return
        width = min(shutil.get_terminal_size((80, 24)).columns, 72)
        if title:
            bar = "─" * max(3, width - len(title) - 3)
            self.stream.write(self.c(f"── {self.c(title, 'bold')} {bar}",
                                     "grey") + "\n")
        else:
            self.stream.write(self.c("─" * width, "grey") + "\n")
        self.stream.flush()

    def item(self, label, value, style=None):
        lab = self.c(f"{label:>12}", "grey")
        val = self.c(str(value), style) if style else str(value)
        self._emit(f"{lab}  {val}")

    def header(self, title, rows):
        """rows: [(label, value, style_or_None), ...]"""
        if self.rich:
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text
            grid = Table.grid(padding=(0, 2))
            grid.add_column(style="dim", justify="right", no_wrap=True)
            grid.add_column()
            for label, value, style in rows:
                grid.add_row(label, Text(str(value), style=_rstyle(style)))
            self.print_rich(Panel(grid, title=f"[bold]{title}[/bold]",
                                  title_align="left", border_style="blue",
                                  expand=False, padding=(0, 1)))
            return
        self.rule(title)
        for label, value, style in rows:
            self.item(label, value, style)

    def note(self, text):
        self._emit(f"{self.c('note', 'cyan')}  {text}")

    def warn(self, text):
        self._emit(f"{self.c('warning', 'yellow')}  {text}")

    def error(self, text):
        self._emit(f"{self.c('error', 'red')}  {text}")

    def ok(self, text):
        self._emit(f"{self.c('ok', 'green')}  {text}")

    def line(self, text=""):
        self._emit(text)


class _ScanState:
    """Counters shared by the progress renderers: what is done, how fast,
    and an estimate of how long the whole run has left."""

    def __init__(self):
        self.lock = threading.Lock()
        self.t0 = None
        self.n_targets = 1
        self.targets_done = 0
        self.in_target = False
        self.cur_idx = 0
        self.cur_name = ""
        self.cur_total = 0
        self.cur_done = 0
        self.cur_live = 0
        self.cur_t0 = None
        self.prev_cand = 0          # candidates checked in finished targets
        self.prev_live = 0
        self.totals = []            # candidate count of every started target
        self.wild = self.lame = self.unres = 0
        self.recent = collections.deque(maxlen=8)

    def begin(self, n_targets):
        if self.t0 is None:
            self.t0 = time.monotonic()
        self.n_targets = max(1, n_targets)

    def begin_target(self, idx, n, name, total):
        self.begin(n)
        self.cur_idx, self.cur_name = idx, name
        self.cur_total, self.cur_done, self.cur_live = total, 0, 0
        self.cur_t0 = time.monotonic()
        self.in_target = True
        self.totals.append(total)

    def set_done(self, done, live):
        self.cur_done, self.cur_live = done, live

    def end_target(self):
        if not self.in_target:
            return
        self.prev_cand += self.cur_done
        self.prev_live += self.cur_live
        self.targets_done += 1
        self.in_target = False

    def found(self, perm):
        with self.lock:
            self.recent.appendleft((perm.risk, perm.ascii, perm.target,
                                    perm.fuzzer, time.monotonic()))

    def recent_snapshot(self):
        with self.lock:
            return list(self.recent)

    # -- derived numbers -------------------------------------------------- #
    @property
    def done_all(self):
        return self.prev_cand + (self.cur_done if self.in_target else 0)

    @property
    def live_all(self):
        return self.prev_live + (self.cur_live if self.in_target else 0)

    def elapsed(self):
        return time.monotonic() - self.t0 if self.t0 else 0.0

    def rate(self):
        e = self.elapsed()
        return self.done_all / e if e > 0 else 0.0

    def cur_rate(self):
        if not self.cur_t0:
            return 0.0
        e = time.monotonic() - self.cur_t0
        return self.cur_done / e if e > 0 else 0.0

    def cur_eta(self):
        r = self.cur_rate()
        return (self.cur_total - self.cur_done) / r if r > 0 else None

    def overall_eta(self):
        r = self.rate()
        if r <= 0:
            return None
        avg = (sum(self.totals) / len(self.totals)) if self.totals \
            else self.cur_total
        remaining = max(0, self.cur_total - self.cur_done) if self.in_target \
            else 0
        later = self.n_targets - self.targets_done - (1 if self.in_target else 0)
        remaining += avg * max(0, later)
        return remaining / r

    def overall_frac(self):
        frac_cur = (self.cur_done / self.cur_total
                    if self.in_target and self.cur_total else 0.0)
        return (self.targets_done + frac_cur) / self.n_targets


class Progress:
    """Progress for plain terminals (in-place ASCII bar) and for redirected
    output (throttled timestamped log lines that read well under `tail -f`).
    The rich live view is `Dashboard`; both share this interface:

      begin(n) / start_target(i, n, name, total) / update_target(done, live)
      found(perm) / target_done(info) / start(total) / update(done, live)
      finish(done, live) / set_counts(wild, lame, unresolved) / close()
    """

    def __init__(self, mode="auto", ui=None, label="scanning"):
        self.ui = ui or UI()
        self.stream = self.ui.stream
        self.label = label
        tty = self.stream.isatty()
        if mode == "none":
            self.kind = "none"
        elif mode == "plain" or not tty:
            self.kind = "plain"
        else:
            self.kind = "ascii"
        self.s = _ScanState()
        self._last_draw = 0.0
        self._last_log = 0.0
        self._last_pct = -1
        self._bar_shown = False

    _fmt = staticmethod(_fmt_dur)    # kept for callers of Progress._fmt

    # -- multi-target interface ------------------------------------------ #
    def begin(self, n_targets):
        self.s.begin(n_targets)

    def start_target(self, idx, n, name, total):
        self.s.begin_target(idx, n, name, total)
        self._last_pct = -1
        self._last_log = time.monotonic()
        if self.kind == "plain":
            self.ui._emit(f"[{idx}/{n}] {name}: scanning {total:,} candidates")

    def update_target(self, done, live):
        self.s.set_done(done, live)
        self._tick()

    def found(self, perm):
        self.s.found(perm)

    def set_counts(self, wild, lame, unresolved):
        self.s.wild, self.s.lame, self.s.unres = wild, lame, unresolved

    def target_done(self, info):
        self.s.end_target()
        if self.kind == "none":
            return
        self._clear_bar()
        self.ui._emit(_target_done_line(self.ui, info, self.s.n_targets))

    # -- single-pool interface (also called from Scanner / run_scan) ----- #
    def start(self, total):
        if self.s.in_target:
            self.s.cur_total = total        # repeated start: just resize
            return
        self.s.begin_target(1, 1, self.label, total)
        if self.kind == "plain":
            self.ui._emit(f"{self.label}: {total:,} candidates to check")

    def update(self, done, live):
        self.s.set_done(done, live)
        self._tick()

    def finish(self, done, live):
        self.s.set_done(done, live)
        if self.kind == "plain":
            self._log_status(force=True)
        self._clear_bar()

    def close(self):
        self._clear_bar()

    # -- rendering -------------------------------------------------------- #
    def _tick(self):
        if self.kind == "ascii":
            now = time.monotonic()
            if now - self._last_draw >= 0.1:
                self._last_draw = now
                self._draw_bar()
        elif self.kind == "plain":
            self._log_status()

    def _clear_bar(self):
        if self._bar_shown:
            self.stream.write("\r\033[K")
            self.stream.flush()
            self._bar_shown = False

    def _draw_bar(self):
        s = self.s
        cols = shutil.get_terminal_size((80, 24)).columns
        frac = s.cur_done / s.cur_total if s.cur_total else 1.0
        eta = s.cur_eta()
        head = (f"[{s.cur_idx}/{s.n_targets}] " if s.n_targets > 1 else "") \
            + s.cur_name
        stats = (f" {frac * 100:3.0f}% {_human(s.cur_done)}/"
                 f"{_human(s.cur_total)} live {s.live_all} "
                 f"{s.cur_rate():,.0f}/s eta "
                 f"{_fmt_dur(eta) if eta is not None else '--:--'}")
        width = max(10, min(40, cols - len(head) - len(stats) - 4))
        filled = int(width * frac)
        bar = ("█" * filled + "░" * (width - filled)) if self.ui.color \
            else ("#" * filled + "." * (width - filled))
        self.stream.write(f"\r\033[K{self.ui.c(head, 'bold', 'blue')} "
                          f"{self.ui.c(bar, 'cyan')}{stats}")
        self.stream.flush()
        self._bar_shown = True

    def _log_status(self, force=False):
        s = self.s
        now = time.monotonic()
        pct = int(s.cur_done / s.cur_total * 100) if s.cur_total else 100
        since = now - self._last_log
        if not force and not ((pct >= self._last_pct + 10 and since >= 15)
                              or since >= 60):
            return
        self._last_pct, self._last_log = pct, now
        eta = s.cur_eta()
        head = (f"[{s.cur_idx}/{s.n_targets}] " if s.n_targets > 1 else "") \
            + s.cur_name
        line = (f"{head}: {pct:3d}%  {s.cur_done:,}/{s.cur_total:,}  "
                f"live {s.cur_live}  {s.cur_rate():,.0f}/s  "
                f"eta {_fmt_dur(eta) if eta is not None else '?'}")
        if s.n_targets > 1:
            oeta = s.overall_eta()
            line += (f"  | run: {s.live_all} live, "
                     f"~{_fmt_dur(oeta) if oeta is not None else '?'} left")
        if s.recent:
            line += f"  | latest: {s.recent[0][1]}"
        self.ui._emit(line)


def _target_done_line(ui, info, n):
    """One line per finished target, shared by all renderers (ANSI styled)."""
    lv = info["live"]
    head = f"[{info['idx']}/{n}]"
    top = info.get("top")
    parts = [f"{ui.c('done', 'green')} {ui.c(head, 'grey')} "
             f"{ui.c(info['name'], 'bold')}",
             ui.c(f"{lv} live", "green" if lv else "grey"),
             f"{info['candidates']:,} checked"]
    if info.get("secs") is not None:
        rate = info["candidates"] / info["secs"] if info["secs"] > 0 else 0
        parts.append(f"{_fmt_dur(info['secs'])} ({rate:,.0f}/s)")
    if top is not None:
        col = "red" if top.risk >= 70 else "yellow" if top.risk >= 45 else "grey"
        parts.append(f"top {ui.c(top.ascii, col)} ({top.risk})")
    return "  ".join(parts)


class Dashboard(Progress):
    """Live rich dashboard (terminal + `rich`): overall and per-target bars,
    throughput / memory / DNS-health counters, and a feed of recent finds.

    All terminal output while the dashboard is up goes through ONE pump
    thread: other code only queues lines (via print()). Python's text stream
    is not thread-safe, and letting the scan thread and a refresh thread both
    write lost bytes, which made the dashboard erase lines above itself."""

    def __init__(self, ui, label="scanning"):
        super().__init__(mode="auto", ui=ui, label=label)
        self.kind = "rich"
        self.console = Console(file=ui.stream, highlight=False)
        self.live = None
        self._pending = collections.deque()
        self._stop = threading.Event()
        self._pump_thread = None

    # queued output: called by UI._emit / UI.print_rich while live
    def print(self, renderable):
        self._pending.append(renderable)

    def _flush(self):
        while self._pending:
            self.console.print(self._pending.popleft())
        if self.live is not None:
            self.live.refresh()

    def _pump(self):
        while not self._stop.wait(0.25):
            try:
                self._flush()
            except Exception:
                pass            # never let a render glitch kill the scan

    def _ensure_live(self):
        if self.live is None:
            from rich.live import Live
            self.live = Live(self, console=self.console, auto_refresh=False,
                             transient=True, redirect_stdout=False,
                             redirect_stderr=False)
            self.live.start()
            self.ui.live_console = self
            self._stop.clear()
            self._pump_thread = threading.Thread(target=self._pump,
                                                 name="twistr-ui", daemon=True)
            self._pump_thread.start()

    def begin(self, n_targets):
        super().begin(n_targets)
        self._ensure_live()

    def start_target(self, idx, n, name, total):
        self.s.begin_target(idx, n, name, total)
        self._ensure_live()

    def update_target(self, done, live):
        self.s.set_done(done, live)

    def target_done(self, info):
        self.s.end_target()
        self.ui._emit(_target_done_line(self.ui, info, self.s.n_targets))

    def start(self, total):
        if self.s.in_target:
            self.s.cur_total = total
            return
        self.s.begin_target(1, 1, self.label, total)
        self._ensure_live()

    def update(self, done, live):
        self.s.set_done(done, live)

    def finish(self, done, live):
        self.s.set_done(done, live)

    def close(self):
        if self.live is None:
            return
        self._stop.set()
        if self._pump_thread is not None:
            self._pump_thread.join(timeout=5)
            self._pump_thread = None
        try:
            self._flush()           # queued lines, then one last frame
            self.live.stop()        # transient: removes the dashboard
        finally:
            self.live = None
            self.ui.live_console = None

    # -- rendering (called from the pump thread via live.refresh) -------- #
    def __rich__(self):
        from rich.console import Group
        from rich.panel import Panel
        from rich.progress_bar import ProgressBar
        from rich.table import Table
        from rich.text import Text
        s = self.s
        grid = Table.grid(padding=(0, 1), expand=True)
        grid.add_column(style="dim", width=8, no_wrap=True)
        grid.add_column(ratio=1)
        grid.add_column(justify="right", no_wrap=True)

        if s.n_targets > 1:
            oeta = s.overall_eta()
            grid.add_row(
                "overall",
                ProgressBar(total=1.0, completed=s.overall_frac(),
                            complete_style="blue", finished_style="green"),
                Text.assemble((f"{s.targets_done}/{s.n_targets}", "bold"),
                              " targets  ", (f"{s.live_all} live", "green"),
                              "  eta ", (f"~{_fmt_dur(oeta)}" if oeta is not None
                                         else "--", "cyan")))
        frac = s.cur_done / s.cur_total if s.cur_total else 0.0
        ceta = s.cur_eta()
        name = (f"[{s.cur_idx}/{s.n_targets}] " if s.n_targets > 1 else "") \
            + s.cur_name
        grid.add_row("target", Text(name, style="bold"), "")
        grid.add_row(
            "",
            ProgressBar(total=1.0, completed=frac, complete_style="cyan",
                        finished_style="green"),
            Text.assemble(f"{frac * 100:3.0f}%  ",
                          f"{_human(s.cur_done)}/{_human(s.cur_total)}  ",
                          (f"{s.cur_live} live", "green"),
                          f"  {s.cur_rate():,.0f}/s  eta ",
                          (_fmt_dur(ceta) if ceta is not None else "--",
                           "cyan")))

        rss = _rss_bytes()
        stats = Text.assemble(
            ("elapsed ", "dim"), _fmt_dur(s.elapsed()),
            ("   checked ", "dim"), _human(s.done_all),
            ("   avg ", "dim"), f"{s.rate():,.0f}/s",
            ("   mem ", "dim"), f"{rss / 2**30:.1f} GB" if rss else "?",
            ("   wildcard ", "dim"), str(s.wild),
            ("   lame ", "dim"), str(s.lame),
            ("   unresolved ", "dim"),
            (str(s.unres), "yellow" if s.unres else ""))

        finds = Table.grid(padding=(0, 2))
        finds.add_column(justify="right", no_wrap=True)
        finds.add_column(no_wrap=True, overflow="ellipsis", max_width=40)
        finds.add_column(style="dim", no_wrap=True, overflow="ellipsis",
                         max_width=28)
        finds.add_column(style="dim", no_wrap=True)
        finds.add_column(style="dim", justify="right", no_wrap=True)
        now = time.monotonic()
        recent = s.recent_snapshot()
        for risk, dom, tgt, fz, t in recent:
            col = "red" if risk >= 70 else "yellow" if risk >= 45 else "green"
            ago = now - t
            age = f"{int(ago)}s ago" if ago < 120 else f"{int(ago // 60)}m ago"
            finds.add_row(Text(str(risk), style=col), dom, tgt, fz, age)
        body = [grid, Text(""), stats, Text("")]
        body.append(Text("recent finds", style="bold"))
        body.append(finds if recent else
                    Text("  no live lookalikes yet", style="dim"))
        return Panel(Group(*body), title="[bold]twistr[/bold] · scanning",
                     title_align="left", border_style="blue", padding=(0, 1))


_default_unraisablehook = sys.unraisablehook


def _quiet_unraisablehook(unraisable):
    exc = unraisable.exc_value
    where = f"{unraisable.err_msg or ''} {unraisable.object!r}"
    if (isinstance(exc, RuntimeError) and "Event loop is closed" in str(exc)
            and ("cffi callback" in where or "_cb" in where)):
        return
    _default_unraisablehook(unraisable)


sys.unraisablehook = _quiet_unraisablehook


def make_progress(mode, ui, label="scanning"):
    """Rich dashboard on a colour terminal with `rich`; otherwise Progress."""
    if mode != "none" and mode != "plain" and ui.rich:
        return Dashboard(ui, label=label)
    return Progress(mode=mode, ui=ui, label=label)


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

class _Gate:
    """Semaphore whose capacity can change while tasks wait on it."""

    def __init__(self, limit):
        self.limit = max(1, int(limit))
        self.active = 0
        self._waiters = collections.deque()

    async def acquire(self):
        if self.active < self.limit and not self._waiters:
            self.active += 1
            return
        fut = asyncio.get_running_loop().create_future()
        self._waiters.append(fut)
        await fut                       # the releaser counted us as active

    def release(self):
        self.active -= 1
        self._wake()

    def set_limit(self, limit):
        self.limit = max(1, int(limit))
        self._wake()

    @property
    def waiting(self):
        return len(self._waiters)

    def _wake(self):
        while self._waiters and self.active < self.limit:
            fut = self._waiters.popleft()
            if not fut.done():
                self.active += 1
                fut.set_result(None)


# Wildcard probe results, keyed by parent zone, kept for the life of the
# process. Each target used to build its own Scanner and re-probe the same
# parents (the 36 hosting providers above, and every TLD), which on a list of
# brands is thousands of wasted lookups against names that do not exist.
_WILD_CACHE = {}
_WILD_CACHE_MAX = 20000


# the concurrency the adaptive controller settled on, carried from one target
# (and one Scanner) to the next so each target does not start slow again
_LEARNED = {"limit": None}
_AUTO_MIN, _AUTO_START, _AUTO_MAX = 16, 64, 2048


class Scanner:
    def __init__(self, concurrency=64, timeout=5.0, nameservers=None,
                 do_web=False, do_rdap=False, do_favicon=False, do_mx=False,
                 base_fuzzy=None, base_favicon=None):
        self.adaptive = (concurrency == "auto")
        self.concurrency = (_LEARNED["limit"] or _AUTO_START) if self.adaptive \
            else int(concurrency)
        self.do_mx = do_mx
        self._qn = 0            # query attempts finished (for the controller)
        self._qf = 0            # of which transient failures (timeout/servfail)
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
            # Hard per-query deadline. c-ares's own timeout is per *server*:
            # after one times out it tries the next, so with 12 resolvers a
            # dead name could take 12 x timeout. A single timer that cancels
            # the future caps the total, and is far cheaper than
            # asyncio.wait_for (which cost ~13% CPU per query).
            # aiodns returns a Future; ensure_future keeps the deadline
            # working if that ever becomes a plain coroutine
            fut = asyncio.ensure_future(self._qfn(name, rtype))
            expired = []
            timer = self._loop.call_later(
                self.timeout, lambda f=fut, x=expired: (x.append(1), f.cancel()))
            try:
                res = await fut
                self._qn += 1
                return ("ok", self._dns_values(res, rtype, name),
                        self._dns_values(res, "CNAME", name, own=True))
            except asyncio.CancelledError:
                if not expired:
                    raise               # a real cancellation (Ctrl-C, shutdown)
                self._qn += 1
                self._qf += 1
                status = "servfail" if status == "servfail" else "fail"
                if attempt + 1 < attempts:
                    await asyncio.sleep(0.2 * (attempt + 1))
                continue
            except Exception as e:
                self._qn += 1
                code = e.args[0] if getattr(e, "args", None) else None
                if code == 4:
                    return "nx", None, None     # definitive: does not exist
                if code == 1:
                    return "nodata", None, None  # exists, no such record
                self._qf += 1
                status = ("servfail" if code == 3 or status == "servfail"
                          else "fail")
                if attempt + 1 < attempts:
                    await asyncio.sleep(0.2 * (attempt + 1))
            finally:
                timer.cancel()
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
        # AAAA is asked for only when A came back empty: an address of either
        # family proves the same thing, and almost every live name has an A
        # record, so this drops a query for most names that exist.
        qtypes = ["A"] + (["MX"] if self.do_mx else [])
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
            else:
                perm.dns_mx = vals
        if not perm.dns_a and not cnames:
            s6, v6, cn6 = await self._query(perm.ascii, "AAAA", attempts)
            cnames.update(cn6 or [])
            if s6 in ("servfail", "fail"):
                failed = True
            if v6:
                perm.dns_aaaa = v6
        # a name that exists only because its parent zone answers for *any*
        # name (wildcard DNS) is not a registration: no delegation of its own
        # and the same addresses as a random name in that zone
        perm.dns_cname = sorted(cnames)
        perm.wildcard = False
        if perm.dns_a or perm.dns_ns or perm.dns_cname:
            wa, wn, wc, catch_all = await self._wildcard_addrs(
                perm.ascii.split(".", 1)[1])
            ns_same = {n.lower() for n in perm.dns_ns} == wn
            if catch_all and ns_same:
                perm.wildcard = True        # zone answers for any name
            elif wa or wn or wc:
                a_same = bool(set(perm.dns_a) & wa) if perm.dns_a else not wa
                c_same = {c.lower() for c in perm.dns_cname} == wc
                perm.wildcard = a_same and ns_same and c_same
        # name exists but we could not confirm anything -> worth a retry
        perm._dns = "fail" if (failed and not perm.registered
                               and not perm.wildcard) else "ok"

    async def _wildcard_addrs(self, parent):
        """(addresses, nameservers) a random label under `parent` gets - both
        empty if the zone has no wildcard. Probed once per zone and cached;
        concurrent callers share the same probe."""
        hit = _WILD_CACHE.get(parent)
        if hit is not None:
            return hit
        # in-flight probes are shared within this event loop; finished ones are
        # shared with every later target through _WILD_CACHE
        cache = self.__dict__.setdefault("_wild", {})
        fut = cache.get(parent)
        if fut is None:
            fut = cache[parent] = asyncio.ensure_future(self._probe_wild(parent))
        try:
            result = await asyncio.shield(fut)
        except Exception:
            return set(), set(), set(), False
        if len(_WILD_CACHE) < _WILD_CACHE_MAX:
            _WILD_CACHE[parent] = result
        return result

    async def _probe_wild(self, parent):
        addrs, ns, cn = set(), set(), set()
        answered = probes = 0
        for _ in range(3):                  # random labels, union of answers
            name = "zq" + "".join(random.choices(
                string.ascii_lowercase + string.digits, k=14)) + "." + parent
            probes += 1
            st, vals, c = await self._query(name, "A", 3)
            if st == "nx":
                break                       # no wildcard in this zone
            if vals:
                answered += 1
                addrs.update(vals)
            cn.update(x.lower() for x in (c or []))
            st, vals, c = await self._query(name, "NS", 3)
            ns.update(v.lower() for v in (vals or []))
        # a zone that answers for every random name answers for anything, so a
        # candidate resolving there is no evidence at all. Catching this by
        # address alone fails on hosts that rotate IPs (vercel, netlify, ...).
        catch_all = probes >= 2 and answered == probes
        return addrs, ns, cn, catch_all

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

    async def _pool(self, items, session, width, attempts, on_done,
                    adaptive=False):
        """Bounded worker pool: at most gate.limit scans in flight, so file
        descriptors / memory stay flat. With adaptive=True the limit is tuned
        while running (see _control)."""
        queue = collections.deque(items)
        gate = _Gate(width)
        done = [0]

        async def worker():
            while True:
                await gate.acquire()
                if not queue:
                    gate.release()
                    return
                perm = queue.popleft()
                try:
                    await self._scan_one(perm, session, attempts)
                finally:
                    gate.release()
                done[0] += 1
                on_done(perm)

        n_workers = _AUTO_MAX if adaptive else width
        n_workers = max(1, min(n_workers, len(items)))
        ctl = None
        if adaptive and len(items) > 2000:
            ctl = asyncio.ensure_future(self._control(gate, queue, done))
        try:
            await asyncio.gather(*[worker() for _ in range(n_workers)])
        finally:
            if ctl is not None:
                ctl.cancel()
                try:
                    await ctl
                except BaseException:
                    pass

    async def _control(self, gate, queue, done):
        """Adaptive concurrency: raise queries-in-flight while throughput keeps
        rising, step back when it stops (CPU- or resolver-bound), and back off
        hard when transient failures appear (rate limiting / overload)."""
        window = 1.0
        hold = 0
        prev_rate = None
        prev_limit = gate.limit
        last_done, last_qn, last_qf = done[0], self._qn, self._qf
        while True:
            await asyncio.sleep(window)
            n, qn, qf = done[0], self._qn, self._qf
            rate = (n - last_done) / window
            q, f = qn - last_qn, qf - last_qf
            last_done, last_qn, last_qf = n, qn, qf
            if len(queue) < gate.limit * 2:
                continue                # draining: no signal left
            fail = f / q if q else 0.0
            if q >= 50 and fail > 0.02:
                gate.set_limit(max(_AUTO_MIN, int(gate.limit * 0.7)))
                hold, prev_rate = 5, None
            elif hold > 0:
                hold -= 1
                prev_rate = None
            elif prev_rate is not None and gate.limit > prev_limit \
                    and rate < prev_rate * 1.05:
                # the last increase bought nothing: go back, rest, then probe
                gate.set_limit(prev_limit)
                hold, prev_rate = 8, None
            elif gate.active >= gate.limit * 0.9 and gate.limit < _AUTO_MAX:
                prev_limit, prev_rate = gate.limit, rate
                gate.set_limit(min(_AUTO_MAX, int(gate.limit * 1.3) + 4))
            else:
                prev_rate = rate
            _LEARNED["limit"] = gate.limit
            self.concurrency = gate.limit

    def _use_resolver(self, timeout):
        """(Re)create the c-ares resolver with the given per-query timeout.
        The timeout lives in c-ares itself, so a longer one (calm retry
        rounds) needs a fresh resolver."""
        old = self._resolver
        kw = dict(timeout=timeout, tries=1)
        if self.nameservers and len(self.nameservers) > 1:
            kw["rotate"] = True         # spread load across all resolvers
        try:
            self._resolver = aiodns.DNSResolver(
                nameservers=self.nameservers or None, **kw)
        except TypeError:                # older aiodns without these options
            self._resolver = aiodns.DNSResolver(
                nameservers=self.nameservers or None, timeout=timeout)
        # prefer the non-deprecated query_dns() (aiodns >= 4.0)
        self._qfn = getattr(self._resolver, "query_dns", None) \
            or self._resolver.query
        if old is not None:
            try:
                old.cancel()
            except Exception:
                pass

    async def scan(self, perms, progress=None, prime=True, on_result=None):
        self._loop = asyncio.get_running_loop()
        if _HAVE_AIODNS:
            self._use_resolver(self.timeout)
        else:
            # the socket resolver runs in the loop's thread pool, whose default
            # size (~min(32, cpus+4)) would otherwise cap --concurrency
            loop = asyncio.get_running_loop()
            loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(
                max_workers=min(_AUTO_MAX if self.adaptive
                                else self.concurrency, 256)))
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
                             first_pass_done, adaptive=self.adaptive)
            if progress:
                progress.finish(done, live)
            finished = True

            # calm second pass: transient failures from load spikes are retried
            # at low concurrency with more patience, so they no longer cost us
            # real domains. A SERVFAIL that survives this is a lame delegation:
            # the TLD delegated the name, so it is registered (dnstwist agrees).
            if unsettled:
                self._calm = True
                for rnd in range(3):
                    if not unsettled:
                        break
                    self.timeout *= 1.5
                    if _HAVE_AIODNS:
                        self._use_resolver(self.timeout)
                    # sized by the work left, NOT by the learned concurrency:
                    # a slow resolver can teach 'auto' a small limit, and the
                    # retry rounds must not inherit that
                    width = max(8, min(32, len(unsettled)))
                    await self._pool(unsettled, session, width, 2,
                                     lambda p: None)
                    still = [p for p in unsettled
                             if getattr(p, "_dns", "") in ("servfail", "fail")]
                    # a round that recovered nothing will not be helped by
                    # another, longer one: classify what is left now instead
                    # of spending up to ~a minute more on names that never
                    # answer
                    last = rnd == 2 or len(still) == len(unsettled)
                    remaining = []
                    for p in unsettled:
                        st = getattr(p, "_dns", "")
                        if st in ("servfail", "fail") and not last:
                            remaining.append(p)        # try again, calmer
                            continue
                        # never a definitive answer, but SERVFAIL while the
                        # resolver was idle -> lame delegation (registered)
                        if (st in ("servfail", "fail")
                                and getattr(p, "_sf", False) and not p.deep):
                            p._dns = "servfail"
                            p.dns_ns = ["!servfail"]
                            p.risk = score(p)
                        emit(p)
                    unsettled = remaining
        finally:
            if progress and not finished:
                progress.finish(done, live)
            if session is not None:
                await session.close()
            # stop in-flight DNS queries while the loop is still running, so
            # their callbacks don't fire into a closed loop (Ctrl-C, errors)
            if self._resolver is not None:
                try:
                    self._resolver.cancel()
                    closer = getattr(self._resolver, "close", None)
                    if closer is not None and asyncio.iscoroutinefunction(closer):
                        await asyncio.wait_for(closer(), 2)
                except BaseException:
                    pass
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

    shards = max(processes, 1) * (4 if concurrency == "auto" else 10)
    batch_size = max(25, math.ceil(len(perms) / shards))
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
    if progress:
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
            if progress:
                progress.update(done, live)
    if progress:
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
            addrs = ", ".join([*p.dns_a, *p.dns_aaaa]) or "-"
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
        addrs = ", ".join([*p.dns_a, *p.dns_aaaa]) or "-"
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

__version__ = "1.0.0"


def _concurrency_arg(value):
    if str(value).lower() == "auto":
        return "auto"
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a number or 'auto'")
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n


def build_parser():
    p = argparse.ArgumentParser(
        description="Generate and scan lookalike domains (dnstwist-style).")
    p.add_argument("domain", nargs="*",
                   help="one or more target domains, e.g. example.com "
                        "brand.co.uk. Omit to read from --input or stdin.")
    p.add_argument("-i", "--input", metavar="FILE",
                   help="read target domains from FILE (one per line; "
                        "blank lines and #comments ignored). Use '-' for stdin.")
    p.add_argument("--preset", choices=sorted(_PRESETS),
                   help="scan profile: picks the fuzzers (and sometimes the "
                        "keywords, TLDs and checks) that matter for one kind "
                        "of abuse. --list-presets shows what each one does. "
                        "Anything you pass explicitly still wins.")
    p.add_argument("--list-presets", action="store_true",
                   help="print the available presets and exit")
    p.add_argument("--fuzzers", help="comma-separated subset of fuzzers "
                   f"(default all: {','.join(DomainFuzzer._ALL)})")
    p.add_argument("--all-idn", action="store_true",
                   help="generate IDN lookalikes even with characters the "
                        "TLD's registry does not accept (default: skip them)")
    p.add_argument("-V", "--version", action="version",
                   version=f"twistr {__version__}")
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
    p.add_argument("--concurrency", type=_concurrency_arg, default="auto",
                   metavar="N|auto",
                   help="lookups in flight per process. 'auto' (default) "
                        "starts at 64 and adapts: it raises the limit while "
                        "throughput keeps improving and backs off when the "
                        "resolvers start failing. A number fixes it.")
    p.add_argument("-P", "--processes", type=int, default=1,
                   help="split the scan across N worker processes to use "
                        "multiple cores (helps most with --web/ppdeep or very "
                        "high concurrency; try your core count, e.g. 6)")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--nameservers", metavar="LIST",
                   help="comma-separated resolvers (needs aiodns), e.g. "
                        "1.1.1.1,8.8.4.4 or 127.0.0.1:5335. The word "
                        "'unfiltered' expands to a vetted set of 12 public "
                        "resolvers from 6 providers that do not block domains. "
                        "Known filtering resolvers are refused, because they "
                        "hide phishing domains.")
    p.add_argument("--allow-filtering-resolvers", action="store_true",
                   help="allow resolvers known to filter/block domains "
                        "(not recommended: blocked lookalikes look unregistered)")
    p.add_argument("--check-resolvers", action="store_true",
                   help="health-check the --nameservers (or the unfiltered "
                        "preset if none given) and exit")
    p.add_argument("--progress", choices=["auto", "bar", "plain", "none"],
                   default="auto",
                   help="progress style: auto (bar on a terminal, log lines "
                        "when redirected), bar, plain (timestamped lines), "
                        "or none")
    p.add_argument("--top", type=int, default=15, metavar="N",
                   help="how many findings to list in the summary (default 15)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="only print warnings/errors and the final summary "
                        "(no header, no progress, no per-target lines)")
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


# --------------------------------------------------------------------------- #
# Resolver selection: unfiltered presets, filtering guard, health check
# --------------------------------------------------------------------------- #

# Public resolvers that do NOT filter by default. A filtering resolver hides
# exactly what twistr hunts for: known phishing / malware domains get NXDOMAIN
# (so they look unregistered) or a sinkhole / block-page address (a fake
# answer). Spread across six providers so per-IP rate limits apply to each
# provider separately.
_UNFILTERED_RESOLVERS = [
    ("1.1.1.1", "Cloudflare"), ("1.0.0.1", "Cloudflare"),
    ("8.8.8.8", "Google"), ("8.8.4.4", "Google"),
    ("9.9.9.10", "Quad9 unsecured"), ("149.112.112.10", "Quad9 unsecured"),
    ("208.67.222.2", "OpenDNS Sandbox"), ("208.67.220.2", "OpenDNS Sandbox"),
    ("94.140.14.140", "AdGuard non-filtering"),
    ("94.140.14.141", "AdGuard non-filtering"),
    ("76.76.2.0", "Control D unfiltered"), ("76.76.10.0", "Control D unfiltered"),
]

# Well-known resolvers that DO filter by default -> (what it is, unfiltered
# alternative). Refused unless --allow-filtering-resolvers is given.
_FILTERING_RESOLVERS = {
    "9.9.9.9": ("Quad9 secure - blocks malicious domains", "9.9.9.10"),
    "149.112.112.112": ("Quad9 secure - blocks malicious domains",
                        "149.112.112.10"),
    "9.9.9.11": ("Quad9 secure+ECS - blocks malicious domains", "9.9.9.10"),
    "149.112.112.11": ("Quad9 secure+ECS - blocks malicious domains",
                       "149.112.112.10"),
    "2620:fe::fe": ("Quad9 secure - blocks malicious domains", "2620:fe::10"),
    "2620:fe::9": ("Quad9 secure - blocks malicious domains", "2620:fe::fe:10"),
    "1.1.1.2": ("Cloudflare for Families - blocks malware", "1.1.1.1"),
    "1.0.0.2": ("Cloudflare for Families - blocks malware", "1.0.0.1"),
    "1.1.1.3": ("Cloudflare for Families - blocks malware + adult", "1.1.1.1"),
    "1.0.0.3": ("Cloudflare for Families - blocks malware + adult", "1.0.0.1"),
    "2606:4700:4700::1112": ("Cloudflare for Families - blocks malware",
                             "2606:4700:4700::1111"),
    "2606:4700:4700::1113": ("Cloudflare for Families - blocks malware + adult",
                             "2606:4700:4700::1111"),
    "208.67.222.222": ("OpenDNS - blocks phishing by default", "208.67.222.2"),
    "208.67.220.220": ("OpenDNS - blocks phishing by default", "208.67.220.2"),
    "208.67.222.123": ("OpenDNS FamilyShield - content filter", "208.67.222.2"),
    "208.67.220.123": ("OpenDNS FamilyShield - content filter", "208.67.220.2"),
    "94.140.14.14": ("AdGuard default - blocks ads/trackers/phishing",
                     "94.140.14.140"),
    "94.140.15.15": ("AdGuard default - blocks ads/trackers/phishing",
                     "94.140.14.141"),
    "94.140.14.15": ("AdGuard Family - content filter", "94.140.14.140"),
    "94.140.15.16": ("AdGuard Family - content filter", "94.140.14.141"),
    "185.228.168.9": ("CleanBrowsing Security - filters", "1.1.1.1"),
    "185.228.169.9": ("CleanBrowsing Security - filters", "1.0.0.1"),
    "185.228.168.10": ("CleanBrowsing Adult - filters", "1.1.1.1"),
    "185.228.169.11": ("CleanBrowsing Adult - filters", "1.0.0.1"),
    "185.228.168.168": ("CleanBrowsing Family - filters", "1.1.1.1"),
    "185.228.169.168": ("CleanBrowsing Family - filters", "1.0.0.1"),
    "77.88.8.88": ("Yandex Safe - blocks fraud/malware", "77.88.8.8"),
    "77.88.8.2": ("Yandex Safe - blocks fraud/malware", "77.88.8.1"),
    "77.88.8.7": ("Yandex Family - content filter", "77.88.8.8"),
    "77.88.8.3": ("Yandex Family - content filter", "77.88.8.1"),
    "2606:4700:4700::1002": ("Cloudflare for Families - blocks malware",
                             "2606:4700:4700::1001"),
    "2606:4700:4700::1003": ("Cloudflare for Families - blocks malware + adult",
                             "2606:4700:4700::1001"),
    "76.76.2.1": ("Control D - blocks malware", "76.76.2.0"),
    "76.76.10.1": ("Control D - blocks malware", "76.76.10.0"),
    "76.76.2.2": ("Control D - blocks malware/ads/trackers", "76.76.2.0"),
    "76.76.10.2": ("Control D - blocks malware/ads/trackers", "76.76.10.0"),
    "76.76.2.3": ("Control D - blocks malware/ads/social", "76.76.2.0"),
    "76.76.10.3": ("Control D - blocks malware/ads/social", "76.76.10.0"),
    "76.76.2.4": ("Control D Family - content filter", "76.76.2.0"),
    "76.76.10.4": ("Control D Family - content filter", "76.76.10.0"),
    "86.54.11.1": ("DNS4EU protective - blocks malware/phishing", "1.1.1.1"),
    "86.54.11.201": ("DNS4EU protective - blocks malware/phishing", "1.0.0.1"),
    "86.54.11.11": ("DNS4EU child/no-ads - filters", "1.1.1.1"),
    "86.54.11.211": ("DNS4EU child/no-ads - filters", "1.0.0.1"),
    "86.54.11.12": ("DNS4EU child - filters", "1.1.1.1"),
    "86.54.11.212": ("DNS4EU child - filters", "1.0.0.1"),
    "86.54.11.13": ("DNS4EU no-ads - filters", "1.1.1.1"),
    "86.54.11.213": ("DNS4EU no-ads - filters", "1.0.0.1"),
}

_RESOLVER_NAMES = dict(_UNFILTERED_RESOLVERS)


def _ns_host(ns):
    """Strip an optional :port (and [brackets] for IPv6) from a resolver spec."""
    ns = ns.strip()
    if ns.startswith("["):
        return ns[1:ns.index("]")] if "]" in ns else ns[1:]
    if ns.count(":") == 1:           # IPv4 or hostname with a port
        return ns.split(":")[0]
    return ns                        # bare IPv6 (or plain IPv4)


def parse_nameservers(spec, allow_filtering=False):
    """Expand a --nameservers value into a resolver list.
    Accepts IPs (optionally ip:port) and the preset word 'unfiltered'.
    Returns (list, error_message_or_None)."""
    out = []
    for tok in (t.strip() for t in spec.split(",")):
        if not tok:
            continue
        if tok.lower() in ("unfiltered", "public"):
            out.extend(ip for ip, _ in _UNFILTERED_RESOLVERS)
        else:
            out.append(tok)
    seen, uniq = set(), []
    for ns in out:
        if ns not in seen:
            seen.add(ns)
            uniq.append(ns)
    bad = [(ns, *_FILTERING_RESOLVERS[_ns_host(ns)]) for ns in uniq
           if _ns_host(ns) in _FILTERING_RESOLVERS]
    if bad and not allow_filtering:
        lines = [f"    {ns:18} {what}  ->  use {alt} instead"
                 for ns, what, alt in bad]
        msg = ("these resolvers FILTER by default, which would hide exactly the "
               "phishing/malware lookalikes twistr is looking for (blocked "
               "names come back as 'does not exist' or as a fake block-page "
               "address):\n" + "\n".join(lines) +
               "\n  Use '--nameservers unfiltered' for a vetted unfiltered set, "
               "or --allow-filtering-resolvers to override.")
        return None, msg
    return uniq, None


async def _probe_one(ns, timeout):
    """Health-check one resolver: must answer a real name, and must return
    NXDOMAIN for a random non-existent one (not a fake address)."""
    try:
        r = aiodns.DNSResolver(nameservers=[ns], timeout=timeout, tries=1)
        qfn = getattr(r, "query_dns", None) or r.query
    except Exception as e:
        return ns, "error", f"cannot create resolver: {e}", None
    t = time.monotonic()
    ok = False
    for _ in range(2):
        try:
            await asyncio.wait_for(qfn("example.com", "A"), timeout)
            ok = True
            break
        except Exception:
            continue
    latency = (time.monotonic() - t) * 1000
    if not ok:
        return ns, "dead", "no answer for example.com", None
    fake = "zq" + "".join(random.choices(string.ascii_lowercase +
                                         string.digits, k=16)) + ".com"
    try:
        res = await asyncio.wait_for(qfn(fake, "A"), timeout)
        vals = Scanner._dns_values(res, "A")
        return ns, "hijack", (f"answers {', '.join(vals) or 'something'} for a "
                              f"name that does not exist (NXDOMAIN "
                              f"rewriting)"), latency
    except Exception as e:
        code = e.args[0] if getattr(e, "args", None) else None
        if code == 4:
            return ns, "ok", "", latency
        return ns, "ok", "did not return NXDOMAIN cleanly (kept)", latency


def check_resolvers(nameservers, timeout=3.0):
    """Probe every resolver concurrently; returns a list of result tuples."""
    async def run():
        return await asyncio.gather(*[_probe_one(ns, timeout)
                                      for ns in nameservers])
    return asyncio.run(run())


def _report_resolvers(results, ui=None):
    """Resolver health table: rich on a colour terminal, plain lines otherwise."""
    ui = ui or UI()
    if ui.rich:
        from rich.table import Table
        from rich.text import Text
        t = Table(show_header=True, header_style="bold", box=None,
                  padding=(0, 2))
        for col in ("status", "resolver", "provider", "latency", "detail"):
            t.add_column(col, justify="right" if col == "latency" else "left")
        for ns, status, detail, lat in results:
            tag, col = {"ok": ("ok", "green"), "dead": ("DEAD", "red"),
                        "hijack": ("BAD", "red"),
                        "error": ("ERR", "red")}.get(status, (status, "yellow"))
            t.add_row(Text(tag, style=col), ns,
                      _RESOLVER_NAMES.get(_ns_host(ns), "custom"),
                      f"{lat:.0f} ms" if lat is not None else "-",
                      Text(detail or "", style="dim"))
        ui.print_rich(t)
        return
    for ns, status, detail, lat in results:
        name = _RESOLVER_NAMES.get(_ns_host(ns), "")
        label = f"{ns} ({name})" if name else ns
        ms = f"{lat:5.0f} ms" if lat is not None else "     - "
        tag = {"ok": "ok  ", "dead": "DEAD", "hijack": "BAD ",
               "error": "ERR "}.get(status, status)
        extra = f"  {detail}" if detail else ""
        ui.line(f"  [{tag}] {label:40} {ms}{extra}")


def _warn_missing():
    missing = []
    if not _HAVE_AIODNS:
        missing.append("aiodns (MX/NS lookups + custom resolvers disabled)")
    if not _HAVE_TLDEXTRACT:
        missing.append("tldextract (using heuristic suffix splitting)")
    if not _HAVE_RICH:
        missing.append("rich (plain progress/summary)")
    if missing:
        UI().note("optional libs not found -> " + "; ".join(missing))


def _target_stats(perms, idx=None, secs=None):
    """Per-target numbers for the summary table, from one target's results."""
    cands = [p for p in perms if p.fuzzer != "original"]
    reg = [p for p in cands if p.registered]
    top = max(reg, key=lambda p: p.risk) if reg else None
    name = perms[0].target if perms else "?"
    return {"idx": idx, "name": name, "candidates": len(cands),
            "live": len(reg), "high": sum(1 for p in reg if p.risk >= 70),
            "top": top, "secs": secs}


def _resolves_to(p):
    if p.dns_a:
        return p.dns_a[0]
    if p.dns_aaaa:
        return p.dns_aaaa[0]
    if p.dns_cname:
        return "cname " + p.dns_cname[0]
    if p.dns_ns == ["!servfail"]:
        return "lame (SERVFAIL)"
    if p.dns_ns:
        return "ns " + p.dns_ns[0]
    return ""


def _noise_note(reg):
    """One fuzzer producing most of the hits usually means noise rather than
    signal - combosquat words match unrelated businesses, especially for short
    or dictionary-word brands."""
    if len(reg) < 200:
        return ""
    top, n = collections.Counter(p.fuzzer for p in reg).most_common(1)[0]
    share = n / len(reg)
    if share < 0.5:
        return ""
    advice = {
        "dictionary": "brand+keyword matches hit unrelated businesses, "
                      "especially for short or dictionary-word brands - try "
                      "--preset phishing, or your own --dictionary",
        "hosting": "most of these are old, unrelated registrations on free "
                   "hosts - add --all-checks to see which are actually live "
                   "pages",
        "tld-swap": "many of these are the brand's own defensive "
                    "registrations - check the owner before acting",
    }.get(top, "consider a narrower --fuzzers set or a --preset")
    return f"{n:,} of {len(reg):,} findings ({share:.0%}) come from {top}: {advice}"


def _band_note(checks, reg):
    """HIGH needs signals that only the optional checks produce. Without them
    the band is unreachable, so say that instead of showing a silent '0 high'."""
    if not reg or any(p.risk >= 70 for p in reg):
        return ""
    have_mail = "mx" in checks
    if not ({"rdap", "web", "favicon"} & set(checks)):
        extra = "" if have_mail else " (and --mx for mail capability)"
        return ("no HIGH is possible from DNS alone - registration age, page "
                f"content and favicon are what push a result over 70{extra}")
    return ""


def _next_step_hint(checks, reg):
    """One actionable line: the cheapest thing that would sharpen these
    results. Only suggests work that has not been done already."""
    if not reg:
        return ""
    missing = [c for c in ("rdap", "web", "mx") if c not in checks]
    if missing and len(reg) <= 400:
        names = {"rdap": "registration age", "web": "page content",
                 "mx": "mail capability"}
        what = ", ".join(names[m] for m in missing)
        return (f"re-run the hits with --all-checks to add {what} "
                f"- feed this run's output file back in with -i")
    if "ct" not in checks:
        return "add --ct to pull lookalikes out of Certificate Transparency logs"
    return ""


def _severity(risk):
    """Label as well as colour, so the ranking survives a colour-blind reader,
    a black-and-white terminal and a log file."""
    if risk >= 70:
        return "HIGH", "red"
    if risk >= 45:
        return "MED", "yellow"
    return "LOW", "green"


def _signals(p):
    """The short reasons this result scored what it did - the 'why' behind the
    number, so a row can be judged without opening the CSV."""
    out = []
    if p.dns_a or p.dns_aaaa:
        out.append("live")
    elif p.dns_cname:
        out.append("alias")
    elif p.dns_ns == ["!servfail"]:
        out.append("lame-ns")
    elif p.dns_ns:
        out.append("delegated")
    if p.dns_mx:
        out.append("mail")
    if p.age_days is not None:
        if p.age_days <= 30:
            out.append(f"new {p.age_days}d")
        elif p.age_days <= 365:
            out.append(f"{p.age_days // 30}mo old")
    if p.fuzzy is not None and p.fuzzy >= 40:
        out.append(f"clone {p.fuzzy}%")
    if p.favicon_match:
        out.append("same favicon")
    if p.http_status and p.http_status < 400:
        out.append(f"http {p.http_status}")
    if p.ct:
        out.append("cert")
    if p.title and p.target:
        brand = p.target.split(".", 1)[0]
        if len(brand) >= 3 and brand in p.title.lower():
            out.append("brand in title")
    return ", ".join(out)


def _summarize(ui, perms, only_registered, ml, elapsed, total_generated,
               live, wild, lame, unresolved, target_stats, out_path=None,
               n_written=None, top_n=15, checks=()):
    """End-of-run summary: totals, risk mix, per-target table, findings by
    fuzzer, and the top findings ranked by risk across all targets."""
    rows = _rows(perms, only_registered, ml)
    # ties on risk are common with DNS-only scans, so break them by how
    # convincing the technique is rather than by alphabet
    reg = sorted((p for p in rows if p.registered),
                 key=lambda p: (-p.risk, -_FUZZER_RISK.get(p.fuzzer, 1),
                                p.target, p.ascii))
    hi = sum(1 for p in reg if p.risk >= 70)
    med = sum(1 for p in reg if 45 <= p.risk < 70)
    low = len(reg) - hi - med
    rate = total_generated / elapsed if elapsed > 0 else 0
    by_fuzzer = collections.Counter(p.fuzzer for p in reg).most_common(8)
    multi = len(target_stats) > 1
    top = reg[:max(0, top_n)]
    filt = [f"{wild} wildcard ignored" if wild else "",
            f"{lame} lame counted" if lame else "",
            f"{unresolved} unresolved" if unresolved else ""]
    filt = " · ".join(x for x in filt if x)

    if ui.rich:
        from rich.console import Group
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", justify="right", no_wrap=True)
        grid.add_column()
        grid.add_row("registered", Text.assemble(
            (f"{live:,}", "bold green" if live else "dim"), " lookalikes   ",
            (f"{hi} high", "red"), " · ", (f"{med} medium", "yellow"),
            " · ", (f"{low} low", "dim")))
        grid.add_row("checked", f"{total_generated:,} candidates across "
                     f"{len(target_stats)} target"
                     f"{'s' if len(target_stats) != 1 else ''}")
        grid.add_row("time", f"{_fmt_dur(elapsed)} · avg {rate:,.0f}/s"
                     + (f" · concurrency settled at {_LEARNED['limit']}"
                        if _LEARNED["limit"] else ""))
        if filt:
            grid.add_row("dns", Text(filt, style="yellow" if unresolved
                                     else "dim"))
        if by_fuzzer:
            grid.add_row("by fuzzer", " · ".join(f"{f} {n}"
                                                for f, n in by_fuzzer))
        if out_path:
            grid.add_row("output", Text.assemble(
                (out_path, "cyan"),
                f"  ({n_written:,} domains)" if n_written is not None else ""))
        parts = [grid]

        if multi:
            tt = Table(box=None, header_style="bold", padding=(0, 2),
                       title="per target", title_justify="left",
                       title_style="bold")
            tt.add_column("target", no_wrap=True)
            tt.add_column("checked", justify="right")
            tt.add_column("live", justify="right")
            tt.add_column("high", justify="right")
            tt.add_column("time", justify="right")
            tt.add_column("top find", no_wrap=True, overflow="ellipsis",
                          max_width=40)
            shown = target_stats if len(target_stats) <= 40 else sorted(
                target_stats, key=lambda t: -t["live"])[:40]
            for t in shown:
                tp = t["top"]
                tt.add_row(
                    t["name"], f"{t['candidates']:,}",
                    Text(str(t["live"]), style="green" if t["live"] else "dim"),
                    Text(str(t["high"]), style="red" if t["high"] else "dim"),
                    _fmt_dur(t["secs"]) if t["secs"] is not None else "-",
                    Text(f"{tp.ascii} ({tp.risk})", style="dim") if tp else "")
            parts += [Text(""), tt]
            if len(target_stats) > 40:
                parts.append(Text(f"  showing 40 of {len(target_stats)} "
                                  f"targets (most live first)", style="dim"))

        if top:
            ft = Table(box=None, header_style="bold", padding=(0, 2),
                       title="top findings", title_justify="left",
                       title_style="bold")
            ft.add_column("risk", justify="right")
            ft.add_column("", no_wrap=True)                 # severity label
            ft.add_column("domain", no_wrap=True, overflow="ellipsis",
                          max_width=40)
            if multi:
                ft.add_column("target", style="dim", no_wrap=True)
            ft.add_column("fuzzer", style="dim", no_wrap=True)
            ft.add_column("why", style="dim", no_wrap=True,
                          overflow="ellipsis", max_width=34)
            ft.add_column("resolves to", style="dim", no_wrap=True,
                          overflow="ellipsis", max_width=24)
            for p in top:
                label, col = _severity(p.risk)
                dom = p.ascii if p.ascii == p.domain else \
                    f"{p.ascii} ({p.domain})"
                row = [Text(str(p.risk), style=col), Text(label, style=col),
                       dom]
                if multi:
                    row.append(p.target)
                row += [p.fuzzer, _signals(p), _resolves_to(p)]
                ft.add_row(*row)
            parts += [Text(""), ft]
            if len(reg) > len(top):
                parts.append(Text(f"  … and {len(reg) - len(top):,} more in "
                                  f"the output  (--top {min(len(reg), 50)} "
                                  f"to see more)", style="dim"))
            parts.append(Text.assemble(
                ("  risk  ", "dim"), ("HIGH", "red"), (" >=70   ", "dim"),
                ("MED", "yellow"), (" 45-69   ", "dim"), ("LOW", "green"),
                (" <45", "dim")))
            band = _band_note(checks, reg)
            if band:
                parts.append(Text(f"        {band}", style="dim"))
            noise = _noise_note(reg)
            if noise:
                parts.append(Text(f"  note  {noise}", style="yellow"))
            hint = _next_step_hint(checks, reg)
            if hint:
                parts.append(Text(f"  next  {hint}", style="cyan"))
        elif not reg:
            parts += [Text(""), Text("no registered lookalikes found",
                                     style="dim")]
        ui.print_rich(Panel(Group(*parts), title="[bold]results[/bold]",
                            title_align="left",
                            border_style="green" if live else "blue",
                            padding=(0, 1)))
        return len(rows)

    # -- plain / log version ---------------------------------------------- #
    ui.line()
    ui.rule("results")
    ui.item("registered", f"{live:,} lookalikes ({hi} high, {med} medium, "
            f"{low} low)", "green" if live else "grey")
    ui.item("checked", f"{total_generated:,} candidates across "
            f"{len(target_stats)} target{'s' if len(target_stats) != 1 else ''}")
    ui.item("time", f"{_fmt_dur(elapsed)} (avg {rate:,.0f}/s"
            + (f", concurrency settled at {_LEARNED['limit']}"
               if _LEARNED["limit"] else "") + ")")
    if filt:
        ui.item("dns", filt, "yellow" if unresolved else "grey")
    if by_fuzzer:
        ui.item("by fuzzer", ", ".join(f"{f} {n}" for f, n in by_fuzzer))
    if out_path:
        ui.item("output", out_path + (f" ({n_written:,} domains)"
                                      if n_written is not None else ""), "cyan")
    if multi:
        ui.line()
        w = max(len(t["name"]) for t in target_stats)
        ui.line(ui.c(f"  {'target':<{w}}  {'checked':>11}  {'live':>5}  "
                     f"{'high':>4}  {'time':>8}  top find", "bold"))
        for t in target_stats:
            tp = t["top"]
            tm = _fmt_dur(t["secs"]) if t["secs"] is not None else "-"
            ui.line(f"  {t['name']:<{w}}  {t['candidates']:>11,}  "
                    f"{t['live']:>5}  {t['high']:>4}  {tm:>8}  "
                    f"{(tp.ascii + ' (' + str(tp.risk) + ')') if tp else ''}")
    if top:
        ui.line()
        ui.line(ui.c("  top findings", "bold"))
        wd = max(len(p.ascii) for p in top)
        wf = max(len(p.fuzzer) for p in top)
        wt = max(len(p.target) for p in top)
        for p in top:
            label, col = _severity(p.risk)
            tgt = f"  {p.target:<{wt}}" if multi else ""
            why = _signals(p)
            ui.line(f"  {ui.c(f'{p.risk:>3}', col)} {ui.c(f'{label:<4}', col)} "
                    f"{p.ascii:<{wd}}  {p.fuzzer:<{wf}}{tgt}  {why}")
        if len(reg) > len(top):
            ui.line(ui.c(f"  ... and {len(reg) - len(top):,} more in the "
                         f"output (--top {min(len(reg), 50)} to see more)",
                         "grey"))
        ui.line(ui.c("  risk  HIGH >=70   MED 45-69   LOW <45", "grey"))
        band = _band_note(checks, reg)
        if band:
            ui.line(ui.c(f"        {band}", "grey"))
        noise = _noise_note(reg)
        if noise:
            ui.line(ui.c(f"  note  {noise}", "yellow"))
        hint = _next_step_hint(checks, reg)
        if hint:
            ui.line(ui.c(f"  next  {hint}", "cyan"))
    elif not reg:
        ui.line()
        ui.line(ui.c("  no registered lookalikes found", "grey"))
    return len(rows)


def main(argv=None):
    args = build_parser().parse_args(argv)
    ui = UI()
    quiet = args.quiet

    if args.list_fuzzers:
        ui.rule("fuzzers")
        for name in DomainFuzzer._ALL:
            ui.line(f"  {name:<16} risk weight {_FUZZER_RISK.get(name, 1)}")
        return 0

    if args.list_presets:
        ui.rule("presets")
        for name in sorted(_PRESETS):
            spec = _PRESETS[name]
            ui.line(f"  {ui.c(name, 'bold')}")
            ui.line(f"      {spec['description']}")
            ui.line(ui.c(f"      fuzzers:  {', '.join(spec['fuzzers'])}",
                         "grey"))
            extras = []
            if spec.get("dictionary"):
                extras.append(f"{len(spec['dictionary'])} built-in keywords")
            if spec.get("tlds"):
                extras.append(f"{len(spec['tlds'])} TLDs")
            if spec.get("mx"):
                extras.append("MX lookups on")
            if extras:
                ui.line(ui.c(f"      also:     {', '.join(extras)}", "grey"))
        ui.line()
        ui.line(ui.c("  use with:  --preset fakeshop", "grey"))
        return 0

    if args.check_resolvers:
        if not _HAVE_AIODNS:
            ui.error("--check-resolvers needs aiodns (pip install aiodns)")
            return 2
        spec = args.nameservers or "unfiltered"
        ns_list, err = parse_nameservers(spec, args.allow_filtering_resolvers)
        if err:
            ui.error(err)
            return 2
        ui.rule("resolver health")
        results = check_resolvers(ns_list, timeout=min(args.timeout, 5.0))
        _report_resolvers(results, ui)
        good = [r for r in results if r[1] == "ok"]
        if len(good) == len(results):
            ui.ok(f"{len(good)}/{len(results)} usable")
        else:
            ui.warn(f"{len(good)}/{len(results)} usable")
        return 0 if len(good) == len(results) else 1

    nameservers = None
    if args.nameservers:
        nameservers, err = parse_nameservers(args.nameservers,
                                             args.allow_filtering_resolvers)
        if err:
            ui.error(err)
            return 2
        if not _HAVE_AIODNS:
            ui.warn("--nameservers needs aiodns (pip install aiodns); "
                    "falling back to the system resolver")
            nameservers = None

    targets = _collect_targets(args)
    if not targets:
        ui.error("no target domains given (pass domains, --input FILE, or pipe "
                 "them in; or use --list-fuzzers)")
        return 2

    if not _HAVE_AIODNS or not _HAVE_TLDEXTRACT or not _HAVE_RICH:
        _warn_missing()

    # optional custom wordlists (shared across all targets)
    try:
        dictionary = _load_wordlist(args.dictionary) if args.dictionary else None
        tlds = _load_wordlist(args.tld_file) if args.tld_file else None
    except OSError as e:
        ui.error(f"cannot read wordlist: {e}")
        return 2

    preset = _PRESETS.get(args.preset) if args.preset else None
    selected = None
    if args.fuzzers:
        selected = [f.strip() for f in args.fuzzers.split(",") if f.strip()]
    elif preset:
        selected = list(preset["fuzzers"])
    if preset:
        # explicit wordlists beat the preset's built-in ones
        if dictionary is None and preset.get("dictionary"):
            dictionary = list(preset["dictionary"])
        if tlds is None and preset.get("tlds"):
            tlds = list(preset["tlds"])

    # resolve which detection checks are on
    do_web = args.web or args.favicon or args.all_checks
    do_favicon = args.favicon or args.all_checks
    do_rdap = args.rdap or args.all_checks
    do_mx = args.mx or args.all_checks or bool(preset and preset.get("mx"))
    later_notes = []          # printed after the header
    if (do_web or do_rdap) and not _HAVE_AIOHTTP:
        later_notes.append(("warn", "web/favicon/rdap checks need aiohttp (not "
                                    "installed); skipping them"))
    if do_web and not _HAVE_FUZZY:
        later_notes.append(("note", "install ppdeep for homepage "
                                    "content-similarity scoring"))

    # generation guards: stop well before the OS OOM-killer fires (SIGKILL,
    # which we could not otherwise report), and honour an explicit cap
    avail = _avail_memory()
    mem_budget = int(avail * 0.80) if avail else 0
    max_cand = args.max_candidates

    # validate targets cheaply (constructing a fuzzer parses/splits but does
    # not generate), so an invalid target is reported before any heavy work
    valid, seen_reg, dup = [], {}, 0
    for t in targets:
        try:
            fz = DomainFuzzer(t, dictionary=dictionary, tlds=tlds,
                              idn_policy=not args.all_idn)
        except ValueError as e:
            ui.warn(f"skip {t!r}: {e}")
            continue
        # "amazon.com", "www.amazon.com" and "AMAZON.com" are one scan: the
        # fuzzers work on the registrable domain, so scanning each spelling
        # repeats the same work and doubles the results
        if fz.original in seen_reg:
            dup += 1
            continue
        seen_reg[fz.original] = t
        valid.append(t)
    if dup:
        ui.note(f"skipped {dup} duplicate target"
                f"{'s' if dup != 1 else ''} (same registrable domain)")
    targets = valid
    if not targets:
        ui.error("no valid targets to scan")
        return 2

    ml = args.min_length
    out_path = _resolve_output_path(args, targets)

    # resolver health, before the header so the header can report it
    res_results = None
    if not args.no_scan and nameservers:
        res_results = check_resolvers(nameservers,
                                      timeout=min(args.timeout, 5.0))
        good = [r[0] for r in res_results if r[1] == "ok"]
        if not good:
            if not quiet:
                _report_resolvers(res_results, ui)
            ui.error("none of the --nameservers answered correctly; check your "
                     "network or run --check-resolvers")
            return 2
        nameservers = good

    # set up live streaming to the output file, if requested and supported
    writer = None
    live_ok = (args.live and out_path and not args.no_scan
               and args.format in ("domains", "csv"))
    if args.live and not live_ok:
        if not out_path:
            later_notes.append(("note", "--live needs an output file (-o / "
                                        "--outdir / --timestamp); ignoring "
                                        "--live"))
        elif args.no_scan:
            later_notes.append(("note", "--live has no effect with --no-scan"))
        else:
            later_notes.append(("note", f"--live supports domains/csv only; "
                                        f"{args.format} is written at the end"))
    if live_ok:
        try:
            writer = LiveWriter(out_path, args.format, args.registered, ml)
        except OSError as e:
            ui.error(f"cannot open {out_path} for live output: {e}")
            return 2

    # ---- header ----------------------------------------------------------- #
    if not quiet:
        rows = []
        shown = ", ".join(targets[:3])
        more = f", +{len(targets) - 3} more" if len(targets) > 3 else ""
        rows.append(("targets", f"{len(targets)}  ({shown}{more})"
                     if len(targets) > 1 else targets[0], "bold"))
        if args.input and args.input != "-":
            rows.append(("input", args.input, None))
        if args.preset:
            rows.append(("preset", f"{args.preset} - "
                         f"{_PRESETS[args.preset]['description']}", "bold"))
        rows.append(("fuzzers", ", ".join(selected) if selected
                     else f"all {len(DomainFuzzer._ALL)}", None))
        if dictionary:
            src = (os.path.basename(args.dictionary) if args.dictionary
                   else f"built into --preset {args.preset}")
            rows.append(("dictionary", f"{len(dictionary):,} words · {src}",
                         None))
        if tlds:
            src = (os.path.basename(args.tld_file) if args.tld_file
                   else f"built into --preset {args.preset}")
            rows.append(("tld list", f"{len(tlds):,} TLDs · {src}", None))
        if max_cand:
            samp = " (dictionary sampled evenly)" if dictionary and \
                len(dictionary) * 4 > max_cand else ""
            rows.append(("per target", f"max {max_cand:,} candidates{samp}",
                         None))
        elif dictionary and len(dictionary) * 4 > 500_000:
            rows.append(("per target",
                         f"unlimited: up to ~{_human(len(dictionary) * 4)} "
                         f"candidates each (memory guard "
                         f"~{mem_budget // 2**30} GB) - consider "
                         f"--max-candidates", "yellow"))
        checks = ["dns (A/AAAA/NS" + ("/MX" if do_mx else "") + ")"]

        checks += [n for n, on in (("web", do_web), ("favicon", do_favicon),
                                   ("rdap", do_rdap), ("ct", args.ct)) if on]
        rows.append(("checks", ", ".join(checks), None))
        if args.no_scan:
            rows.append(("mode", "generate only (--no-scan)", None))
        elif res_results is not None:
            good_n = sum(1 for r in res_results if r[1] == "ok")
            provs = []
            for ns in nameservers:
                p = _RESOLVER_NAMES.get(_ns_host(ns), "custom")
                for suffix in (" unsecured", " Sandbox", " non-filtering",
                               " unfiltered"):
                    p = p.replace(suffix, "")
                if p not in provs:
                    provs.append(p)
            rows.append(("resolvers", f"{good_n}/{len(res_results)} healthy · "
                         + ", ".join(provs),
                         "green" if good_n == len(res_results) else "yellow"))
        elif _HAVE_AIODNS:
            rows.append(("resolvers", "system resolver (may filter - consider "
                         "--nameservers unfiltered)", "yellow"))
        else:
            rows.append(("resolvers", "system resolver (aiodns not installed)",
                         "yellow"))
        if not args.no_scan:
            conc = ("auto (adaptive, starts at 64)"
                    if args.concurrency == "auto" else str(args.concurrency))
            rows.append(("concurrency", conc +
                         (f" × {args.processes} processes"
                          if args.processes > 1 else ""), None))
        if out_path:
            rows.append(("output", f"{args.format} → {out_path}"
                         + ("  (live)" if writer else ""), "cyan"))
        else:
            rows.append(("output", f"{args.format} → stdout", None))
        rows.append(("started", time.strftime("%Y-%m-%d %H:%M:%S")
                     + f"  ·  twistr {__version__}", None))
        ui.header("twistr", rows)

    if res_results is not None:
        for ns, status, detail, _lat in res_results:
            if status != "ok":
                nm = _RESOLVER_NAMES.get(_ns_host(ns), "")
                lbl = f"{ns} ({nm})" if nm else ns
                ui.warn(f"dropped {lbl}: {detail}")
    for kind, text in later_notes:
        (ui.warn if kind == "warn" else ui.note)(text)

    def gen(target):
        fz = DomainFuzzer(target, dictionary=dictionary, tlds=tlds,
                          idn_policy=not args.all_idn)
        tp = fz.generate(selected, max_candidates=max_cand,
                         mem_budget=mem_budget)
        if fz.stopped_reason:
            ui.warn(f"{fz.original}: generation stopped early - "
                    f"{fz.stopped_reason}; scanning the "
                    f"{_generated_count(tp):,} generated so far")
        return fz, tp

    # Stream target-by-target when there are several: each is generated, scanned
    # and then reduced to just the rows we'll output, so memory stays flat and a
    # crash keeps every finished target (in the --live file). The single-pool
    # path is used for one target, for --ct (needs the shared set), or for -P
    # multiprocess sharding.
    per_target = (not args.no_scan and not args.ct and len(targets) > 1)

    live = lame = wild = unresolved = total_generated = 0
    target_stats = []

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

    active_checks = {n for n, on in (("web", do_web), ("favicon", do_favicon),
                                     ("rdap", do_rdap), ("mx", do_mx),
                                     ("ct", args.ct)) if on}
    prog_mode = "none" if quiet else args.progress
    t0 = time.monotonic()
    progress = None
    perms = []

    try:
        if not args.no_scan:
            if not quiet:
                ui.line()
            if per_target:
                progress = make_progress(prog_mode, ui)
                progress.begin(len(targets))
                for idx, target in enumerate(targets, 1):
                    try:
                        fz, tp = gen(target)
                    except ValueError as e:
                        ui.error(f"{e} (use --list-fuzzers to see valid names)")
                        return 2
                    progress.start_target(idx, len(targets), fz.original,
                                          _generated_count(tp))
                    tcount = {"done": 0, "live": 0}

                    def _cb(p, _tc=tcount):
                        if p.fuzzer == "original":
                            return
                        _tc["done"] += 1
                        if p.registered:
                            _tc["live"] += 1
                            progress.found(p)
                        if writer:
                            writer.feed(p)
                        progress.update_target(_tc["done"], _tc["live"])

                    t_start = time.monotonic()
                    tp = run_scan(tp, processes=max(1, args.processes),
                                  concurrency=args.concurrency,
                                  timeout=args.timeout, nameservers=nameservers,
                                  do_web=do_web, do_rdap=do_rdap,
                                  do_favicon=do_favicon, do_mx=do_mx,
                                  progress=None, on_result=_cb)
                    tally(tp)
                    progress.set_counts(wild, lame, unresolved)
                    st = _target_stats(tp, idx=idx,
                                       secs=time.monotonic() - t_start)
                    target_stats.append(st)
                    perms.extend(p for p in tp
                                 if _passes(p, args.registered, ml))
                    progress.target_done(st)
                    del tp
            else:
                for target in targets:
                    try:
                        fz, tp = gen(target)
                    except ValueError as e:
                        ui.error(f"{e} (use --list-fuzzers to see valid names)")
                        return 2
                    perms += tp
                if not perms:
                    ui.error("no valid targets to scan")
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
                    ui.note(f"ct: added {added} domains from Certificate "
                            f"Transparency logs")
                label = targets[0] if len(targets) == 1 else \
                    f"{len(targets)} targets"
                progress = make_progress(prog_mode, ui, label=label)
                progress.start(_generated_count(perms))

                def _res(p):
                    if writer:
                        writer.feed(p)
                    if p.registered and p.fuzzer != "original":
                        progress.found(p)

                t_start = time.monotonic()
                perms = run_scan(perms, processes=max(1, args.processes),
                                 concurrency=args.concurrency,
                                 timeout=args.timeout, nameservers=nameservers,
                                 do_web=do_web, do_rdap=do_rdap,
                                 do_favicon=do_favicon, do_mx=do_mx,
                                 progress=progress, on_result=_res)
                tally(perms)
                secs = time.monotonic() - t_start
                groups = collections.OrderedDict()
                for p in perms:
                    groups.setdefault(p.target, []).append(p)
                for i, (_tgt, grp) in enumerate(groups.items(), 1):
                    target_stats.append(_target_stats(
                        grp, idx=i, secs=secs if len(groups) == 1 else None))
            if progress:
                progress.close()
            if unresolved:
                ui.warn(f"{unresolved} domains could not be resolved even after "
                        f"retry rounds; results may be incomplete. Try "
                        f"--nameservers unfiltered (spreads load over 6 "
                        f"providers), a local resolver, or lower --concurrency")
        else:
            for target in targets:
                try:
                    fz, tp = gen(target)
                except ValueError as e:
                    ui.error(f"{e} (use --list-fuzzers to see valid names)")
                    return 2
                perms += tp
                if not quiet:
                    ui.item("generated",
                            f"{_generated_count(tp):,} for {fz.original}")
            if not perms:
                ui.error("no valid targets to scan")
                return 2
            for p in perms:
                p.risk = score(p)
    except KeyboardInterrupt:
        if progress:
            progress.close()
        if writer:
            writer.close()
        done_n = len(target_stats)
        msg = f"interrupted after {_fmt_dur(time.monotonic() - t0)}"
        if per_target:
            msg += f" ({done_n}/{len(targets)} targets finished)"
        if writer:
            msg += f"; matches found so far are in {out_path}"
        ui.warn(msg)
        return 130
    except MemoryError:
        if progress:
            progress.close()
        ui.error("ran out of memory. Reduce the --dictionary size, scan fewer "
                 "targets at once, or set --max-candidates. (twistr tries to "
                 "self-limit, but a hard cap is safest for very large runs.)")
        if writer:
            writer.close()
        return 2
    finally:
        if progress:
            progress.close()

    if writer:
        writer.close()

    elapsed = time.monotonic() - t0

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
            if not args.no_scan and not quiet:
                _summarize(ui, perms, args.registered, ml, elapsed,
                           total_generated, live, wild, lame, unresolved,
                           target_stats, top_n=args.top,
                           checks=active_checks)
                ui.line()
            render_table(perms, args.registered, ml)
            return 0

    n_written = len(_rows(perms, args.registered, ml))
    if out_path:
        _atomic_write(out_path, out)
    else:
        print(out, end="" if args.format == "domains" else "\n")

    if not args.no_scan and not quiet:
        _summarize(ui, perms, args.registered, ml, elapsed, total_generated,
                   live, wild, lame, unresolved, target_stats,
                   out_path=out_path, n_written=n_written if out_path else None,
                   top_n=args.top, checks=active_checks)
    elif out_path and not quiet:
        ui.ok(f"wrote {n_written:,} domains -> {out_path}")
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
