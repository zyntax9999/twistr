# twistr

A fast, accurate scanner for **typosquatting and phishing lookalike domains**.
Give it a domain (or a list of your brands); it generates the lookalikes an
attacker would register, checks which ones are actually live, enriches them with
signals that separate real phishing from harmless parked typos, and ranks the
results worst-first.

It is a modern, fully-async re-implementation inspired by
[dnstwist](https://github.com/elceef/dnstwist), designed to be faster on large
lists, more accurate (fewer false positives), and friendlier for unattended
background runs.

> **Intended use:** defensive research on domains you own or are authorized to
> assess — brand protection, phishing hunting, takedown triage.

---

## Table of contents

- [Why twistr](#why-twistr)
- [Install](#install)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [What you'll see](#what-youll-see)
- [Command-line reference](#command-line-reference)
- [Presets](#presets)
- [Fuzzers](#fuzzers)
- [Output formats](#output-formats)
- [Understanding the results](#understanding-the-results)
- [The risk score](#the-risk-score)
- [Cookbook: lots of examples](#cookbook-lots-of-examples)
  - [Basics](#basics)
  - [Scanning a list of brands](#scanning-a-list-of-brands)
  - [Output files and naming](#output-files-and-naming)
  - [Live streaming while it runs](#live-streaming-while-it-runs)
  - [Running in the background (nohup)](#running-in-the-background-nohup)
  - [Deeper detection signals](#deeper-detection-signals)
  - [Certificate Transparency discovery](#certificate-transparency-discovery)
  - [Choosing and tuning fuzzers](#choosing-and-tuning-fuzzers)
  - [Custom wordlists](#custom-wordlists)
  - [Performance tuning](#performance-tuning)
  - [Piping and automation](#piping-and-automation)
  - [A complete brand-monitoring workflow](#a-complete-brand-monitoring-workflow)
- [Choosing resolvers](#choosing-resolvers)
- [Performance notes](#performance-notes)
- [Development and tests](#development-and-tests)
- [Troubleshooting](#troubleshooting)
- [Exit codes](#exit-codes)
- [FAQ](#faq)

---

## Why twistr

- **More coverage.** 17 permutation techniques including homoglyph/IDN
  homographs (with double substitution), TLD typos (`.cm`, `.co`, `.om`…),
  soundsquatting, number/word swaps, and built-in combosquatting keywords.
- **Better accuracy.** Detects and drops **wildcard-DNS** false positives,
  handles **lame delegations** (registered but broken nameservers), parses
  records by type and owner (no CNAME confusion), and de-duplicates names that
  encode to the same wire form.
- **Modern signals.** RDAP registration age (newly-registered = high risk),
  homepage content similarity, favicon matching, HTTP banners, MX records, and
  Certificate Transparency discovery.
- **Fast.** Fully async DNS with staged NS-first lookups, retries, optional
  `uvloop`, and optional multi-process sharding.
- **Built for unattended runs.** Adaptive progress (bar on a terminal, clean
  log lines when backgrounded), live-updating output files, timestamped unique
  filenames, and memory-bounded streaming for large lists.
- **Ranked output.** Every result gets a 0–100 risk score; the worst float to
  the top.

---

## Install

twistr is a single file, `twistr.py`. It runs on **Python 3.9+** with no
dependencies at all — but installing the optional libraries unlocks its fast
path and its richer checks.

```bash
git clone https://github.com/zyntax9999/twistr.git
cd twistr

# optional but strongly recommended (see the table below)
pip install -r requirements.txt

python3 twistr.py --version
python3 twistr.py example.com --registered
```

On Debian/Ubuntu, `pip` may refuse to install into the system Python. Either
use a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

…or install the packages system-wide with `pip install --break-system-packages
-r requirements.txt`. `aiodns` needs a compiler and the c-ares headers on some
systems: `sudo apt install build-essential libcares-dev` first if the install
fails.

To pull in later changes:

```bash
cd twistr && git pull
```

If you would rather not clone the whole repository, the script is
self-contained and works on its own:

```bash
curl -O https://raw.githubusercontent.com/zyntax9999/twistr/main/twistr.py
python3 twistr.py --help
```

What each optional library adds:

| Library      | Enables |
|--------------|---------|
| `aiodns`     | Fast async DNS + MX/NS lookups + custom `--nameservers` (without it, a slower socket resolver is used, A/AAAA only) |
| `aiohttp`    | `--web`, `--favicon`, `--rdap` (HTTP/RDAP fetches) |
| `ppdeep`     | Homepage **content similarity** scoring under `--web` |
| `mmh3`       | Shodan-compatible **favicon hashing** (falls back to SHA-1) |
| `tldextract` | Accurate public-suffix splitting (falls back to a built-in heuristic) |
| `rich`       | Colored progress bar and pretty tables (falls back to plain text) |
| `idna`       | Robust IDNA/punycode encoding |
| `uvloop`     | A faster event loop (used automatically if present) |

twistr degrades gracefully: any missing library just disables its feature with
a one-line note, it never crashes.

```bash
# make it executable if you like
chmod +x twistr.py
./twistr.py --help

# ...or put it on your PATH so you can run it from anywhere
sudo ln -s "$PWD/twistr.py" /usr/local/bin/twistr
twistr --version
```

Check the install is healthy before a long scan:

```bash
python3 twistr.py --check-resolvers --nameservers unfiltered   # DNS is usable
pytest -q                                                      # 56 tests, ~5s
```

---

## Quick start

```bash
# See lookalikes of your domain that are actually registered
python twistr.py example.com --registered

# Same, but with every detection signal turned on
python twistr.py example.com --all-checks --ct --registered

# Scan a whole list of your brands into a timestamped file, one domain per line
python twistr.py -i brands.txt --registered --format domains --outdir results/

# Hunt counterfeit shops for your brands (focused, much faster than the full set)
python twistr.py -i brands.txt --preset fakeshop -r --nameservers unfiltered
```

---

## How it works

A scan has three stages.

**1. Generate candidates.** For each target, twistr applies its
[fuzzers](#fuzzers) to produce the lookalike domains an attacker might register
(typos, homoglyphs, extra keywords, wrong TLDs, …). Names that a TLD registry
would refuse (e.g. a Cyrillic character under `.no`) are skipped automatically
unless you pass `--all-idn`.

**2. Resolve.** Each candidate is checked over DNS, asynchronously. twistr
queries **NS first** — most candidates don't exist, and a single NS query
settles them cheaply — then fetches A/AAAA (and MX with `-m`) only for names
that exist. Transient failures (SERVFAIL, timeouts) are retried in calm rounds
at the end so a busy resolver doesn't make you miss real domains.

**3. Enrich and score.** With the optional flags, live domains get HTTP
banners, page titles, content-similarity, favicon comparison, RDAP registration
dates, and MX records. Everything feeds a single [risk score](#the-risk-score),
and results are sorted worst-first.

---

## What you'll see

On a terminal (with `rich` installed), twistr opens with a header panel that
summarises the run, then a live dashboard while it scans:

```
╭─ twistr · scanning ───────────────────────────────────────────────────────────────╮
│ overall  ━━━━━━━━╺━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  7/29 targets  503 live  eta ~4:12:10 │
│ target   [8/29] northface-shop.com                                                 │
│          ━━━━━━━━━━━━━━━━╺━━━━━━━━━━━━━━  41%  1.48M/3.62M  3 live  2,410/s  eta 15:02 │
│                                                                                    │
│ elapsed 1:02:11   checked 17.2M   avg 2,380/s   mem 2.1 GB   wildcard 12   lame 3  │
│                                                                                    │
│ recent finds                                                                       │
│ 67  northfaceshop-sale.com   northface-shop.com   dictionary   4s ago              │
│ 44  thenorthface.cm          thenorthface.com     tld-typo     1m ago              │
╰────────────────────────────────────────────────────────────────────────────────────╯
```

- **overall**: targets finished, live lookalikes so far, and an estimate for
  the whole run (based on your actual speed and the size of targets so far).
- **target**: the current target's progress, hits, speed and ETA.
- **stats line**: elapsed time, total checked, average speed, memory in use, and
  DNS health (wildcards ignored, lame delegations, unresolved).
- **recent finds**: the newest live lookalikes as they appear, with risk score.

Each finished target leaves a line above the dashboard:

```
done [7/29] northface-sale.com  12 live  299,999 checked  2:05 (2,399/s)  top northface-sale.shop (72)
```

At the end you get a **results** panel: totals and risk mix, DNS notes,
findings by fuzzer, the output file, a **per-target table**, and the **top
findings** across all targets — each with a severity word, the reasons behind
its score, and where it resolves:

```
top findings
  risk            domain                   fuzzer      why           resolves to
    76    HIGH    paypal.freeddns.org      hosting     live, mail    158.255.215.59
    71    HIGH    paypal.net               tld-typo    live, mail    3.33.139.32
    60    MED     paypal.pages.dev         hosting     live          172.66.47.115
    43    LOW     paypal.workers.dev       hosting     delegated     ns doug.ns.cloudflare.com
  … and 54 more in the output  (--top 50 to see more)
  risk  HIGH >=70   MED 45-69   LOW <45
  next  re-run the hits with --all-checks to add registration age, page content
```

The **why** column is the reason behind the number — `live`, `mail`,
`new 9d`, `clone 87%`, `same favicon`, `cert`, `brand in title` — so a row can
be judged without opening the CSV. Severity is a **word as well as a colour**,
so the ranking survives a colour-blind reader, a mono terminal and a log file.
The **next** line suggests the cheapest thing that would sharpen the results,
and only ever suggests checks that did not already run. `--top N` lists more.

**Under `nohup` or when redirected to a file**, the same information is written
as plain timestamped lines (no colours or cursor codes), so `tail -f` works:
a header, `[i/n] target: 41% ... | run: 503 live, ~4:12:10 left | latest: ...`
status lines about once a minute on long targets, a `done` line per target, and
the results summary.

Without `rich`, a terminal gets a single in-place progress bar instead of the
dashboard. `NO_COLOR=1` turns colours off. `-q` shows only warnings, errors
and the summary. **Ctrl-C** stops cleanly: the dashboard is removed, the
terminal is restored, and it tells you where the matches found so far were
saved (with `--live`).

---

## Command-line reference

```
python twistr.py [domains...] [options]
```

### Targets (what to scan)

| Option | Description |
|---|---|
| `domain ...` | One or more targets, e.g. `example.com brand.co.uk`. |
| `-i, --input FILE` | Read targets from a file, one per line (blank lines and `#comments` ignored). Use `-` for stdin. |
| *(stdin)* | If no target is given and something is piped in, targets are read from stdin. |

### Generation (what lookalikes to produce)

| Option | Description |
|---|---|
| `--preset NAME` | Scan profile for one kind of abuse: picks the fuzzers, and sometimes keywords, TLDs and checks. See [Presets](#presets). Anything you pass explicitly still wins. |
| `--list-presets` | Print the presets and what each one does, then exit. |
| `--fuzzers LIST` | Comma-separated subset of fuzzers to use (default: all). See [Fuzzers](#fuzzers). |
| `--list-fuzzers` | Print the available fuzzers and their risk weights, then exit. |
| `--dictionary FILE` | Wordlist for the `dictionary` (combosquatting) fuzzer, one word per line. Replaces the built-in list. |
| `--tld-file FILE` | Wordlist of TLDs for the `tld-swap` fuzzer, one per line. Replaces the built-in list. |
| `--all-idn` | Also generate IDN lookalikes using characters the TLD's registry doesn't accept (off by default, since those can't be registered there). |
| `--max-candidates N` | Cap each target at N candidates (0 = unlimited). Every other fuzzer runs in full first; the `dictionary` fuzzer gets the remaining budget and, if trimmed, samples words evenly across the whole list (so a sorted dictionary isn't cut to the start of the alphabet). twistr also self-limits as it approaches available memory. |
| `--no-scan` | Only generate candidates; don't query DNS. Great for building lists or counting. |

### Detection (what to check on each candidate)

| Option | Description |
|---|---|
| `-r, --registered` | Only output domains that are registered / resolve. |
| `-m, --mx` | Also look up MX records (mail-interception signal). Off by default to save one lookup per domain. |
| `--web` | Fetch each live homepage: HTTP status, `Server` banner, `<title>`, and content similarity to the real site (needs `aiohttp`; similarity needs `ppdeep`). |
| `--favicon` | Compare each candidate's favicon to the real site's — reused favicons flag phishing kits. Implies `--web`. |
| `--rdap` | Look up registration date + registrar via RDAP and flag newly-registered domains (needs `aiohttp`). |
| `--ct` | Also **discover** lookalikes from Certificate Transparency logs (crt.sh) — finds real, cert-bearing impersonations no permutation would generate. |
| `--all-checks` | Shortcut for `--web --favicon --rdap --mx`. |
| `--min-length N` | Only output permutations whose full domain is ≥ N characters. |

### Resolver and performance

| Option | Default | Description |
|---|---|---|
| `--concurrency N\|auto` | `auto` | Lookups in flight per process. `auto` starts at 64 and adapts while scanning: it raises the limit while throughput keeps improving, steps back when it stops, and backs off when resolvers start failing. The learned value carries over between targets. A number fixes it. |
| `-P, --processes N` | `1` | Split each scan across N worker processes to use multiple CPU cores. Works in every mode, including multi-target lists. Only helps once one core is maxed out (see [Performance notes](#performance-notes)). |
| `--timeout SECS` | `5.0` | Per-query DNS timeout. |
| `--nameservers LIST` | *(system)* | Comma-separated resolvers, e.g. `1.1.1.1,8.8.4.4` or `127.0.0.1:5335` (needs `aiodns`). The word `unfiltered` expands to a vetted set of 12 unfiltered public resolvers. Multiple resolvers are load-balanced and health-checked at start. Known *filtering* resolvers are refused. See [Choosing resolvers](#choosing-resolvers). |
| `--allow-filtering-resolvers` | | Allow resolvers that block domains (not recommended: blocked lookalikes look unregistered). |
| `--check-resolvers` | | Health-check your `--nameservers` (or the `unfiltered` preset) and exit. |

### Output

| Option | Default | Description |
|---|---|---|
| `--format {table,json,csv,domains}` | `table` | Output format. `domains` = one domain per line, ranked worst-first. |
| `-o, --output FILE` | *(stdout)* | Write to a file. `strftime` tokens are expanded, e.g. `-o 'twistr-%Y%m%d.csv'`. |
| `--outdir DIR` | | Write to DIR with an auto, timestamped, unique filename. |
| `--timestamp` | | Add a date-time stamp to the output filename so each run is unique. |
| `--live` | | Write matches to the output file **as they're found** (tail/copy mid-run). `domains` and `csv` only; the file is risk-sorted with a final atomic rewrite. |
| `--top N` | `15` | How many findings to list in the end-of-run summary. |
| `--progress {auto,bar,plain,none}` | `auto` | Progress display. `auto` = animated bars (overall + current target) on a terminal, timestamped log lines when redirected/backgrounded. |
| `-q, --quiet` | | Only warnings, errors, and the final summary — no header, progress, or per-target lines. With a stdout format (no `-o`) stderr goes silent, so `... -q --format domains` is clean for pipelines. |

---

## Presets

The full fuzzer set is thorough but broad. A preset narrows it to the
techniques that matter for one kind of abuse, which makes scans much faster
and the results much less noisy.

```bash
python twistr.py --list-presets
python twistr.py -i brands.txt --preset fakeshop -r --nameservers unfiltered
```

| Preset | For | What it does |
|---|---|---|
| `fakeshop` | Counterfeit / fake web shops | Brand + shop words (`outlet`, `sale`, `discount`, …), cheap TLDs (`.shop`, `.store`, `.xyz`, `.top`, …), free hosting, plus light typos. Ships its own 53-word keyword list and 40 TLDs. |
| `phishing` | Credential phishing | Homoglyphs, login/verify keywords, free hosting, subdomains, TLD typos, bitsquatting |
| `typo` | Genuine typing mistakes | Omission, repetition, transposition, replacement, insertion, vowel swap, phonetic, reorder, TLD typos |
| `bec` | Business email compromise | Mail-capable lookalikes; **turns on MX lookups** automatically |
| `homograph` | Visual impersonation only | Homoglyphs and IDN whole-script look-alikes |
| `quick` | Fast triage | The highest-yield fuzzers only, smallest candidate set |

On a nine-letter brand, the full set generates about 4,000 candidates;
`fakeshop` generates 461 and `quick` 162, so a list of brands finishes in a
fraction of the time.

A preset only sets defaults. `--fuzzers`, `--dictionary`, `--tld-file` and
`-m` all override it, so `--preset fakeshop --dictionary mywords.txt` keeps
the preset's fuzzers and cheap TLDs but uses your own keywords.

A real run against `adidas.com` with `--preset fakeshop` found 109 registered
domains in 55 seconds, including `shopadidas.com`, `sale-adidas.com`,
`store-adidas.com` and `adidas.pages.dev`.

---

## Fuzzers

Run `python twistr.py --list-fuzzers` to see this list with risk weights.

| Fuzzer | What it produces | Example (`paypal.com`) |
|---|---|---|
| `omission` | Drops one character | `papal.com` |
| `repetition` | Doubles a character | `payypal.com` |
| `transposition` | Swaps adjacent characters | `apypal.com` |
| `replacement` | Adjacent-key typo (QWERTY/QWERTZ/AZERTY, incl. number row) | `paypak.com`, `pa7pal.com` |
| `insertion` | Inserts an adjacent key | `payppal.com`, `payp0al.com` |
| `addition` | Appends a character | `paypals.com` |
| `vowel-swap` | Swaps vowels | `poypal.com` |
| `hyphenation` | Inserts a hyphen | `pay-pal.com` |
| `subdomain` | Inserts a dot | `pay.pal.com` |
| `bitsquatting` | Flips one bit (bit-rot / memory errors) | `taypal.com` |
| `homoglyph` | Visually confusable characters, incl. IDN/Unicode, double substitution and `rn`↔`m` windows | `paypaɩ.com`, `pа́ypal.com` |
| `dictionary` | Combosquatting: brand + keyword (login, secure, verify…) | `paypal-login.com`, `securepaypal.com` |
| `homophone` | Sound-alike substrings (soundsquatting) | `4paypal` style |
| `cardinal` | Number ↔ word / leet swaps | `p4ypal.com` |
| `tld-swap` | Same name, different TLD | `paypal.net`, `paypal.io` |
| `tld-typo` | Typo of the real TLD (the `.cm`/`.co`/`.om` family) | `paypal.cm`, `paypal.co` |
| `separator` | Hyphen/dot edits: drops or swaps separators a brand already has, and splits a compound brand into two extra words | `thenorthface.com` and `the.north.face.com` (from `the-north-face.com`), `north-face.com` |
| `numeral` | Numbers and years appended or prepended, tracking the current year | `adidas2026.com`, `adidas-24.com`, `3adidas.com` |
| `double-omission` | Two characters dropped (names of 6+ characters) | `nortace.com` |
| `hosting` | Brand as a host on dynamic-DNS and free-hosting providers — a standard way to serve a phishing page with no registration at all | `paypal.duckdns.org`, `paypal.pages.dev` |
| `wrong-sld` | Another second-level domain in the same ccTLD family | `brand.org.uk` (from `brand.co.uk`) |
| `phonetic` | Common-misspelling swaps (`ph`↔`f`, `ck`↔`k`, `s`↔`z`) | `northphace.com`, `northfake.com` |
| `reorder` | Letters swapped at a distance, not just adjacent ones | `ronthface.com` |
| `various` | TLD-in-name, `www` noise, plurals | `paypalcom.com`, `wwwpaypal.com` |

A special `homoglyph-script` sub-result produces whole-script IDN homographs —
Cyrillic, Greek and Armenian — where every letter maps into one alphabet, so
the result is visually identical to the original.
Results discovered via `--ct` are labelled `ct-log`.

---

## Output formats

### `table` (default) — for reading in a terminal

Ranked, colored (with `rich`), worst-first:

```
┏━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━┳━━━━━━┓
┃ risk ┃ fuzzer     ┃ domain     ┃ A / AAAA        ┃ MX ┃ http ┃
┡━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━╇━━━━━━┩
│ 49   │ homoglyph  │ paypaı.com │ 99.83.176.46    │ -  │ -    │
│ 49   │ tld-typo   │ paypal.cm  │ 34.102.136.180  │ -  │ -    │
└──────┴────────────┴────────────┴─────────────────┴────┴──────┘
```

### `domains` — one domain per line, for blocklists and pipelines

Ranked worst-first, de-duplicated, always the ASCII/punycode form (so every
line is directly usable). IDN lookalikes appear as `xn--…`.

```
paypal-login.com
securepaypal.com
paypal.cm
aypal.com
xn--pypal-4ve.com
```

### `csv` — full detail, for spreadsheets and analysis

Columns:

```
risk,target,fuzzer,domain,ascii,a,aaaa,mx,ns,cname,http_status,
http_server,title,fuzzy,favicon_match,created,age_days,registrar,ct,wildcard
```

### `json` — structured, for programmatic use

An array of objects with every field above (and `dns_*` as lists). Ideal for
piping into `jq` or another tool.

---

## Understanding the results

Every result row carries these signals (visible in `csv`/`json`; the table
shows the highlights):

- **`a` / `aaaa`** — IPv4 / IPv6 the name resolves to.
- **`ns`** — the domain's nameservers. The special value `!servfail` means the
  domain is registered but its nameservers are broken (a *lame delegation*) —
  still counted as live.
- **`cname`** — an alias at the apex (common for parked domains).
- **`mx`** — mail servers (only with `-m`); a domain that can receive mail can
  run credential phishing by email.
- **`http_status` / `http_server` / `title`** — from `--web`.
- **`fuzzy`** — 0–100 similarity of the homepage to your real site (`--web` +
  `ppdeep`). High = the site looks like a clone.
- **`favicon_match`** — `yes` if the favicon is identical to your real site's
  (`--favicon`).
- **`created` / `age_days` / `registrar`** — from `--rdap`. A domain registered
  in the last few weeks is a strong phishing indicator.
- **`ct`** — `yes` if the domain was found in Certificate Transparency logs
  (`--ct`) — i.e. someone obtained a TLS certificate for it.
- **`wildcard`** — `yes` if the name only "resolves" because its parent zone
  answers for *any* name (wildcard DNS). These are **excluded** from the
  registered count but kept in the output so you can see them. This covers
  catch-all hosting providers (`vercel.app`, `github.io`, `netlify.app` and
  others answer for every name, even ones nobody claimed), which is why a
  `hosting` result that survives is a host somebody really created.

The end-of-run summary (on stderr) tells you about edge cases:

```
scan complete: 336 live / 2190 checked in 01:00
  3 ignored: only resolve because the parent zone answers for any name (wildcard DNS)
  4 registered with broken nameservers (SERVFAIL, lame delegation) - counted as live
  warning: 5 domains could not be resolved even after retry rounds; results may be incomplete.
```

---

## The risk score

Each result gets a 0–100 score so the most dangerous rise to the top. It
combines *how convincing the lookalike is* with *how live and phishing-ready it
looks*:

| Signal | Contribution |
|---|---|
| Fuzzer type | weight × 5 (homoglyph highest, then bitsquatting/dictionary/tld-typo…) |
| Registered | +18 |
| Has an A record | +6 |
| Has MX (mail-capable) | +16 |
| Homepage reachable (HTTP < 400) | +6 |
| Homepage looks like the real site (`fuzzy`) | up to +35 |
| **Favicon matches the real site** | +25 |
| Seen in Certificate Transparency | +8 |
| **Newly registered** (≤30d +25, ≤90d +15, ≤1y +6) | up to +25 |
| Page title name-drops the brand | +10 |

Rule of thumb: a newly-registered, mail-capable homoglyph that clones your
favicon scores ~100; an old, plain, parked typo stays moderate.

---

## Cookbook: lots of examples

### Basics

```bash
# Generate + scan a single domain, pretty table
python twistr.py example.com

# Only show ones that are actually registered
python twistr.py example.com --registered
python twistr.py example.com -r                 # short form

# Just generate the candidate list, don't touch the network
python twistr.py example.com --no-scan --format domains

# How many candidates would a full scan check?
python twistr.py example.com --no-scan --format domains | wc -l

# Scan several domains at once
python twistr.py example.com brand.co.uk shop.example.org -r

# List the fuzzers and their weights
python twistr.py --list-fuzzers
```

### Scanning a list of brands

```bash
# From a file (one domain per line; # comments allowed)
python twistr.py -i brands.txt -r

# From stdin
cat brands.txt | python twistr.py -r
echo "example.com" | python twistr.py -r

# brands.txt can look like:
#   # our core brands
#   example.com
#   example.co.uk
#   examplebank.com
```

For lists over 8 targets, twistr automatically scans **one target at a time**
so memory stays flat and partial results survive a crash — you'll see per-brand
progress:

```
streaming 12 targets one at a time (memory-bounded)
  [1/12] example.com: 41 live / 2190
  [2/12] example.co.uk: 7 live / 384
  ...
```

### Output files and naming

```bash
# Write results to a specific file
python twistr.py example.com -r --format csv -o results.csv

# Auto-named, timestamped, unique file in a directory
python twistr.py example.com -r --format domains --outdir results/
#   -> results/twistr_example-com_20260923-141005.txt

# Add a timestamp to your own filename so runs never overwrite each other
python twistr.py example.com -r -o scan.csv --timestamp
#   -> scan_20260923-141005.csv

# Use strftime tokens directly in the filename
python twistr.py example.com -r -o 'twistr-%Y%m%d-%H%M%S.csv'
```

Output files are written atomically (via a temp file + rename), so a process
reading or copying the file never sees a half-written result.

### Live streaming while it runs

`--live` appends each match to the output file the moment it's found, so you can
watch progress and copy domains before the scan finishes. When the scan ends,
the file is rewritten once, risk-sorted.

```bash
# Stream matches into a timestamped file as they're discovered
python twistr.py example.com -r --format domains --outdir results/ --live

# In another terminal, watch them arrive:
tail -f results/twistr_example-com_*.txt
```

`--live` works with the `domains` and `csv` formats and needs an output
destination (`-o`, `--outdir`, or `--timestamp`).

### Running in the background (nohup)

Progress auto-detects that it's not attached to a terminal and switches from an
animated bar to clean, timestamped log lines — so your log file stays readable.

```bash
# Detach from the SSH session; results to a file, progress/log to scan.log
nohup python twistr.py -i brands.txt --all-checks --ct -r \
    --nameservers 1.1.1.1,8.8.4.4 \
    --format domains --outdir results/ --live \
    > scan.log 2>&1 &

# Reconnect later and watch progress:
tail -f scan.log

# ...and pull domains out of the results file while it's still running:
tail -f results/twistr_*.txt
```

Because `nohup ... &` detaches the process, a dropped SSH connection won't kill
the scan.

### Deeper detection signals

```bash
# Add MX lookups (mail-interception capability)
python twistr.py example.com -r -m

# Fetch homepages: status, banner, title, and content similarity to your site
python twistr.py example.com -r --web

# Also compare favicons (reused favicon = likely phishing kit)
python twistr.py example.com -r --web --favicon

# Flag newly-registered domains via RDAP
python twistr.py example.com -r --rdap

# Everything at once (= --web --favicon --rdap --mx)
python twistr.py example.com -r --all-checks

# Full-power run, JSON out for analysis
python twistr.py example.com --all-checks --ct -r --format json -o example.json
```

### Certificate Transparency discovery

`--ct` is a different kind of discovery: instead of *generating* candidates, it
queries crt.sh for certificates mentioning your brand and pulls in real,
cert-bearing lookalikes you'd never guess.

```bash
# Combine generated candidates with CT-log discoveries
python twistr.py example.com --ct -r

# CT results are labelled 'ct-log' in the fuzzer column
python twistr.py example.com --ct -r --format csv | grep ct-log
```

### Choosing and tuning fuzzers

```bash
# Only the highest-signal fuzzers
python twistr.py example.com -r --fuzzers homoglyph,bitsquatting,tld-typo

# Everything except the huge homoglyph set (much faster / fewer queries)
python twistr.py example.com -r \
  --fuzzers omission,repetition,transposition,replacement,insertion,addition,\
vowel-swap,hyphenation,subdomain,dictionary,tld-swap,tld-typo,various

# Only combosquatting (brand + keyword)
python twistr.py example.com -r --fuzzers dictionary

# Include IDN lookalikes the registry would normally reject
python twistr.py example.com --fuzzers homoglyph --all-idn --no-scan
```

### Custom wordlists

```bash
# Your own combosquatting keywords (replaces the built-in list)
python twistr.py example.com -r --fuzzers dictionary --dictionary words.txt

# Your own set of TLDs to swap in
python twistr.py example.com -r --fuzzers tld-swap --tld-file tlds.txt

# words.txt / tlds.txt: one entry per line, # comments allowed
```

### Performance tuning

```bash
# Default: adaptive concurrency finds the right level for your resolvers
python twistr.py -i brands.txt -r --nameservers unfiltered

# Use several CPU cores once one is maxed out (e.g. a fast local resolver)
python twistr.py -i brands.txt -r --nameservers 127.0.0.1:5335 -P 4

# Fix the concurrency yourself instead of adapting
python twistr.py -i brands.txt -r --nameservers unfiltered --concurrency 200
```

### Piping and automation

```bash
# Feed a blocklist / another tool: just the domains, worst-first
python twistr.py example.com -r --format domains | tee blocklist.txt

# Only "long" combosquats (like dnstwist's `awk 'length >= N'`)
python twistr.py example.com -r --format domains --min-length 15

# Pull one column out of CSV (domain is column 4)
python twistr.py example.com -r --format csv | cut -d, -f4

# Parse JSON with jq: mail-capable domains scoring 60+
python twistr.py example.com -r -m --format json \
  | jq -r '.[] | select(.risk >= 60 and (.mx|length>0)) | .ascii'

# Diff today's registered set against yesterday's to catch NEW lookalikes
python twistr.py example.com -r --format domains | sort > today.txt
comm -13 yesterday.txt today.txt        # newly-appeared domains
```

### A complete brand-monitoring workflow

A daily cron job that scans your brands, saves a dated snapshot, and emails you
only the domains that are new since yesterday:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /home/you/twistr
DATE=$(date +%F)

# 1. full scan, results streamed to a dated file
python twistr.py -i brands.txt --all-checks --ct -r \
    --nameservers 1.1.1.1,8.8.4.4 --concurrency 200 \
    --format domains -o "snapshots/$DATE.txt" --live \
    > "logs/$DATE.log" 2>&1

# 2. compare with the previous snapshot
PREV=$(ls snapshots/*.txt | grep -v "$DATE" | tail -1 || true)
if [ -n "${PREV:-}" ]; then
    comm -13 <(sort "$PREV") <(sort "snapshots/$DATE.txt") > "new-$DATE.txt"
    if [ -s "new-$DATE.txt" ]; then
        mail -s "New lookalike domains ($DATE)" you@example.com < "new-$DATE.txt"
    fi
fi
```

---

## Choosing resolvers

The resolver you use decides what twistr can see. Two rules matter.

**1. Never use a filtering resolver.** Many public resolvers block known
phishing and malware domains by default, which are exactly the domains twistr
is looking for. Depending on the provider, a blocked name comes back as
NXDOMAIN (so twistr concludes it isn't registered) or as a sinkhole or
block-page address (a fake answer). Either way the scan is silently wrong.
twistr refuses known filtering resolvers and tells you the unfiltered
alternative:

| Filtering (refused) | Unfiltered alternative |
|---|---|
| Quad9 `9.9.9.9`, `149.112.112.112`, `9.9.9.11` | Quad9 unsecured `9.9.9.10`, `149.112.112.10` |
| Cloudflare for Families `1.1.1.2`, `1.1.1.3` (and `1.0.0.x`) | Cloudflare `1.1.1.1`, `1.0.0.1` |
| OpenDNS `208.67.222.222`, `208.67.220.220` (blocks phishing by default), FamilyShield `.123` | OpenDNS Sandbox `208.67.222.2`, `208.67.220.2` |
| AdGuard default `94.140.14.14`, Family `94.140.14.15` | AdGuard non-filtering `94.140.14.140`, `94.140.14.141` |
| Control D `76.76.2.1`-`.4`, `76.76.10.1`-`.4` | Control D unfiltered `76.76.2.0`, `76.76.10.0` |
| CleanBrowsing (all), Yandex Safe/Family, DNS4EU filtering services | Cloudflare or Google |

This list covers well-known services only. Your **router or ISP** resolver may
also filter (for example, content or threat filtering enabled on the router),
and twistr can't detect that. That's why it prints a note when you run without
`--nameservers`.

**2. Spread the load.** Public resolvers rate-limit per client IP. A big scan
sends thousands of queries per second, so a single provider will start dropping
queries. `--nameservers unfiltered` spreads the load over 12 resolvers from 6
independent providers (Cloudflare, Google, Quad9 unsecured, OpenDNS Sandbox,
AdGuard non-filtering, Control D unfiltered):

```bash
python twistr.py -i brands.txt -r --nameservers unfiltered --concurrency 300
```

At start, twistr health-checks every resolver. Each must answer a real name and
return NXDOMAIN for a random non-existent one; any that are dead, or that
rewrite non-existent names into fake addresses, are dropped:

```
resolvers: 11/12 healthy
  dropping:
  [DEAD] 208.67.220.2 (OpenDNS Sandbox)      -   no answer for example.com
```

You can run the same check on its own:

```bash
python twistr.py --check-resolvers --nameservers unfiltered
python twistr.py --check-resolvers --nameservers 127.0.0.1:5335
```

### Best option: your own resolver (Unbound)

For large or regular scans, run a local recursive resolver on the scanning
machine. It asks the authoritative servers directly, so there's **no third
party that could filter, no per-client rate limit, and no one else's cache**
between you and the answer. On Ubuntu/Debian:

```bash
sudo apt install unbound dnsutils

sudo tee /etc/unbound/unbound.conf.d/twistr.conf >/dev/null <<'EOF'
server:
    interface: 127.0.0.1
    port: 5335
    access-control: 127.0.0.0/8 allow
    num-threads: 4
    so-reuseport: yes
    outgoing-range: 8192
    num-queries-per-thread: 4096
    msg-cache-size: 128m
    rrset-cache-size: 256m
    so-rcvbuf: 4m
    so-sndbuf: 4m
    prefetch: no
    qname-minimisation: yes
    harden-glue: yes
    edns-buffer-size: 1232
EOF

sudo unbound-checkconf && sudo systemctl restart unbound
dig @127.0.0.1 -p 5335 example.com +short          # should print an IP
python twistr.py --check-resolvers --nameservers 127.0.0.1:5335
```

Then scan with it, alone or together with the public preset:

```bash
python twistr.py -i brands.txt -r --nameservers 127.0.0.1:5335 --concurrency 400
python twistr.py -i brands.txt -r --nameservers 127.0.0.1:5335,unfiltered
```

Notes: port 5335 avoids clashing with anything already on port 53. Set
`num-threads` to your core count. If Unbound logs *"cannot increase max open
fds"*, lower `outgoing-range` to `4096`. If it warns about socket buffers, raise
`net.core.rmem_max` / `net.core.wmem_max` with `sysctl`, or lower
`so-rcvbuf`/`so-sndbuf`. With Ubuntu's default package config Unbound also
validates DNSSEC; a domain with broken DNSSEC then shows up as a lame delegation
(`!servfail`), which twistr still counts as registered.

---

## Performance notes

- twistr is usually **waiting on DNS**, not using CPU. Speed is roughly
  *lookups in flight ÷ resolver latency*: 64 in flight at ~27 ms is ~2,400/s.
  The default `--concurrency auto` raises the number in flight until
  throughput stops improving or the resolvers start dropping queries, then
  holds there. In a test with 25 ms latency and a 6,000 queries/s limit it
  scanned 2.3× faster than a fixed 64 (5,500/s vs 2,400/s), within a few
  percent of the best hand-picked value, without overshooting into the limit.
- Pushing concurrency *past* what your resolvers accept makes things
  **slower**: dropped queries hold a slot for a full timeout and then need a
  retry round. That is why `auto` backs off; if you fix `--concurrency` by
  hand and the summary reports unresolved domains, lower it.
- twistr keeps the number of DNS queries down as well as the rate up: a name
  that does not exist is settled by one NS query, `AAAA` is only asked for when
  `A` came back empty, and wildcard probes are cached for the whole run instead
  of being repeated for every target. On a four-brand run using the `hosting`
  fuzzer that cut queries from 749 to 418.
- One process tops out around 15,000–17,000 lookups/s of CPU. Beyond that
  (fast local resolver, big lists), `-P N` spreads the work over N cores.
  It gives identical results and works in multi-target mode.
- Install **`aiodns`** and **`uvloop`** for the fast path. Without `aiodns`,
  twistr falls back to a slower socket resolver (A/AAAA only, no `--nameservers`).
- Memory: about 450 bytes per candidate while a target is being scanned, so
  an uncapped 3.6M-candidate target needs ~1.6 GB. Use `--max-candidates` to
  bound it.
- Point it at **fast, reliable resolvers**: `--nameservers 1.1.1.1,8.8.4.4`.
  Multiple resolvers are load-balanced. A weak resolver under high concurrency
  will drop queries (twistr retries, but the summary will warn you if some
  couldn't be resolved).
- The `homoglyph` fuzzer is by far the largest — a 6-letter brand generates
  ~1,800 homoglyph candidates, a 15-letter one over 12,000. Drop it via
  `--fuzzers` if you need a quick, lightweight pass.

---

## Troubleshooting

**`note: optional libs not found -> aiodns …`**
Install the optional libraries for full speed/features (see [Install](#install)).
The scan still runs without them.

**The process printed `Killed`, or `error: ran out of memory`**
You ran out of RAM. `Killed` is the Linux OOM-killer (it sends SIGKILL, which
no program can trap — that's why there was no explanation). It almost always
means a **huge `--dictionary`**: the combosquatting fuzzer produces ~4
candidates per dictionary word, per target, so an 800k-word list makes ~3.4M
candidates *for every target*. Fixes:
- Use a **smaller dictionary** (most curated lists are a few hundred to a few
  thousand words).
- Set **`--max-candidates`** (e.g. `--max-candidates 500000`) to cap each
  target's generation.
- Scan **fewer targets per run**, or let the built-in per-target streaming do
  it (it kicks in automatically for more than one target when not using `--ct`
  or `-P`).

twistr now watches its own memory during generation and will **stop early with
a printed reason** rather than being killed — but a smaller dictionary or an
explicit `--max-candidates` is the real fix. You'll see notes like:

```
note: dictionary has 812,004 words -> up to ~3,248,016 combosquatting candidates
      per target. twistr will cap generation near ~13 GB RAM.
note: northface.com: generation stopped early - memory budget reached (~13000 MB)
      after 3,120,000 candidates; scanning the 3,120,000 generated so far
```

**`warning: N domains could not be resolved even after retry rounds`**
Your resolver dropped queries under load. Use better `--nameservers`
(`1.1.1.1,8.8.4.4`) and/or lower `--concurrency`.

**`--nameservers` seems ignored**
It requires `aiodns`. Without it, twistr uses the system socket resolver.

**`--web` / `--rdap` / `--favicon` do nothing**
They require `aiohttp` (and content similarity requires `ppdeep`). twistr prints
a one-line warning and skips them.

**`--ct` returns nothing or a 403**
crt.sh rate-limits; twistr logs it and continues. Try again later, or run `--ct`
on a smaller set of targets.

**A domain shows `wildcard`**
It only "resolves" because its parent zone answers for every name. It is not a
real registration and is excluded from the live count on purpose.

**A registered domain shows `!servfail` in the `ns` column**
It's registered but its own nameservers are broken (a lame delegation). twistr
still counts it as live.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (including `--list-fuzzers`). |
| `2` | Usage error: no targets, unreadable wordlist, unknown fuzzer, or unwritable output file. |
| `130` | Interrupted with Ctrl-C. |

A closed downstream pipe (e.g. `... | head`) exits cleanly with no traceback.

---

## FAQ

**Is this a drop-in dnstwist replacement?**
It covers the same core job and shares familiar flags (`-r`, `-m`,
`--dictionary`, `--tld`→`--tld-file`, `--fuzzers`, `--nameservers`). It adds
CT discovery, RDAP age, favicon matching, wildcard detection, live streaming,
and per-target memory-bounded scanning. dnstwist has some things twistr doesn't
(GeoIP, TLSH, a web GUI), so for maximum coverage some teams run both.

**Does it register or contact the lookalike domains?**
By default it only does DNS lookups. `--web`/`--favicon` fetch the candidate's
homepage/favicon; `--rdap` queries public RDAP; `--ct` queries crt.sh. It never
registers anything.

**Can I scan domains I don't own?**
twistr is a defensive tool. Only scan domains you own or are authorized to
assess, and follow the acceptable-use rules of any resolver/service you point
it at.

**Why is a homoglyph shown as `xn--…`?**
That's the domain's real (punycode) form — what actually resolves and what you'd
put in a blocklist. The `domain` column in `csv`/`json` shows the human-readable
Unicode version too.

---

## Development and tests

`test_twistr.py` is an offline test suite: it replaces DNS with a fake
resolver, so it needs no network, finishes in about three seconds, and gives
the same result every time.

```bash
pip install pytest
pytest -q                 # from the directory holding twistr.py
```

```
38 passed in 3.14s
```

Every test exists because the behaviour it checks broke at least once during
development, and each one names that bug in its docstring. The suite covers:

- **generation** — the original domain never appears in its own results,
  candidates that encode to the same wire name are queried once, number-row
  typos, whole-script IDN homographs, registry character rules, and
  `--max-candidates` capping without starving the later fuzzers or cutting a
  sorted dictionary to the front of the alphabet;
- **DNS parsing** — answers filtered by record type and owner, so an alias
  answer can't be mistaken for an address or a delegation;
- **scanning** — apex-CNAME parked domains counted as registered, wildcard
  zones *not* counted, persistent SERVFAIL classified as a lame delegation, MX
  only queried with `-m`, a per-query deadline that stops one dead name
  hanging the scan, and one pathological domain never aborting a run;
- **output** — every format renders from unresolved defaults, `domains` output
  ranked and deduplicated, `--live` streaming actually reaching disk, atomic
  writes leaving no temp files, and timestamped filenames;
- **resolvers** — filtering resolvers refused with the unfiltered alternative
  named, the `unfiltered` preset, and `host:port` / IPv6 parsing;
- **CLI and UI** — `--concurrency auto` and its validation, the plain
  (redirected) progress renderer staying free of colour and carriage returns,
  the fallback when `rich` is missing, and a static check that **every**
  `ui.*` call site passes the arguments those helpers require.

That last one is worth keeping: a single `ui.item()` call with a missing
argument once crashed a real scan, and no unit test of the `UI` class can
catch a bad call site. The check parses `twistr.py` and inspects every call.

If you change twistr, run `pytest -q` before a long scan. The suite catches
regressions in seconds that a 12-hour run would otherwise surface the hard
way.

---

## License & credits

twistr is licensed under the **Apache License, Version 2.0** — see the
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) files.

It is inspired by and derives some data and methods from
[**dnstwist**](https://github.com/elceef/dnstwist) by Marcin Ulikowski, which
is also Apache-2.0 licensed. twistr is an independent reimplementation (async
architecture, its own scanning/scoring/output), but the keyboard-adjacency
maps, part of the homoglyph method and glyph data, and the per-registry IDN
character tables were adapted from dnstwist. Full attribution is in the
[`NOTICE`](NOTICE) file. No endorsement by the dnstwist project is implied.

If dnstwist is useful to you, consider starring or supporting the original
project too.
