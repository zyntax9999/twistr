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
- [Command-line reference](#command-line-reference)
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
- [Performance notes](#performance-notes)
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
# nothing required, but strongly recommended:
pip install aiodns aiohttp tldextract rich idna ppdeep mmh3 uvloop
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
| `--fuzzers LIST` | Comma-separated subset of fuzzers to use (default: all). See [Fuzzers](#fuzzers). |
| `--list-fuzzers` | Print the available fuzzers and their risk weights, then exit. |
| `--dictionary FILE` | Wordlist for the `dictionary` (combosquatting) fuzzer, one word per line. Replaces the built-in list. |
| `--tld-file FILE` | Wordlist of TLDs for the `tld-swap` fuzzer, one per line. Replaces the built-in list. |
| `--all-idn` | Also generate IDN lookalikes using characters the TLD's registry doesn't accept (off by default, since those can't be registered there). |
| `--max-candidates N` | Stop generating a target's permutations after N candidates (0 = unlimited). Guards against giant dictionaries; twistr also self-limits as it approaches available memory. |
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
| `--concurrency N` | `64` | Max in-flight lookups per process. I/O-bound, so this can be high (200–1000 with good resolvers). |
| `-P, --processes N` | `1` | Split the scan across N worker processes to use multiple cores. Helps most with `--web`/`ppdeep` or very high concurrency. |
| `--timeout SECS` | `5.0` | Per-query DNS timeout. |
| `--nameservers LIST` | *(system)* | Comma-separated resolvers, e.g. `1.1.1.1,8.8.4.4` (needs `aiodns`). Multiple resolvers are load-balanced. |

### Output

| Option | Default | Description |
|---|---|---|
| `--format {table,json,csv,domains}` | `table` | Output format. `domains` = one domain per line, ranked worst-first. |
| `-o, --output FILE` | *(stdout)* | Write to a file. `strftime` tokens are expanded, e.g. `-o 'twistr-%Y%m%d.csv'`. |
| `--outdir DIR` | | Write to DIR with an auto, timestamped, unique filename. |
| `--timestamp` | | Add a date-time stamp to the output filename so each run is unique. |
| `--live` | | Write matches to the output file **as they're found** (tail/copy mid-run). `domains` and `csv` only; the file is risk-sorted with a final atomic rewrite. |
| `--progress {auto,bar,plain,none}` | `auto` | Progress display. `auto` = animated bar on a terminal, timestamped log lines when redirected/backgrounded. |

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
| `various` | TLD-in-name, `www` noise, plurals | `paypalcom.com`, `wwwpaypal.com` |

A special `homoglyph-script` sub-result produces whole-script IDN homographs
(e.g. an all-Cyrillic look-alike that is visually identical to the original).
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
  registered count but kept in the output so you can see them.

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
# Raise concurrency (biggest single speed lever; needs good resolvers)
python twistr.py example.com -r --concurrency 400 --nameservers 1.1.1.1,8.8.4.4

# Use multiple CPU cores (helps most with --web/--all-checks, e.g. 6 cores)
python twistr.py -i brands.txt --all-checks -r -P 6 --concurrency 150

# Shorter timeout for a fast resolver on a big list
python twistr.py -i brands.txt -r --timeout 3 --concurrency 300
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

## Performance notes

- twistr is **I/O-bound** — nearly all its time is spent waiting on DNS. The
  single most effective speed lever is `--concurrency`, not CPU cores.
- Install **`aiodns`** and **`uvloop`** for the fast path. Without `aiodns`,
  twistr falls back to a slower socket resolver (A/AAAA only, no `--nameservers`).
- `-P/--processes` mainly helps when there's real per-domain CPU work
  (`--web`/`ppdeep` content hashing) or at very high concurrency; for pure DNS,
  a single process with high `--concurrency` is usually just as fast.
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
