# Mini-SIEM: Real-Time Web Log Intrusion & Brute-Force Detector

A single-file C++17 tool that reads Apache/Nginx access logs and detects suspicious activity: brute-force logins, request flooding, vulnerability scanning, directory traversal, and SQL/XSS/command injection. It works on finished log files or in live mode (like `tail -f`), prints alerts as they happen, shows a Top-K "most aggressive IPs" dashboard, and exports a CSV report plus a ready-to-use nginx blocklist.

Built as a **Data Structures & Algorithms** course project. Every core feature is powered by a deliberately chosen data structure.

---

## Features

- **Five detection rules:** brute force, rate abuse, scanner/probing, directory traversal, injection
- **Sliding-window counters:** per-IP windows, so "10 failed logins in 60 seconds" is measured exactly, not approximated
- **Top-K leaderboard:** the K most aggressive IPs, ranked by a weighted threat score
- **Live mode:** `--follow` keeps watching a log file as new lines are appended
- **Evasion-resistant URL checks:** paths are URL-decoded twice and lower-cased, so `%252e%252e%252f` is still caught as `../`
- **Robust parser:** malformed lines are counted and skipped instead of crashing the program
- **Built-in demo:** generates a realistic attack log, so you can try it without real data
- **Reports:** `report.csv` (every flagged IP) and `blocklist.txt` (nginx `deny` rules)
- **No dependencies:** standard library only; does not rely on platform-specific `timegm`

---

## Quick start

**Requirements:** a C++17 compiler (developed and tested with g++).

```bash
# build
g++ -std=c++17 -O2 siem_detector.cpp -o siem

# demo: generates sample_access.log and analyses it
./siem
```

---

## Usage

```text
siem                         demo mode (generate sample log + analyse)
siem <logfile> [options]     analyse a log file
siem --generate <file>       only create a sample attack log
```

| Option | Description | Default |
|---|---|---|
| `--follow` | Live mode (tail -f style), stop with Ctrl+C | off |
| `--window S` | Sliding window length in seconds | 60 |
| `--brute N` | Failed-auth (401/403) threshold per window | 10 |
| `--rate N` | Total-requests threshold per window | 120 |
| `--scan N` | 404/probe-hit threshold per window | 15 |
| `--topk K` | Size of the leaderboard | 5 |
| `--refresh N` | Print dashboard every N lines (batch mode) | 1000 |
| `--report F` | CSV report file | `report.csv` |
| `--blocklist F` | Blocklist file | `blocklist.txt` |
| `--color` | ANSI colours | on |
| `--no-color` | Plain text, useful when redirecting output to a file | |
| `--help`, `-h` | Show help | |

**Examples**

```bash
./siem access.log                                  # analyse an existing log
./siem access.log --follow                         # watch a live log
./siem access.log --window 30 --brute 5 --topk 10  # stricter detection
./siem --generate attack.log                       # only create a sample log
```

### Expected log format

Apache/Nginx **combined** format:

```text
203.0.113.50 - - [27/Oct/2026:08:02:00 +0000] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/4.0 (Hydra)"
```

Timestamps with timezone offsets are converted to UTC.

---

## How detection works

| Threat | Trigger |
|---|---|
| `BRUTE_FORCE` | At least `--brute` responses with status 401/403 from one IP inside the window |
| `RATE_ABUSE` | At least `--rate` total requests from one IP inside the window |
| `SCANNER` | At least `--scan` 404s or known probe paths (`/.env`, `/wp-login`, `/phpmyadmin`, ...) inside the window, **or** an attack-tool user agent (sqlmap, nikto, nmap, hydra, masscan, dirbuster, gobuster, wpscan) |
| `DIR_TRAVERSAL` | Decoded path contains `../`, `/etc/passwd`, `boot.ini`, `/proc/self`, etc. |
| `INJECTION` | Decoded path contains `union select`, `or 1=1`, `<script`, `drop table`, `${jndi:`, etc. |

Each IP is alerted **once per threat type**, so the console is not flooded.

**Threat score** (used to rank the leaderboard):

```text
score = failed_auth * 3 + traversal * 15 + injection * 15 + not_found * 2
        + total_requests / 10 + 50 per active flag
```

---

## Data structures & algorithms used

| Structure | Where | Why | Complexity |
|---|---|---|---|
| `std::unordered_map` | Per-IP state, per-endpoint failure counters, status-code counts | Fast lookup by key | O(1) average |
| `std::deque` | Sliding window of timestamps (`SlidingWindow` class) | Push at back, evict from front | O(1) amortised |
| `std::priority_queue` (min-heap) | Top-K leaderboard | Keeps only the best K, replacing the weakest | O(n log K) |
| Template function | Generic `topK()` | Works on any map with any scoring function (used for IPs *and* endpoints) | |
| Bit flags (`enum Threat`) | Per-IP threat state | Compact, many flags in one `unsigned` | O(1) |
| Idle eviction | `evictIdle()` | Forgets clean IPs idle for 10 min so memory stays bounded on huge logs | O(n) every 1000 lines |
| Howard Hinnant's date algorithm | `timeutil` namespace | Converts dates to epoch seconds without platform-specific functions | O(1) |

---

## Sample output

Running `./siem` (demo mode) produces alerts like:

```text
[ALERT] 2026-10-27 08:02:07  BRUTE_FORCE   203.0.113.50     10 failed auth (401/403) in 60s, last on /login
[ALERT] 2026-10-27 08:06:42  DIR_TRAVERSAL 192.0.2.99       path traversal attempt: /download?file=../../../../etc/passwd
[ALERT] 2026-10-27 08:08:20  INJECTION     192.0.2.150      injection payload: /item?id=1;DROP+TABLE+users
[ALERT] 2026-10-27 08:11:58  RATE_ABUSE    203.0.113.200    120 requests in 60s
```

and a dashboard like:

```text
#   IP               SCORE   REQS    FAILS   404s    FLAGS
1   203.0.113.50     924     266     266     0       BRUTE_FORCE,SCANNER
2   203.0.113.77     360     100     100     0       BRUTE_FORCE
3   192.0.2.99       281     10      10      0       BRUTE_FORCE,DIR_TRAVERSAL
4   198.51.100.200   176     60      0       60      SCANNER
5   192.0.2.150      170     8       0       0       INJECTION
```

### Output files

- **`report.csv`**: one row per flagged IP with score, request counts, peak window values, first/last seen, and flags
- **`blocklist.txt`**: nginx syntax, ready to paste into a config:

```text
deny 203.0.113.50;   # BRUTE_FORCE,SCANNER
deny 192.0.2.99;   # BRUTE_FORCE,DIR_TRAVERSAL
```

---

## The demo log simulates

| Attacker | Behaviour |
|---|---|
| `203.0.113.50` | Hydra brute-forcing `/login` |
| `203.0.113.77` | Slow credential stuffing on `/api/login` |
| `192.0.2.99` | Directory traversal (including double-encoded payloads) |
| `192.0.2.150` | SQL injection |
| `198.51.100.200` | Nikto-style vulnerability scanner |
| `203.0.113.200` | Request flooding |

mixed with 40 normal visitors and two deliberately malformed lines to test the parser. The generator uses a fixed seed (42), so the demo is reproducible.

---

## Project structure

```text
.
├── siem_detector.cpp    # entire project (config, parser, detectors, analyzer, reports, demo generator)
├── README.md
├── LICENSE
├── .gitignore
├── docs/                # optional: screenshots, report, slides
└── examples/            # optional: sample output
    ├── sample_access.log
    ├── report.csv
    └── blocklist.txt
```

---

## Limitations & ideas for future work

- Only analyses the request path and user agent; it does not inspect POST bodies or headers
- Detection is signature- and threshold-based, so it can have false positives (e.g. an office behind one shared NAT IP) and false negatives (novel payloads)
- Alerts once per IP per threat type; there is no alert reset or expiry
- Single-threaded, reads one file at a time
- Ideas: IPv6 awareness, CIDR/subnet aggregation, JSON output, config file, unit tests, syslog or email alerts, automatic firewall integration

---

## Disclaimer

This is an educational project. The IP addresses in the demo log come from reserved documentation ranges (RFC 5737) and are fictional. Review any generated blocklist before applying it to a real server.

---

## License

Released under the MIT License. See [LICENSE](LICENSE).
