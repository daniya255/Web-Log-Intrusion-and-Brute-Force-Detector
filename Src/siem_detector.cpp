/*
 * ============================================================================
 *  Real-Time Web Log Intrusion & Brute-Force Detector   (mini-SIEM in C++)
 *  Course : Data Structures & Algorithms
 *
 *  DSA used
 *    - std::unordered_map : per-IP state, per-endpoint counters  (O(1) avg)
 *    - std::deque         : sliding-window queues of timestamps  (O(1) amortised)
 *    - std::priority_queue: min-heap of size K -> Top-K attackers (O(n log K))
 *    - template function  : generic topK() works for any map / score function
 *
 *  Build :  g++ -std=c++17 -O2 siem_detector.cpp -o siem
 *  Run   :  ./siem                      (demo: generates a log, analyses it)
 *           ./siem access.log           (analyse an existing log, then exit)
 *           ./siem access.log --follow  (live mode, like `tail -f`)
 *           ./siem access.log --no-color  (plain text, e.g. when redirecting output)
 *           ./siem --help
 * ============================================================================
 */

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <queue>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace std;

// ============================================================================
//  SECTION 1 : CONFIGURATION
// ============================================================================
struct Config {
    long windowSec       = 60;    // sliding window length (seconds)
    int  bruteThreshold  = 10;    // failed auth (401/403) inside window
    int  rateThreshold   = 120;   // total requests inside window
    int  scanThreshold   = 15;    // 404s / probes inside window
    int  topK            = 5;     // size of the leaderboard
    long refreshLines    = 1000;  // print dashboard every N lines (batch mode)
    long idleEvictSec    = 600;   // forget clean IPs idle for this long
    bool follow          = false; // live-tail mode
    bool color           = true; // ANSI colours
    string reportFile    = "report.csv";
    string blocklistFile = "blocklist.txt";
};

static bool g_color = false;
static volatile sig_atomic_t g_stop = 0;
static void onSignal(int) { g_stop = 1; }

static const char* RED()   { return g_color ? "\033[1;31m" : ""; }
static const char* YEL()   { return g_color ? "\033[1;33m" : ""; }
static const char* CYAN()  { return g_color ? "\033[1;36m" : ""; }
static const char* RESET() { return g_color ? "\033[0m"    : ""; }

// ============================================================================
//  SECTION 2 : TIME UTILITIES  (no dependency on platform-specific timegm)
// ============================================================================
namespace timeutil {

// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
long daysFromCivil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (long)doe - 719468;
}

void civilFromDays(long z, int& y, unsigned& m, unsigned& d) {
    z += 719468;
    long era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = (int)yoe + (int)era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y += (m <= 2);
}

static const char* MONTHS[12] = {"Jan","Feb","Mar","Apr","May","Jun",
                                 "Jul","Aug","Sep","Oct","Nov","Dec"};

// "10/Oct/2026:13:55:36 +0000"  ->  epoch seconds (UTC)
bool parseTimestamp(const string& s, long& out) {
    int d, y, hh, mm, ss, tz = 0;
    char mon[4] = {0};
    char sign = '+';
    int n = sscanf(s.c_str(), "%d/%3[A-Za-z]/%d:%d:%d:%d %c%d",
                   &d, mon, &y, &hh, &mm, &ss, &sign, &tz);
    if (n < 6) return false;
    int m = -1;
    for (int i = 0; i < 12; ++i) if (strcmp(MONTHS[i], mon) == 0) m = i + 1;
    if (m < 0) return false;
    long epoch = daysFromCivil(y, m, d) * 86400L + hh * 3600L + mm * 60L + ss;
    if (n == 8) {
        long off = (tz / 100) * 3600L + (tz % 100) * 60L;
        epoch += (sign == '-') ? off : -off;
    }
    out = epoch;
    return true;
}

// epoch -> "10/Oct/2026:13:55:36 +0000"  (used by the log generator)
string formatApache(long t) {
    long days = t / 86400, rem = t % 86400;
    int y; unsigned m, d;
    civilFromDays(days, y, m, d);
    char buf[64];
    snprintf(buf, sizeof buf, "%02u/%s/%04d:%02ld:%02ld:%02ld +0000",
             d, MONTHS[m - 1], y, rem / 3600, (rem % 3600) / 60, rem % 60);
    return buf;
}

// epoch -> "2026-10-27 08:03:12"  (used for alerts)
string formatISO(long t) {
    long days = t / 86400, rem = t % 86400;
    int y; unsigned m, d;
    civilFromDays(days, y, m, d);
    char buf[32];
    snprintf(buf, sizeof buf, "%04d-%02u-%02u %02ld:%02ld:%02ld",
             y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60);
    return buf;
}
} // namespace timeutil

// ============================================================================
//  SECTION 3 : STRING HELPERS & SIGNATURE LISTS
// ============================================================================
static string toLower(string s) {
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

// Decodes %XX and '+'.  Applied twice to defeat double-encoding (%252e%252e).
static string urlDecode(const string& s) {
    string o;
    o.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() &&
            isxdigit((unsigned char)s[i + 1]) && isxdigit((unsigned char)s[i + 2])) {
            o += (char)stoi(s.substr(i + 1, 2), nullptr, 16);
            i += 2;
        } else if (s[i] == '+') {
            o += ' ';
        } else {
            o += s[i];
        }
    }
    return o;
}

static bool containsAny(const string& text, const vector<string>& needles) {
    for (const string& n : needles)
        if (text.find(n) != string::npos) return true;
    return false;
}

static const vector<string> TRAVERSAL_SIGS = {
    "../", "..\\", "/etc/passwd", "/etc/shadow", "boot.ini", "win.ini", "/proc/self"};
static const vector<string> INJECTION_SIGS = {
    "union select", "' or ", "\" or ", "or 1=1", "<script", "sleep(", "drop table",
    "${jndi:", "; cat ", "|| ping", "xp_cmdshell"};
static const vector<string> PROBE_SIGS = {
    "/.env", "/.git", "wp-login", "wp-admin", "phpmyadmin", "/admin", "/config.php",
    "/backup", "/shell", "/cgi-bin"};
static const vector<string> TOOL_UA_SIGS = {
    "sqlmap", "nikto", "nmap", "hydra", "masscan", "dirbuster", "gobuster", "wpscan"};

// ============================================================================
//  SECTION 4 : LOG ENTRY + PARSER
// ============================================================================
struct LogEntry {
    string ip;
    long   ts = 0;
    string method;
    string rawPath;
    string userAgent;
    int    status = 0;
};

// Parses one line of Apache/Nginx "combined" format:
//   IP - - [dd/Mon/yyyy:HH:MM:SS +0000] "METHOD /path HTTP/1.1" 200 512 "ref" "ua"
bool parseLine(const string& line, LogEntry& e) {
    size_t lb = line.find('[');
    if (lb == string::npos) return false;
    size_t rb = line.find(']', lb);
    if (rb == string::npos) return false;

    { stringstream head(line.substr(0, lb)); head >> e.ip; }
    if (e.ip.empty()) return false;
    if (!timeutil::parseTimestamp(line.substr(lb + 1, rb - lb - 1), e.ts)) return false;

    size_t q1 = line.find('"', rb);
    if (q1 == string::npos) return false;
    size_t q2 = line.find('"', q1 + 1);
    if (q2 == string::npos) return false;

    {
        stringstream req(line.substr(q1 + 1, q2 - q1 - 1));
        req >> e.method >> e.rawPath;
        if (e.rawPath.empty()) e.rawPath = e.method;   // malformed request line
    }
    {
        stringstream rest(line.substr(q2 + 1));
        string bytesTok;
        if (!(rest >> e.status >> bytesTok)) return false;
    }
    size_t u2 = line.rfind('"');
    if (u2 != string::npos && u2 > q2) {
        size_t u1 = line.rfind('"', u2 - 1);
        if (u1 != string::npos && u1 > q2) e.userAgent = line.substr(u1 + 1, u2 - u1 - 1);
    }
    return true;
}

// ============================================================================
//  SECTION 5 : SLIDING WINDOW  (queue of timestamps)
// ============================================================================
class SlidingWindow {
    deque<long> q_;
    long span_;
public:
    explicit SlidingWindow(long span = 60) : span_(span) {}

    // push new event, drop everything that fell out of the window
    void add(long ts) {
        q_.push_back(ts);
        evict(ts);
    }
    void evict(long now) {
        while (!q_.empty() && q_.front() <= now - span_) q_.pop_front();
    }
    size_t count() const { return q_.size(); }
};

// ============================================================================
//  SECTION 6 : THREAT FLAGS + PER-IP STATE
// ============================================================================
enum Threat : unsigned {
    T_BRUTE = 1, T_RATE = 2, T_SCAN = 4, T_TRAVERSAL = 8, T_INJECTION = 16
};

static string threatName(unsigned t) {
    switch (t) {
        case T_BRUTE:     return "BRUTE_FORCE";
        case T_RATE:      return "RATE_ABUSE";
        case T_SCAN:      return "SCANNER";
        case T_TRAVERSAL: return "DIR_TRAVERSAL";
        case T_INJECTION: return "INJECTION";
    }
    return "UNKNOWN";
}

static string flagsToString(unsigned f) {
    if (!f) return "-";
    string s;
    for (unsigned bit : {T_BRUTE, T_RATE, T_SCAN, T_TRAVERSAL, T_INJECTION})
        if (f & bit) s += (s.empty() ? "" : ",") + threatName(bit);
    return s;
}

struct IPStats {
    long total = 0, failed = 0, notFound = 0, traversal = 0, injection = 0;
    long firstSeen = 0, lastSeen = 0;
    size_t peakFail = 0, peakRate = 0;
    unsigned flags = 0;
    SlidingWindow all, fail, nf;           // three independent sliding windows

    explicit IPStats(long window = 60) : all(window), fail(window), nf(window) {}

    // Weighted "aggressiveness" score - this is the key used by the heap.
    long threatScore() const {
        long sc = failed * 3 + traversal * 15 + injection * 15 + notFound * 2 + total / 10;
        for (unsigned b = flags; b; b &= (b - 1)) sc += 50;   // +50 per flag
        return sc;
    }
};

struct Alert {
    long   ts;
    string ip;
    string type;
    string detail;
};

// ============================================================================
//  SECTION 7 : GENERIC TOP-K  (min-heap of size K)
// ============================================================================
// Works on ANY map whose mapped value can be turned into a long by scoreFn.
// Heap root = weakest of the current best K, so replacing it is O(log K).
template <typename Map, typename ScoreFn>
vector<pair<long, string>> topK(const Map& m, size_t k, ScoreFn scoreFn) {
    using P = pair<long, string>;
    priority_queue<P, vector<P>, greater<P>> heap;     // min-heap
    for (const auto& kv : m) {
        P cand(scoreFn(kv.second), kv.first);
        if (cand.first <= 0) continue;
        if (heap.size() < k) {
            heap.push(cand);
        } else if (cand > heap.top()) {
            heap.pop();
            heap.push(cand);
        }
    }
    vector<P> out;
    while (!heap.empty()) { out.push_back(heap.top()); heap.pop(); }
    reverse(out.begin(), out.end());                   // strongest first
    return out;
}

// ============================================================================
//  SECTION 8 : THE ANALYZER  (heart of the project)
// ============================================================================
class LogAnalyzer {
    Config cfg_;
    unordered_map<string, IPStats> ips_;
    unordered_map<string, long>    endpointFails_;
    unordered_map<int, long>       statusCount_;
    vector<Alert> alerts_;
    long lines_ = 0, parsed_ = 0, malformed_ = 0, evicted_ = 0, latestTs_ = 0;

    void raise(IPStats& s, unsigned type, const LogEntry& e, const string& detail) {
        if (s.flags & type) return;                    // alert once per IP per type
        s.flags |= type;
        alerts_.push_back({e.ts, e.ip, threatName(type), detail});
        cout << RED() << "[ALERT] " << RESET()
             << timeutil::formatISO(e.ts) << "  "
             << left << setw(14) << threatName(type)
             << setw(17) << e.ip << detail << "\n";
    }

    // Drop IPs that are clean and idle -> keeps memory bounded on huge logs.
    void evictIdle() {
        for (auto it = ips_.begin(); it != ips_.end();) {
            if (it->second.flags == 0 && latestTs_ - it->second.lastSeen > cfg_.idleEvictSec) {
                it = ips_.erase(it);
                ++evicted_;
            } else {
                ++it;
            }
        }
    }

public:
    explicit LogAnalyzer(const Config& c) : cfg_(c) {}

    void process(const string& line) {
        ++lines_;
        LogEntry e;
        if (!parseLine(line, e)) { ++malformed_; return; }
        ++parsed_;
        ++statusCount_[e.status];
        latestTs_ = max(latestTs_, e.ts);

        auto it = ips_.find(e.ip);
        if (it == ips_.end()) {
            it = ips_.emplace(e.ip, IPStats(cfg_.windowSec)).first;
            it->second.firstSeen = e.ts;
        }
        IPStats& s = it->second;
        s.lastSeen = e.ts;
        ++s.total;
        s.all.add(e.ts);
        s.peakRate = max(s.peakRate, s.all.count());

        // normalise the URL: decode twice, lower-case
        string decoded = toLower(urlDecode(urlDecode(e.rawPath)));
        string basePath = e.rawPath.substr(0, e.rawPath.find('?'));

        // ---- rule 1 : brute force (rapid 401/403) ----
        if (e.status == 401 || e.status == 403) {
            ++s.failed;
            s.fail.add(e.ts);
            ++endpointFails_[basePath];
            s.peakFail = max(s.peakFail, s.fail.count());
            if ((int)s.fail.count() >= cfg_.bruteThreshold)
                raise(s, T_BRUTE, e, to_string(s.fail.count()) + " failed auth (401/403) in " +
                                     to_string(cfg_.windowSec) + "s, last on " + basePath);
        }

        // ---- rule 2 : scanner (many 404s / known probe paths / attack-tool UA) ----
        bool probe = containsAny(decoded, PROBE_SIGS);
        if (e.status == 404 || probe) {
            if (e.status == 404) ++s.notFound;
            s.nf.add(e.ts);
            if ((int)s.nf.count() >= cfg_.scanThreshold)
                raise(s, T_SCAN, e, to_string(s.nf.count()) + " 404/probe hits in " +
                                     to_string(cfg_.windowSec) + "s");
        }
        if (!e.userAgent.empty() && containsAny(toLower(e.userAgent), TOOL_UA_SIGS))
            raise(s, T_SCAN, e, "attack-tool user agent: " + e.userAgent);

        // ---- rule 3 : directory traversal ----
        if (containsAny(decoded, TRAVERSAL_SIGS)) {
            ++s.traversal;
            raise(s, T_TRAVERSAL, e, "path traversal attempt: " + e.rawPath.substr(0, 60));
        }

        // ---- rule 4 : SQLi / XSS / command injection ----
        if (containsAny(decoded, INJECTION_SIGS)) {
            ++s.injection;
            raise(s, T_INJECTION, e, "injection payload: " + e.rawPath.substr(0, 60));
        }

        // ---- rule 5 : request-rate abuse (DoS / aggressive scraping) ----
        if ((int)s.all.count() >= cfg_.rateThreshold)
            raise(s, T_RATE, e, to_string(s.all.count()) + " requests in " +
                                 to_string(cfg_.windowSec) + "s");

        if (lines_ % 1000 == 0) evictIdle();
    }

    // ---------------- reporting ----------------
    void printDashboard() const {
        cout << "\n" << CYAN()
             << "================= LIVE DASHBOARD  @ " << timeutil::formatISO(latestTs_)
             << " =================" << RESET() << "\n";
        cout << "lines " << lines_ << " | parsed " << parsed_ << " | malformed " << malformed_
             << " | tracked IPs " << ips_.size() << " | evicted " << evicted_
             << " | alerts " << alerts_.size() << "\n\n";

        auto best = topK(ips_, cfg_.topK, [](const IPStats& s) { return s.threatScore(); });
        cout << YEL() << "Top " << cfg_.topK << " most aggressive IPs" << RESET() << "\n";
        cout << left << setw(4) << "#" << setw(17) << "IP" << setw(8) << "SCORE"
             << setw(8) << "REQS" << setw(8) << "FAILS" << setw(8) << "404s"
             << "FLAGS\n";
        int rank = 1;
        for (const auto& p : best) {
            const IPStats& s = ips_.at(p.second);
            cout << left << setw(4) << rank++ << setw(17) << p.second << setw(8) << p.first
                 << setw(8) << s.total << setw(8) << s.failed << setw(8) << s.notFound
                 << flagsToString(s.flags) << "\n";
        }
        if (best.empty()) cout << "  (no suspicious activity yet)\n";

        auto eps = topK(endpointFails_, 3, [](long v) { return v; });
        cout << "\n" << YEL() << "Most attacked endpoints (failed auth)" << RESET() << "\n";
        for (const auto& p : eps) cout << "  " << setw(6) << p.first << "  " << p.second << "\n";
        if (eps.empty()) cout << "  (none)\n";

        cout << "\nStatus codes: ";
        vector<pair<int, long>> sc(statusCount_.begin(), statusCount_.end());
        sort(sc.begin(), sc.end());
        for (auto& p : sc) cout << p.first << "=" << p.second << "  ";
        cout << "\n";
    }

    // CSV of every flagged IP + nginx-style deny list
    void exportReports() const {
        ofstream rep(cfg_.reportFile);
        rep << "ip,score,total_requests,failed_auth,not_found,traversal,injection,"
               "peak_fail_window,peak_rate_window,first_seen,last_seen,flags\n";
        ofstream bl(cfg_.blocklistFile);
        bl << "# auto-generated blocklist (nginx syntax)\n";

        vector<pair<long, string>> flagged;
        for (const auto& kv : ips_)
            if (kv.second.flags) flagged.push_back({kv.second.threatScore(), kv.first});
        sort(flagged.rbegin(), flagged.rend());

        for (const auto& p : flagged) {
            const IPStats& s = ips_.at(p.second);
            rep << p.second << "," << p.first << "," << s.total << "," << s.failed << ","
                << s.notFound << "," << s.traversal << "," << s.injection << ","
                << s.peakFail << "," << s.peakRate << ","
                << timeutil::formatISO(s.firstSeen) << "," << timeutil::formatISO(s.lastSeen)
                << ",\"" << flagsToString(s.flags) << "\"\n";
            bl << "deny " << p.second << ";   # " << flagsToString(s.flags) << "\n";
        }
        cout << "\nReports written: " << cfg_.reportFile << ", " << cfg_.blocklistFile
             << "  (" << flagged.size() << " IPs flagged)\n";
    }

    void printSummary() const {
        cout << "\n----------------------- FINAL ALERT LOG -----------------------\n";
        for (const Alert& a : alerts_)
            cout << timeutil::formatISO(a.ts) << "  " << left << setw(14) << a.type
                 << setw(17) << a.ip << a.detail << "\n";
        if (alerts_.empty()) cout << "(no alerts)\n";
    }
};

// ============================================================================
//  SECTION 9 : SAMPLE-LOG GENERATOR  (so the demo works without real logs)
// ============================================================================
static void emitLine(ofstream& out, const string& ip, long ts, const string& method,
                     const string& path, int status, int bytes, const string& ua) {
    out << ip << " - - [" << timeutil::formatApache(ts) << "] \"" << method << " " << path
        << " HTTP/1.1\" " << status << " " << bytes << " \"-\" \"" << ua << "\"\n";
}

void generateSampleLog(const string& file) {
    mt19937 rng(42);
    ofstream out(file);
    if (!out) { cerr << "Cannot create " << file << "\n"; return; }

    const long start = timeutil::daysFromCivil(2026, 10, 27) * 86400L + 8 * 3600L;
    const int DURATION = 900;                               // 15 minutes of traffic

    vector<string> normalIPs;
    for (int i = 1; i <= 40; ++i) normalIPs.push_back("198.51.100." + to_string(i));
    const vector<string> pages = {"/", "/index.html", "/about", "/products", "/blog/post-1",
                                  "/static/app.js", "/static/style.css", "/contact", "/api/items"};
    const string browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0";
    auto pick = [&](const vector<string>& v) { return v[rng() % v.size()]; };

    for (int sec = 0; sec < DURATION; ++sec) {
        long ts = start + sec;

        // normal visitors
        int n = rng() % 4;
        for (int i = 0; i < n; ++i) {
            int r = rng() % 100, st = 200;
            string path = pick(pages);
            if (r >= 92 && r < 96) st = 304;
            else if (r >= 96 && r < 98) { st = 404; path = "/old-page"; }
            else if (r >= 98) st = 500;
            emitLine(out, pick(normalIPs), ts, "GET", path, st, 500 + rng() % 5000, browser);
        }
        // one honest user mistypes a password now and then
        if (sec % 97 == 0) emitLine(out, "198.51.100.7", ts, "POST", "/login", 401, 120, browser);

        // 1) brute-force attacker (hydra)
        if (sec >= 120 && sec < 300)
            for (int i = 0, k = 1 + rng() % 2; i < k; ++i)
                emitLine(out, "203.0.113.50", ts, "POST", "/login", 401, 120, "Mozilla/4.0 (Hydra)");
        // 2) slow credential stuffer
        if (sec >= 200 && sec < 500 && sec % 3 == 0)
            emitLine(out, "203.0.113.77", ts, "POST", "/api/login", (sec % 2 ? 401 : 403), 90, browser);
        // 3) directory traversal
        if (sec >= 400 && sec < 430 && sec % 3 == 0) {
            const vector<string> t = {"/download?file=../../../../etc/passwd",
                                      "/static/..%2f..%2f..%2fetc%2fshadow",
                                      "/view?p=%252e%252e%252fboot.ini"};
            emitLine(out, "192.0.2.99", ts, "GET", pick(t), 403, 0, "curl/7.88");
        }
        // 4) SQL injection
        if (sec >= 500 && sec < 530 && sec % 4 == 0) {
            const vector<string> t = {"/products?id=1'+OR+1=1--", "/search?q=1+UNION+SELECT+user,pass+FROM+users",
                                      "/item?id=1;DROP+TABLE+users"};
            emitLine(out, "192.0.2.150", ts, "GET", pick(t), 500, 300, browser);
        }
        // 5) directory / vulnerability scanner (Nikto)
        if (sec >= 600 && sec < 660) {
            const vector<string> t = {"/admin", "/.env", "/wp-login.php", "/phpmyadmin/", "/backup.zip",
                                      "/config.php", "/.git/config", "/cgi-bin/test.cgi"};
            emitLine(out, "198.51.100.200", ts, "GET", pick(t), 404, 0, "Mozilla/5.00 (Nikto/2.1.6)");
        }
        // 6) request flooder
        if (sec >= 700 && sec < 740)
            for (int i = 0, k = 5 + rng() % 4; i < k; ++i)
                emitLine(out, "203.0.113.200", ts, "GET", "/", 200, 4200, browser);
    }
    // two garbage lines to prove the parser is robust
    out << "this is not a valid log line\n";
    out << "10.0.0.1 - - [bad-timestamp] \"GET / HTTP/1.1\" 200 1\n";
    cout << "Sample log generated: " << file << "\n";
}

// ============================================================================
//  SECTION 10 : DRIVERS (batch + live follow)
// ============================================================================
static void runBatch(const string& file, LogAnalyzer& an, const Config& cfg) {
    ifstream in(file);
    if (!in) { cerr << "Cannot open " << file << "\n"; return; }
    string line;
    long n = 0;
    while (getline(in, line)) {
        if (line.empty()) continue;
        an.process(line);
        if (cfg.refreshLines > 0 && ++n % cfg.refreshLines == 0) an.printDashboard();
    }
}

static void runFollow(const string& file, LogAnalyzer& an) {
    ifstream in(file);
    if (!in) { cerr << "Cannot open " << file << "\n"; return; }
    cout << "Following " << file << " ... press Ctrl+C to stop.\n";
    string line;
    bool dirty = false;
    auto lastDash = chrono::steady_clock::now();
    while (!g_stop) {
        streampos pos = in.tellg();
        if (getline(in, line)) {
            if (in.eof()) {                         // half-written line: wait for the rest
                in.clear();
                in.seekg(pos);
                this_thread::sleep_for(chrono::milliseconds(200));
                continue;
            }
            if (!line.empty()) { an.process(line); dirty = true; }
        } else {
            in.clear();                             // reached EOF: wait for new data
            this_thread::sleep_for(chrono::milliseconds(200));
        }
        auto now = chrono::steady_clock::now();
        if (dirty && now - lastDash > chrono::seconds(5)) {
            an.printDashboard();
            dirty = false;
            lastDash = now;
        }
    }
}

static void printHelp() {
    cout << "Usage:\n"
            "  siem                         demo mode (generate sample log + analyse)\n"
            "  siem <logfile> [options]     analyse a log file\n"
            "  siem --generate <file>       only create a sample attack log\n\n"
            "Options:\n"
            "  --follow        live mode (tail -f style)\n"
            "  --window  S     sliding window in seconds        (default 60)\n"
            "  --brute   N     failed-auth threshold            (default 10)\n"
            "  --rate    N     requests-per-window threshold    (default 120)\n"
            "  --scan    N     404/probe threshold              (default 15)\n"
            "  --topk    K     leaderboard size                 (default 5)\n"
            "  --refresh N     dashboard every N lines          (default 1000)\n"
            "  --report  F     CSV report file                  (default report.csv)\n"
            "  --blocklist F   blocklist file                   (default blocklist.txt)\n"
            "  --color         ANSI colours (default)\n"
            "  --no-color      plain text, no ANSI colours\n";
}

int main(int argc, char* argv[]) {
    Config cfg;
    string logFile;
    bool demo = (argc == 1);

    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        auto need = [&](const char* name) -> string {
            if (i + 1 >= argc) { cerr << name << " needs a value\n"; exit(1); }
            return argv[++i];
        };
        try {
        if (a == "--help" || a == "-h")      { printHelp(); return 0; }
        else if (a == "--generate")          { generateSampleLog(need("--generate")); return 0; }
        else if (a == "--follow")            cfg.follow = true;
        else if (a == "--color")             cfg.color = true;
        else if (a == "--no-color")          cfg.color = false;
        else if (a == "--window")            cfg.windowSec = stol(need("--window"));
        else if (a == "--brute")             cfg.bruteThreshold = stoi(need("--brute"));
        else if (a == "--rate")              cfg.rateThreshold = stoi(need("--rate"));
        else if (a == "--scan")              cfg.scanThreshold = stoi(need("--scan"));
        else if (a == "--topk")              cfg.topK = stoi(need("--topk"));
        else if (a == "--refresh")           cfg.refreshLines = stol(need("--refresh"));
        else if (a == "--report")            cfg.reportFile = need("--report");
        else if (a == "--blocklist")         cfg.blocklistFile = need("--blocklist");
        else if (a[0] != '-')                logFile = a;
        else { cerr << "Unknown option " << a << " (try --help)\n"; return 1; }
        } catch (const exception&) {
            cerr << "Invalid numeric value for " << a << " (try --help)\n";
            return 1;
        }
    }
    if (cfg.windowSec <= 0 || cfg.bruteThreshold <= 0 || cfg.rateThreshold <= 0 ||
        cfg.scanThreshold <= 0 || cfg.topK <= 0 || cfg.refreshLines < 0) {
        cerr << "--window, --brute, --rate, --scan and --topk must be positive; "
                "--refresh must not be negative\n";
        return 1;
    }
    g_color = cfg.color;

    if (demo) {
        logFile = "sample_access.log";
        generateSampleLog(logFile);
    }
    if (logFile.empty()) { printHelp(); return 1; }

    signal(SIGINT, onSignal);
    LogAnalyzer analyzer(cfg);

    if (cfg.follow) runFollow(logFile, analyzer);
    else            runBatch(logFile, analyzer, cfg);

    analyzer.printDashboard();
    analyzer.printSummary();
    analyzer.exportReports();
    return 0;
}
