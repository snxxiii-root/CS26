#!/usr/bin/env python3
"""
CVEHunter - Smart CVE Lookup Tool by SNXXIII
Find CVEs from vague pentester descriptions or pull full detail by CVE ID
"""

import sys
import re
import json
import argparse
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

# Colors
GREEN   = '\033[92m'
CYAN    = '\033[96m'
RED     = '\033[91m'
YELLOW  = '\033[93m'
MAGENTA = '\033[95m'
RESET   = '\033[0m'
BOLD    = '\033[1m'
DIM     = '\033[2m'

BANNER = r"""
 ██████╗██╗   ██╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔════╝██║   ██║██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║     ██║   ██║█████╗      ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║     ╚██╗ ██╔╝██╔══╝      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚██████╗ ╚████╔╝ ███████╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝  ╚═══╝  ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""

# Pentester slang / vague terms → NVD search keywords
KEYWORD_MAP = {
    # Injection
    "quotes":              "SQL injection",
    "quote":               "SQL injection",
    "sql":                 "SQL injection",
    "sqli":                "SQL injection",
    "inject":              "injection",
    "injection":           "injection",
    "command injection":   "command injection",
    "cmd injection":       "command injection",
    "os command":          "command injection",
    "shell injection":     "command injection",
    "ldap":                "LDAP injection",
    "xpath":               "XPath injection",
    "nosql":               "NoSQL injection",

    # XSS
    "xss":                 "cross-site scripting",
    "cross site":          "cross-site scripting",
    "script injection":    "cross-site scripting",
    "reflected":           "reflected XSS",
    "stored xss":          "stored cross-site scripting",
    "dom xss":             "DOM cross-site scripting",

    # Auth / Access
    "login bypass":        "authentication bypass",
    "auth bypass":         "authentication bypass",
    "bypass login":        "authentication bypass",
    "bypass auth":         "authentication bypass",
    "skip login":          "authentication bypass",
    "no password":         "authentication bypass",
    "default creds":       "default credentials",
    "default password":    "default credentials",
    "weak password":       "weak password",
    "brute force":         "brute force",
    "session":             "session fixation",
    "cookie":              "session hijacking",
    "token":               "token forgery",
    "jwt":                 "JWT vulnerability",
    "privilege":           "privilege escalation",
    "priv esc":            "privilege escalation",
    "privesc":             "privilege escalation",
    "escalation":          "privilege escalation",
    "admin access":        "unauthorized access",
    "unauthorized":        "unauthorized access",

    # File / Path
    "read files":          "path traversal",
    "read other":          "path traversal",
    "directory traversal": "path traversal",
    "path traversal":      "path traversal",
    "dot dot slash":       "path traversal",
    "../":                 "path traversal",
    "lfi":                 "local file inclusion",
    "local file":          "local file inclusion",
    "file inclusion":      "file inclusion",
    "rfi":                 "remote file inclusion",
    "remote file":         "remote file inclusion",
    "file upload":         "unrestricted file upload",
    "upload shell":        "unrestricted file upload",
    "webshell":            "web shell upload",

    # RCE / Code Execution
    "rce":                 "remote code execution",
    "remote code":         "remote code execution",
    "execute code":        "remote code execution",
    "code execution":      "remote code execution",
    "run commands":        "remote code execution",
    "reverse shell":       "remote code execution",
    "deserialization":     "deserialization",
    "deserialize":         "deserialization",
    "pickle":              "deserialization",

    # Memory
    "buffer overflow":     "buffer overflow",
    "overflow":            "buffer overflow",
    "heap overflow":       "heap buffer overflow",
    "stack overflow":      "stack buffer overflow",
    "use after free":      "use after free",
    "uaf":                 "use after free",
    "null pointer":        "null pointer dereference",
    "memory corruption":   "memory corruption",
    "format string":       "format string",

    # SSRF / XXE
    "ssrf":                "server-side request forgery",
    "internal request":    "server-side request forgery",
    "xxe":                 "XML external entity",
    "xml injection":       "XML external entity",
    "xml entity":          "XML external entity",

    # CSRF
    "csrf":                "cross-site request forgery",
    "cross site request":  "cross-site request forgery",
    "forged request":      "cross-site request forgery",

    # DoS
    "crash":               "denial of service",
    "crashing":            "denial of service",
    "dos":                 "denial of service",
    "hang":                "denial of service",
    "unresponsive":        "denial of service",
    "resource exhaustion": "resource exhaustion",
    "memory leak":         "memory leak",

    # Info Disclosure
    "information disclosure": "information disclosure",
    "info disclosure":     "information disclosure",
    "leak":                "information disclosure",
    "leaking":             "information disclosure",
    "expose":              "information disclosure",
    "exposed":             "information disclosure",
    "sensitive data":      "sensitive data exposure",
    "error message":       "information disclosure",
    "stack trace":         "information disclosure",
    "verbose error":       "information disclosure",

    # Crypto
    "weak crypto":         "weak cryptography",
    "weak encryption":     "weak encryption",
    "md5":                 "MD5 weak hash",
    "sha1":                "SHA-1 weak hash",
    "ssl":                 "SSL vulnerability",
    "tls":                 "TLS vulnerability",
    "certificate":         "certificate validation",
    "mitm":                "man-in-the-middle",
    "man in the middle":   "man-in-the-middle",

    # Software specific
    "apache":              "Apache",
    "nginx":               "nginx",
    "iis":                 "IIS",
    "tomcat":              "Apache Tomcat",
    "log4j":               "Log4j",
    "log4shell":           "Log4Shell Log4j",
    "spring":              "Spring Framework",
    "springshell":         "Spring4Shell",
    "wordpress":           "WordPress",
    "drupal":              "Drupal",
    "joomla":              "Joomla",
    "struts":              "Apache Struts",
    "openssl":             "OpenSSL",
    "php":                 "PHP",
    "python":              "Python",
    "java":                "Java",
    "node":                "Node.js",
    "windows":             "Windows",
    "linux":               "Linux kernel",
    "samba":               "Samba",
    "ssh":                 "OpenSSH",
    "ftp":                 "FTP",
    "smb":                 "SMB",
    "rdp":                 "Remote Desktop",
    "vpn":                 "VPN",
    "citrix":              "Citrix",
    "exchange":            "Microsoft Exchange",
    "sharepoint":          "Microsoft SharePoint",
    "jenkins":             "Jenkins",
    "gitlab":              "GitLab",
    "github":              "GitHub",
    "docker":              "Docker",
    "kubernetes":          "Kubernetes",
    "k8s":                 "Kubernetes",
}

SEVERITY_COLORS = {
    "CRITICAL": f"{RED}{BOLD}",
    "HIGH":     f"{YELLOW}{BOLD}",
    "MEDIUM":   f"{CYAN}",
    "LOW":      f"{GREEN}",
    "NONE":     f"{DIM}",
}

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

def print_banner():
    print(f"{RED}{BANNER}{RESET}")
    print(f"{CYAN}{BOLD}               Smart CVE Lookup — by SNXXIII{RESET}")
    print(f"{DIM}  {'─'*70}{RESET}")
    print(f"{YELLOW}  ⚠  For authorized security research and pentesting only{RESET}")
    print(f"{DIM}  {'─'*70}{RESET}\n")

def expand_keywords(user_input):
    """Map vague pentester terms to proper CVE search terms."""
    lowered = user_input.lower()
    matched = []
    for slang, proper in KEYWORD_MAP.items():
        if slang in lowered and proper not in matched:
            matched.append(proper)
    # Fallback to raw meaningful words
    if not matched:
        words = [w for w in lowered.split() if len(w) > 3]
        matched = [' '.join(words)] if words else [user_input]
    return matched

def fetch_raw(url):
    """Fetch JSON from NVD API."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CVEHunter/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        print(f"{RED}[!] Network error: {e}{RESET}")
        return None
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
        return None

def parse_cve_item(item):
    """Extract all fields from a CVE item."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "N/A")

    # Description
    descs = cve.get("descriptions", [])
    description = next((d["value"] for d in descs if d["lang"] == "en"), "No description available")

    # Published / Modified
    published = cve.get("published", "N/A")[:10]
    modified  = cve.get("lastModified", "N/A")[:10]

    # Status
    vuln_status = cve.get("vulnStatus", "N/A")

    # CVSS scores — collect all versions
    metrics = cve.get("metrics", {})
    cvss_info = {}
    for version_key, label in [("cvssMetricV31", "v3.1"), ("cvssMetricV30", "v3.0"), ("cvssMetricV2", "v2.0")]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            m = metric_list[0]
            cvss_data = m.get("cvssData", {})
            cvss_info[label] = {
                "score":               cvss_data.get("baseScore", "N/A"),
                "severity":            m.get("baseSeverity", cvss_data.get("baseSeverity", "N/A")).upper(),
                "vector":              cvss_data.get("vectorString", "N/A"),
                "exploitability":      m.get("exploitabilityScore", "N/A"),
                "impact":              m.get("impactScore", "N/A"),
                "attackVector":        cvss_data.get("attackVector", cvss_data.get("accessVector", "N/A")),
                "attackComplexity":    cvss_data.get("attackComplexity", cvss_data.get("accessComplexity", "N/A")),
                "privilegesRequired":  cvss_data.get("privilegesRequired", cvss_data.get("authentication", "N/A")),
                "userInteraction":     cvss_data.get("userInteraction", "N/A"),
                "scope":               cvss_data.get("scope", "N/A"),
                "confidentiality":     cvss_data.get("confidentialityImpact", "N/A"),
                "integrity":           cvss_data.get("integrityImpact", "N/A"),
                "availability":        cvss_data.get("availabilityImpact", "N/A"),
            }

    # CWE
    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value", "").startswith("CWE"):
                cwes.append(d["value"])

    # Affected configurations / CPE
    configs = cve.get("configurations", [])
    affected = []
    for config in configs:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    cpe = cpe_match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor  = parts[3]
                        product = parts[4]
                        version = parts[5] if len(parts) > 5 else "*"
                        entry = f"{vendor}/{product} {version}".replace("*", "any")
                        if entry not in affected:
                            affected.append(entry)

    # References
    refs = cve.get("references", [])
    references = [{"url": r.get("url", ""), "tags": r.get("tags", [])} for r in refs[:8]]

    # Top severity
    top_score    = "N/A"
    top_severity = "NONE"
    for label in ("v3.1", "v3.0", "v2.0"):
        if label in cvss_info:
            top_score    = cvss_info[label]["score"]
            top_severity = cvss_info[label]["severity"]
            break

    return {
        "id":           cve_id,
        "description":  description,
        "published":    published,
        "modified":     modified,
        "status":       vuln_status,
        "cvss":         cvss_info,
        "top_score":    top_score,
        "top_severity": top_severity,
        "cwes":         cwes,
        "affected":     affected,
        "references":   references,
    }

def fetch_by_id(cve_id):
    """Fetch full details for a specific CVE ID."""
    url = f"{NVD_API}?cveId={cve_id.upper()}"
    data = fetch_raw(url)
    if not data:
        return None
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print(f"{RED}[!] CVE not found: {cve_id}{RESET}")
        return None
    return parse_cve_item(vulns[0])

def fetch_by_keyword(keyword, limit=5, severity=None, year=None):
    """Search CVEs by keyword."""
    params = {
        "keywordSearch":  keyword,
        "resultsPerPage": min(limit, 20),
        "startIndex":     0,
    }
    if year:
        params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
        params["pubEndDate"]   = f"{year}-12-31T23:59:59.999"

    url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
    data = fetch_raw(url)
    if not data:
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        c = parse_cve_item(item)
        if severity and c["top_severity"] != severity.upper():
            continue
        results.append(c)
    return results

def print_full_detail(c):
    """Print complete CVE details."""
    sev_color = SEVERITY_COLORS.get(c["top_severity"], "")

    print(f"\n  {BOLD}{'═'*68}{RESET}")
    print(f"  {CYAN}{BOLD}  {c['id']}{RESET}  "
          f"{sev_color}[{c['top_severity']} — {c['top_score']}]{RESET}  "
          f"{DIM}Status: {c['status']}{RESET}")
    print(f"  {BOLD}{'═'*68}{RESET}\n")

    # Description
    print(f"  {YELLOW}{BOLD}Description:{RESET}")
    desc = c["description"]
    # Word-wrap at 90 chars
    words = desc.split()
    line, lines = [], []
    for w in words:
        if sum(len(x)+1 for x in line) + len(w) > 90:
            lines.append(' '.join(line))
            line = [w]
        else:
            line.append(w)
    if line:
        lines.append(' '.join(line))
    for l in lines:
        print(f"    {l}")

    # Dates
    print(f"\n  {YELLOW}{BOLD}Timeline:{RESET}")
    print(f"    {DIM}Published : {RESET}{c['published']}")
    print(f"    {DIM}Modified  : {RESET}{c['modified']}")

    # CWE
    if c["cwes"]:
        print(f"\n  {YELLOW}{BOLD}Weakness (CWE):{RESET}")
        for cwe in c["cwes"]:
            print(f"    {MAGENTA}{cwe}{RESET}")

    # CVSS Scores
    if c["cvss"]:
        print(f"\n  {YELLOW}{BOLD}CVSS Scores:{RESET}")
        for ver, info in c["cvss"].items():
            sev_c = SEVERITY_COLORS.get(info["severity"], "")
            print(f"\n    {BOLD}[{ver}]{RESET}  "
                  f"{sev_c}{info['severity']} {info['score']}{RESET}  "
                  f"{DIM}Vector: {info['vector']}{RESET}")
            print(f"    {DIM}  Exploitability: {info['exploitability']}  |  Impact: {info['impact']}{RESET}")
            print(f"    {DIM}  Attack Vector: {info['attackVector']}  |  Complexity: {info['attackComplexity']}{RESET}")
            print(f"    {DIM}  Privileges Required: {info['privilegesRequired']}  |  User Interaction: {info['userInteraction']}{RESET}")
            print(f"    {DIM}  Confidentiality: {info['confidentiality']}  |  Integrity: {info['integrity']}  |  Availability: {info['availability']}{RESET}")

    # Affected Products
    if c["affected"]:
        print(f"\n  {YELLOW}{BOLD}Affected Products:{RESET}")
        for prod in c["affected"][:10]:
            print(f"    {RED}• {prod}{RESET}")
        if len(c["affected"]) > 10:
            print(f"    {DIM}  ... and {len(c['affected']) - 10} more{RESET}")

    # References
    if c["references"]:
        print(f"\n  {YELLOW}{BOLD}References:{RESET}")
        for ref in c["references"]:
            tags = f"  {DIM}[{', '.join(ref['tags'])}]{RESET}" if ref["tags"] else ""
            print(f"    {CYAN}→ {ref['url']}{RESET}{tags}")

    print(f"\n  {BOLD}{'─'*68}{RESET}\n")

def print_summary(c):
    """Print a single-line summary for keyword search results."""
    sev_color = SEVERITY_COLORS.get(c["top_severity"], "")
    desc = c["description"]
    if len(desc) > 110:
        desc = desc[:107] + "..."
    print(f"  {BOLD}{CYAN}{c['id']}{RESET}  "
          f"{sev_color}[{c['top_severity']} {c['top_score']}]{RESET}  "
          f"{DIM}{c['published']}{RESET}")
    print(f"    {DIM}{desc}{RESET}\n")

def save_results(cves, query, filepath):
    with open(filepath, 'a') as f:
        f.write(f"\nCVEHunter Results\n")
        f.write(f"Query     : {query}\n")
        f.write(f"Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n")
        for c in cves:
            f.write(f"{c['id']}  [{c['top_severity']} {c['top_score']}]  {c['published']}\n")
            f.write(f"  {c['description']}\n")
            if c["cwes"]:
                f.write(f"  CWE: {', '.join(c['cwes'])}\n")
            if c["references"]:
                f.write(f"  References:\n")
                for ref in c["references"]:
                    f.write(f"    {ref['url']}\n")
            f.write("\n")

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="CVEHunter - Smart CVE lookup from descriptions or CVE IDs",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("query",    nargs="?",
                        help="CVE ID (e.g. CVE-2021-44228) or describe the issue")
    parser.add_argument("--limit",    type=int, default=5,
                        help="Results per keyword search (default: 5)")
    parser.add_argument("--severity", choices=["LOW","MEDIUM","HIGH","CRITICAL"],
                        help="Filter by severity")
    parser.add_argument("--year",     type=int,
                        help="Filter by published year e.g. 2023")
    parser.add_argument("--output",   help="Save results to file")
    parser.add_argument("--expand",   action="store_true",
                        help="Show expanded keywords from your input")

    if len(sys.argv) == 1:
        print(f"{CYAN}  Provide a CVE ID for full details, or describe the issue{RESET}")
        print(f"{CYAN}  in plain language to search matching CVEs.\n{RESET}")
        print(f"{YELLOW}  Usage:{RESET}")
        print(f"    python3 CVEHunter.py \"<CVE-ID or description>\" [options]\n")
        print(f"{YELLOW}  Examples:{RESET}")
        print(f"    python3 CVEHunter.py CVE-2021-44228")
        print(f"    python3 CVEHunter.py \"login page breaks when i add quotes\"")
        print(f"    python3 CVEHunter.py \"old apache crashing\" --severity HIGH")
        print(f"    python3 CVEHunter.py \"rce via log4j\" --year 2021 --limit 10")
        print(f"    python3 CVEHunter.py \"buffer overflow in ssh\" --output results.txt")
        sys.exit(0)

    args = parser.parse_args()

    if not args.query:
        print(f"{RED}[!] No query provided. Run without arguments to see usage.{RESET}")
        sys.exit(1)

    # Check if input is a CVE ID
    cve_match = CVE_PATTERN.search(args.query)

    if cve_match:
        # --- Full detail mode ---
        cve_id = cve_match.group(0).upper()
        print(f"  {CYAN}[*] Fetching full details for: {BOLD}{cve_id}{RESET}\n")
        detail = fetch_by_id(cve_id)
        if detail:
            print_full_detail(detail)
            if args.output:
                save_results([detail], cve_id, args.output)
                print(f"{GREEN}  [+] Saved to: {args.output}{RESET}")
    else:
        # --- Keyword search mode ---
        keywords = expand_keywords(args.query)

        if args.expand:
            print(f"  {DIM}[*] Expanded keywords: {', '.join(keywords)}{RESET}\n")

        print(f"  {CYAN}[*] Searching for: {BOLD}{args.query}{RESET}")
        print(f"  {DIM}{'─'*68}{RESET}\n")

        for kw in keywords:
            cves = fetch_by_keyword(kw, limit=args.limit,
                                    severity=args.severity, year=args.year)
            if not cves:
                print(f"  {YELLOW}[~] No results for: {kw}{RESET}\n")
                continue

            print(f"  {GREEN}[+] Keyword: {BOLD}{kw}{RESET}  {DIM}({len(cves)} found){RESET}\n")
            for c in cves:
                print_summary(c)

            if args.output:
                save_results(cves, kw, args.output)

        if args.output:
            print(f"\n  {GREEN}[+] All results saved to: {args.output}{RESET}")

if __name__ == "__main__":
    main()
