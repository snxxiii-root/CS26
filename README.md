# CS26 — Offensive & Defensive Security Toolkit

> **By SNXXIII** | For ethical hackers, pentesters, and cyber enthusiasts

---

## What is CS26?

CS26 is an open collection of security tools built for **cyber enthusiasts who want to understand both sides of the attack surface** — how systems are broken, and how they are defended.

Every tool in this repository is designed with a dual purpose:
- **Offensive** — understand how real-world attacks are executed
- **Defensive** — learn how to detect, prevent, and respond to those attacks

The goal is not just to run exploits — it's to **build the mindset of both an attacker and a defender**, which is what separates a good security professional from a great one.

---

## Who Is This For?

- Penetration testers conducting authorized assessments
- CTF players sharpening their skills
- Security students learning offensive and defensive techniques
- Blue teamers who want to understand attacker TTPs
- Red teamers building their toolkit
- Anyone preparing for certifications like OSCP, CEH, eJPT, PNPT

---

## Tools

### ZeroRecon — Network Scanner
> `ZeroRecon/ZeroRecon.py`

A feature-rich Nmap wrapper for fast, flexible network reconnaissance.

| Mode | What it does |
|------|-------------|
| `quick` | Top 100 ports — fast initial recon |
| `full` | All 65535 ports |
| `stealth` | SYN scan — low noise |
| `aggressive` | Full scan — OS, version, scripts |
| `vuln` | Nmap vulnerability scripts |
| `ping` | Host discovery across a range |
| `custom` | Your own Nmap flags |

```bash
python3 ZeroRecon.py 192.168.1.1 --mode aggressive
python3 ZeroRecon.py 192.168.1.0/24 --mode ping
python3 ZeroRecon.py 192.168.1.1 --mode vuln --output results.txt
```

---

### Vuln — Smart CVE Lookup
> `Vuln/Vuln.py`

Finds CVEs from vague pentester descriptions or pulls full detail from a CVE ID. Powered by the NVD (National Vulnerability Database) API.

- Describe an issue in plain language → get matching CVEs
- Provide a CVE ID → get full breakdown (CVSS, affected products, references, CWE)
- Smart keyword expansion maps pentester slang to proper CVE search terms

```bash
python3 Vuln.py CVE-2021-44228
python3 Vuln.py "login page breaks with quotes"
python3 Vuln.py "apache crashing" --severity HIGH --year 2023
```

---

### Project 101 — Attack & Defense Guide
> `Project 101/Project101.py`

A comprehensive step-by-step guide that covers how attacks are executed and how to defend against them — all in one place.

**39 techniques across 9 categories:**

| Category | Techniques |
|----------|-----------|
| Web | SQLi, XSS, CSRF, SSRF, LFI, SSTI, XXE, IDOR, File Upload, Broken Auth, GraphQL Injection, OAuth Misconfiguration, CORS Misconfiguration, HTTP Request Smuggling, Insecure Deserialization |
| Network | MITM, Port Scanning, DNS Poisoning, Packet Sniffing |
| System | Linux PrivEsc, Windows PrivEsc, Buffer Overflow, Pass-the-Hash, LOLBins, Container Escape |
| Active Directory | Kerberoasting, AS-REP Roasting, DCSync, Golden Ticket, BloodHound Enumeration |
| Cloud | AWS S3 Misconfiguration, AWS IAM PrivEsc, Kubernetes Attack, Cloud Metadata SSRF |
| Modern Exploits | Log4Shell, PrintNightmare, Follina, ProxyShell/ProxyLogon |
| Wireless | WPA2 Cracking, Evil Twin |
| Social Engineering | Phishing, Password Spraying |
| Cryptography | Hash Cracking |

```bash
python3 Project101.py "sql injection"
python3 Project101.py "break wifi" --attack
python3 Project101.py "kerberoasting" --defense
python3 Project101.py --list
python3 Project101.py --list --category Cloud
```

---

## Project Structure

```
CS26/
├── ZeroRecon/
│   └── ZeroRecon.py        # Network scanner
├── Vuln/
│   └── Vuln.py             # CVE lookup tool
├── Project 101/
│   └── Project101.py       # Attack & defense guide
└── README.md
```

---

## Legal & Ethical Use

> ⚠️ **Important**

All tools in this repository are intended **strictly for authorized security testing, education, and research.**

- Only use these tools on systems you **own** or have **explicit written permission** to test
- Unauthorized scanning, exploitation, or interception is **illegal** in most jurisdictions
- The author is **not responsible** for any misuse or damage caused by these tools
- Always follow your organization's security policies and local laws

This repository exists to **educate and empower ethical security professionals** — not to enable malicious activity.

---

## Requirements

- Python 3.8+
- Nmap installed (for ZeroRecon)
- Internet access (for Vuln — queries NVD API)

```bash
pip install -r requirements.txt   # No external deps required currently
```

---

## Author

**SNXXIII**
> *"Know the attack. Build the defense."*

---

## Roadmap

- More tools being added continuously
- Upcoming: exploit automation, reporting module, integration between tools
- Suggestions welcome — open an issue

---

*CS26 — Built for those who hack to protect.*
