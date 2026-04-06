#!/usr/bin/env python3


import subprocess
import sys
import argparse
from datetime import datetime

# Colors
GREEN  = '\033[92m'
CYAN   = '\033[96m'
RED    = '\033[91m'
YELLOW = '\033[93m'
RESET  = '\033[0m'
BOLD   = '\033[1m'
DIM    = '\033[2m'

BANNER = r"""
███████╗███████╗██████╗  ██████╗ ██████╗ ███████╗ ██████╗  ██████╗ ███╗   ██╗
   ███╔╝██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔════╝ ██╔═══██╗████╗  ██║
  ███╔╝ █████╗  ██████╔╝██║   ██║██████╔╝█████╗  ██║      ██║   ██║██╔██╗ ██║
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██╔══██╗██╔══╝  ██║      ██║   ██║██║╚██╗██║
███╔╝   ███████╗██║  ██║╚██████╔╝██║  ██║███████╗╚██████╗ ╚██████╔╝██║ ╚████║
╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═══╝
"""

def print_banner():
    print(f"{GREEN}{BANNER}{RESET}")
    print(f"{CYAN}{BOLD}                    by SNXXIII{RESET}")
    print(f"{DIM}  ----------------------------------------{RESET}")
    print(f"{YELLOW}  ⚠  Only scan systems you own or have permission to test{RESET}")
    print(f"{DIM}  ----------------------------------------{RESET}\n")

def run_scan(command, target, output_file=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{CYAN}[*] Target   : {BOLD}{target}{RESET}")
    print(f"{CYAN}[*] Command  : {BOLD}{' '.join(command)}{RESET}")
    print(f"{CYAN}[*] Started  : {timestamp}{RESET}")
    print(f"{DIM}{'─'*50}{RESET}\n")

    try:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
            # Write summary header + stdout only when -oN was NOT used
            # (when -oN is used, nmap already wrote the file directly)
            if output_file and f'-oN' not in command:
                with open(output_file, 'w') as f:
                    f.write(f"ZeroRecon Scan Report\n")
                    f.write(f"Target  : {target}\n")
                    f.write(f"Time    : {timestamp}\n")
                    f.write(f"Command : {' '.join(command)}\n")
                    f.write("=" * 50 + "\n")
                    f.write(result.stdout)
            if output_file:
                print(f"\n{GREEN}[+] Results saved to: {output_file}{RESET}")
        else:
            print(f"{RED}[!] Error: {result.stderr}{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Nmap not found. Install it: https://nmap.org/download.html{RESET}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")

def build_command(args):
    mode_flags = {
        'quick':      ['-F'],
        'full':       ['-p-'],
        'stealth':    ['-sS'],
        'udp':        ['-sU'],
        'version':    ['-sV'],
        'os':         ['-O', '--osscan-guess'],
        'aggressive': ['-A', '-sV', '-sC', '-O', '--osscan-guess'],
        'vuln':       ['--script=vuln'],
        'ping':       ['-sn'],
        'custom':     [],
    }

    cmd = ['nmap'] + mode_flags.get(args.mode, [])

    if args.flags:
        cmd += args.flags.split()

    cmd += [f'-{args.speed}']

    if args.ports and args.mode not in ('full', 'ping'):
        cmd += ['-p', args.ports]

    if args.verbose:
        cmd += ['-v']

    if args.no_ping:
        cmd += ['-Pn']

    if args.output:
        cmd += ['-oN', args.output]

    cmd.append(args.target)
    return cmd

def print_usage():
    modes = [
        ('quick',      'Fast scan of top 100 ports (default)'),
        ('full',       'All 65535 ports'),
        ('stealth',    'SYN stealth scan (-sS)'),
        ('udp',        'UDP scan (-sU)'),
        ('version',    'Service version detection (-sV)'),
        ('os',         'OS fingerprinting (-O)'),
        ('aggressive', 'Full aggressive scan (-A -sV -sC -O)'),
        ('vuln',       'Run vulnerability scripts'),
        ('ping',       'Ping sweep to find live hosts'),
        ('custom',     'Use your own --flags'),
    ]
    print(f"{CYAN}Scan Modes:{RESET}")
    for name, desc in modes:
        print(f"  {GREEN}{name:<12}{RESET} {DIM}{desc}{RESET}")
    print(f"\n{YELLOW}Usage:{RESET}")
    print(f"  python3 ZeroRecon.py <target> --mode <mode> [options]")
    print(f"\n{YELLOW}Examples:{RESET}")
    print(f"  python3 ZeroRecon.py 192.168.1.1 --mode quick")
    print(f"  python3 ZeroRecon.py 192.168.1.1 --mode aggressive --output scan.txt")
    print(f"  python3 ZeroRecon.py 192.168.1.1 --mode version --ports 1-1000")
    print(f"  python3 ZeroRecon.py 192.168.1.0/24 --mode ping")
    print(f"  python3 ZeroRecon.py 192.168.1.1 --mode custom --flags \"-sS -sV -p 22,80,443\"")

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='ZeroRecon - Network Recon Scanner',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True
    )
    parser.add_argument('target', nargs='?', help='Target IP, hostname, or CIDR range')
    parser.add_argument('--mode', choices=[
        'quick', 'full', 'stealth', 'udp', 'version',
        'os', 'aggressive', 'vuln', 'ping', 'custom'
    ], default='quick', help='Scan mode (default: quick)')
    parser.add_argument('--ports',   help='Ports e.g. 80,443 or 1-1000')
    parser.add_argument('--speed',   choices=['T1','T2','T3','T4','T5'], default='T4',
                        help='Scan speed T1=sneaky … T5=insane (default: T4)')
    parser.add_argument('--flags',   help='Extra nmap flags e.g. "--script=http-title"')
    parser.add_argument('--output',  help='Save results to file (nmap -oN format)')
    parser.add_argument('--verbose', action='store_true', help='Verbose nmap output (-v)')
    parser.add_argument('--no-ping', action='store_true', help='Skip host discovery (-Pn)')

    if len(sys.argv) == 1:
        print_usage()
        sys.exit(0)

    args = parser.parse_args()

    if not args.target:
        print(f"{RED}[!] No target specified. Run without arguments to see usage.{RESET}")
        sys.exit(1)

    cmd = build_command(args)
    run_scan(cmd, args.target, args.output)

if __name__ == '__main__':
    main()
