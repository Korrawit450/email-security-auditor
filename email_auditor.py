import sys
import dns.resolver
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)

COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "mandrill"]

def clean_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc
    return domain.split(":")[0]

def query_txt_records(target: str) -> list:
    try:
        answers = dns.resolver.resolve(target, "TXT", lifetime=6.0)
        records = []
        for rdata in answers:
            txt_string = "".join([s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else s for s in rdata.strings])
            records.append(txt_string)
        return records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []

def check_spf(domain: str):
    print(f"{Fore.CYAN}[*] Auditing SPF (Sender Policy Framework)...{Style.RESET_ALL}")
    records = query_txt_records(domain)
    spf_records = [r for r in records if r.lower().startswith("v=spf1")]

    if not spf_records:
        print(f"  {Fore.RED}[!] MISSING:{Style.RESET_ALL} No SPF record found. Domain is vulnerable to spoofing.")
        return

    for spf in spf_records:
        print(f"  {Fore.GREEN}[+] Found:{Style.RESET_ALL} {spf}")
        if "-all" in spf:
            print(f"  {Fore.GREEN}[+] Policy:{Style.RESET_ALL} StrictHardFail (-all) configured properly.")
        elif "~all" in spf:
            print(f"  {Fore.YELLOW}[~] Policy:{Style.RESET_ALL} SoftFail (~all) enabled. Ensure DMARC is enforcing.")
        elif "?all" in spf or "+all" in spf:
            print(f"  {Fore.RED}[!] Weak Policy:{Style.RESET_ALL} Permissive SPF mechanism (?all or +all) allows unauthorized senders!")

def check_dmarc(domain: str):
    print(f"\n{Fore.CYAN}[*] Auditing DMARC (_dmarc.{domain})...{Style.RESET_ALL}")
    dmarc_target = f"_dmarc.{domain}"
    records = query_txt_records(dmarc_target)
    dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        print(f"  {Fore.RED}[!] MISSING:{Style.RESET_ALL} No DMARC record found at {dmarc_target}.")
        return

    for dmarc in dmarc_records:
        print(f"  {Fore.GREEN}[+] Found:{Style.RESET_ALL} {dmarc}")
        lower_dmarc = dmarc.lower()
        if "p=reject" in lower_dmarc:
            print(f"  {Fore.GREEN}[+] Enforcement:{Style.RESET_ALL} Strongest policy ('p=reject') active.")
        elif "p=quarantine" in lower_dmarc:
            print(f"  {Fore.YELLOW}[~] Enforcement:{Style.RESET_ALL} Moderate policy ('p=quarantine') sends spoofed emails to spam.")
        elif "p=none" in lower_dmarc:
            print(f"  {Fore.RED}[!] Weak Enforcement:{Style.RESET_ALL} Monitoring-only policy ('p=none') does not block spoofed emails.")

def check_dkim(domain: str):
    print(f"\n{Fore.CYAN}[*] Probing Common DKIM Selectors...{Style.RESET_ALL}")
    found_selectors = []

    for selector in COMMON_DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        records = query_txt_records(dkim_domain)
        for rec in records:
            if "v=dkim1" in rec.lower() or "k=rsa" in rec.lower() or "p=" in rec.lower():
                found_selectors.append((selector, dkim_domain))
                print(f"  {Fore.GREEN}[+] Active Selector:{Style.RESET_ALL} '{selector}' ({dkim_domain})")

    if not found_selectors:
        print(f"  {Fore.YELLOW}[~] Info:{Style.RESET_ALL} No common DKIM selectors detected (custom selector may be in use).")

def main():
    if len(sys.argv) < 2:
        print("Usage: python email_auditor.py <target-domain>")
        sys.exit(1)

    target_domain = clean_domain(sys.argv[1])
    print(f"\n{Fore.MAGENTA}=== Email Security & Anti-Spoofing Audit: {target_domain} ==={Style.RESET_ALL}\n")

    check_spf(target_domain)
    check_dmarc(target_domain)
    check_dkim(target_domain)

    print(f"\n{Fore.MAGENTA}=== Audit Completed ==={Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()