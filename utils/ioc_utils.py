import ipaddress
import re


def classify_ioc(ioc):
    ioc = ioc.strip()

    try:
        ipaddress.ip_address(ioc)
        return "IP Address"
    except ValueError:
        pass

    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "URL"

    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if re.match(domain_pattern, ioc):
        return "Domain"

    hash_pattern = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
    if re.match(hash_pattern, ioc):
        return "File Hash"

    return "Unknown"