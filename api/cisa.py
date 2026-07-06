import requests
import pandas as pd


def get_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    response = requests.get(url, timeout=20)

    if response.status_code != 200:
        raise Exception(f"CISA API error: {response.status_code}")

    data = response.json()

    kev_list = []

    for item in data["vulnerabilities"][:20]:
        kev_list.append({
            "CVE ID": item.get("cveID", "N/A"),
            "Vendor": item.get("vendorProject", "N/A"),
            "Product": item.get("product", "N/A"),
            "Vulnerability": item.get("vulnerabilityName", "N/A"),
            "Date Added": item.get("dateAdded", "N/A"),
            "Due Date": item.get("dueDate", "N/A")
        })

    return pd.DataFrame(kev_list)