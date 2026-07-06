import requests
import pandas as pd


def get_latest_cves():
    url = url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10"

    params = {
        "resultsPerPage": 10,
        "keywordSearch": "Microsoft"
    }

    response = requests.get(url, timeout=20)

    print(response.status_code)
    print(response.text[:200])

    if response.status_code != 200:
        raise Exception(f"NVD API error: {response.status_code} - {response.text[:100]}")

    data = response.json()
    cve_list = []

    for item in data["vulnerabilities"]:
        cve = item["cve"]

        cve_id = cve["id"]
        published = cve["published"]
        description = cve["descriptions"][0]["value"]
        
        metrics = cve.get("metrics", {})

        severity = "Unknown"
        score = "N/A"

        if "cvssMetricV40" in metrics:
            cvss_data = metrics["cvssMetricV40"][0]["cvssData"]
            severity = cvss_data.get("baseSeverity", "Unknown")
            score = cvss_data.get("baseScore", "N/A")

        elif "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss_data.get("baseSeverity", "Unknown")
            score = cvss_data.get("baseScore", "N/A")

        elif "cvssMetricV30" in metrics:
             cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
             severity = cvss_data.get("baseSeverity", "Unknown")
             score = cvss_data.get("baseScore", "N/A")

        elif "cvssMetricV2" in metrics:
             cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
             severity = metrics["cvssMetricV2"][0].get("baseSeverity", "Unknown")
             score = cvss_data.get("baseScore", "N/A")

        
        cve_list.append({
            "CVE ID": cve_id,
            "Severity": severity,
            "CVSS Score": score,
            "Published Date": published,
            "Description": description
        })

    return pd.DataFrame(cve_list)