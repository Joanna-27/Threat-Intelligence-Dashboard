# 🛡️ Threat Intelligence Dashboard

This project is a simple threat intelligence dashboard developed using Python and Streamlit. It brings together information from different cybersecurity APIs to help users monitor vulnerabilities and perform basic IOC (Indicator of Compromise) analysis.

The dashboard allows users to view the latest CVEs, explore CISA Known Exploited Vulnerabilities, filter vulnerabilities by vendor, and check the reputation of IP addresses using AbuseIPDB.

## Features

- View the latest CVEs from the NVD API.
- Display CISA Known Exploited Vulnerabilities (KEV).
- Filter vulnerabilities by vendor.
- Search vulnerabilities using CVE IDs.
- View dashboard metrics and charts.
- Perform IP reputation lookups using AbuseIPDB.
- Identify IOC types such as IP addresses, domains, URLs, and hashes.
- Display abuse score, reports, ISP, country, and risk assessment for IP addresses.

## Technologies Used

- Python
- Streamlit
- Pandas
- Plotly
- Requests
- python-dotenv

## APIs Used

- NVD (National Vulnerability Database)
- CISA Known Exploited Vulnerabilities Catalog
- AbuseIPDB

## What I Learned

Through this project, I gained practical experience with:

- Working with REST APIs and handling JSON responses.
- Building interactive dashboards using Streamlit.
- Organizing Python projects into reusable modules.
- Performing basic threat intelligence and IOC analysis.
- Visualizing cybersecurity data using Plotly.
- Managing API keys securely using environment variables.

## Screenshots

Screenshots of the dashboard are available in the `screenshots` folder.

## Future Improvements

- Add VirusTotal integration.
- Support domain and URL reputation lookup.
- Export results to CSV or PDF.
- Improve dashboard visualizations.
- Add more threat intelligence sources.

## About This Project

This project was developed as part of my cybersecurity learning journey to gain practical experience with REST APIs, threat intelligence, and Streamlit dashboard development. It helped me understand how vulnerability data and IOC reputation services can be combined into a single dashboard for basic security analysis.
