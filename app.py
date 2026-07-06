import streamlit as st
from api.nvd import get_latest_cves
from api.cisa import get_cisa_kev
import plotly.express as px
from utils.ioc_utils import classify_ioc
from api.abuseipdb import check_ip

st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide"
)
st.title("🛡️ Threat Intelligence Dashboard")
st.write("A simple cybersecurity dashboard for CVEs, exploited vunerabilites, and IOC analysis.")
st.sidebar.title("Navigation")

page = st.sidebar.radio(
    " Go to",
    ["Dashboard", "Latest CVEs", "CISA KEV", "IOC Lookup"]
)
if page == "Dashboard":
    st.header("Dashboard")
    st.success("Dashboard loaded successfully.")

elif page == "Latest CVEs":
    st.header("Latest CVes")
    st.write("This section fetches recent vulnerability data from the NVD API. ")
    
    if st.button("Fetch Latest CVEs"):
     df = get_latest_cves()
     st.dataframe(df, use_container_width=True)

elif page == "IOC Lookup":
    st.header("IOC Lookup")
    st.write("Analyze indicators of compromise such as IP addresses, domains, URLs, and hashes.")

    ioc = st.text_input(
        "Enter IOC",
        placeholder="Example: 8.8.8.8 or example.com"
    )

    if st.button("Analyze IOC"):
        if ioc:
            ioc_type = classify_ioc(ioc)

            st.success("IOC submitted for analysis.")

            col1, col2 = st.columns(2)

            with col1:
                st.metric("Indicator", ioc)

            with col2:
                st.metric("IOC Type", ioc_type)

            if ioc_type == "Unknown":
                st.warning("This input does not match a common IOC format.")

            elif ioc_type == "IP Address":

                st.info("Querying AbuseIPDB...")

                result = check_ip(ioc)
                data = result["data"]

                abuse_score = data.get("abuseConfidenceScore", 0)

                if abuse_score <= 10:
                    risk_status = "Safe"
                elif abuse_score <= 50:
                    risk_status = "Suspicious"
                else:
                    risk_status = "Malicious"

                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric(
                        "Abuse Score",
                        abuse_score
                    )

                with col2:
                    st.metric(
                        "Country",
                        data.get("countryCode", "N/A")
                    )

                with col3:
                    st.metric(
                        "Reports",
                        data.get("totalReports", "N/A")
                    )

                st.subheader("Risk Assessment")
                st.metric("Risk Status", risk_status)
                st.progress(abuse_score / 100)
                st.caption(f"Abuse Confidence Score: {abuse_score}/100")

                st.write("**ISP:**", data.get("isp", "N/A"))
                st.write("**Usage Type:**", data.get("usageType", "N/A"))
                st.write("**Domain:**", data.get("domain", "N/A"))
                st.write("**Last Reported:**", data.get("lastReportedAt", "N/A"))
            else:
                st.info("VirusTotal integration will be added later.")

        else:
            st.warning("Please enter an IOC first.")

elif page == "CISA KEV":


    st.header("CISA Known Exploited Vulnerabilities")
    st.write("This section displays vulnerabilities that are actively exploited according to CISA.")

    if st.button("Fetch CISA KEV"):
        df = get_cisa_kev()

        vendors = ["All"] + sorted(df["Vendor"].unique().tolist())

        selected_vendor = st.selectbox(
            "Filter by Vendor",
            vendors
        )
        search_cve = st.text_input(
            "Search by CVE ID"
        )

        filtered_df = df

        if selected_vendor != "All":
            filtered_df = filtered_df[
                filtered_df["Vendor"] == selected_vendor
            ]

        if search_cve:
           filtered_df = filtered_df[
        filtered_df["CVE ID"].str.contains(
            search_cve,
            case=False,
            na=False
        )
    ]
           vendor_counts = (
               filtered_df["Vendor"]
               .value_counts()
               .head(10)
               .reset_index()
           )
           vendor_counts.columns = ["Vendor", "Count"]

        

        col1, col2 = st.columns(2)

        with col1:
            st.metric("Vulnerabilities Displayed", len(filtered_df))

        with col2:
            st.metric("Unique Vendors", filtered_df["Vendor"].nunique())

            vendor_counts = (
               filtered_df["Vendor"]
               .value_counts()
               .head(10)
               .reset_index()
           )
            vendor_counts.columns = ["Vendor", "Count"]


            fig = px.bar(
               vendor_counts,
               x="Vendor",
               y="Count",
               title="Top 10 Affected Vendors"
           )
            
            st.plotly_chart(fig, use_container_width=True)

        st.dataframe(filtered_df, use_container_width=True)