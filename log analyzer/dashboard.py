
from pathlib import Path
import json
import sys
import subprocess
import pandas as pd
import streamlit as st

# ==========================================
# 1. PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ==========================================
# 2. FILE LOCATIONS
# ==========================================

BASE_DIR = Path(__file__).resolve().parent

REPORT_FILE = BASE_DIR / "reports" / "analysis_report.json"
CSV_FILE = BASE_DIR / "reports" / "security_report.csv"

UPLOAD_DIR = BASE_DIR / "logs" / "uploads"

MAIN_FILE = BASE_DIR / "main.py"

# ==========================================
# 3. INITIALISE SESSION STATE
# ==========================================

if "analysis_output" not in st.session_state:
    st.session_state.analysis_output = ""

if "analysis_error" not in st.session_state:
    st.session_state.analysis_error = ""

if "analysis_success" not in st.session_state:
    st.session_state.analysis_success = False

# ==========================================
# 4. DASHBOARD HEADER
# ==========================================

st.title("🛡️ Log Analyzer – Security Dashboard")

st.caption(
    "Version 7 | Upload, Analyse and Investigate Logs"
)

st.divider()

# ==========================================
# 5. LOG FILE UPLOAD
# ==========================================

st.subheader("Upload Security Log")

uploaded_file = st.file_uploader(
    "Choose a log file",
    type=["log", "txt"],
    help="Upload a UTF-8 text log file. Maximum size: 5 MB."
)

if uploaded_file is not None:

    file_bytes = uploaded_file.getvalue()

    st.write(f"Selected file: {uploaded_file.name}")

    st.write(
        f"File size: {len(file_bytes) / 1024:.2f} KB"
    )

    analyse_button = st.button(
        "Analyse Uploaded Log",
        type="primary"
    )

    if analyse_button:

        if len(file_bytes) > 5 * 1024 * 1024:

            st.error("File exceeds the 5 MB upload limit.")

        elif not file_bytes:

            st.error("The uploaded file is empty.")

        else:

            try:

                file_bytes.decode("utf-8")

                if not MAIN_FILE.exists():

                    st.error("main.py was not found.")

                else:

                    UPLOAD_DIR.mkdir(
                        parents=True,
                        exist_ok=True
                    )

                    upload_path = UPLOAD_DIR / "dashboard_upload.log"

                    upload_path.write_bytes(file_bytes)

                    with st.spinner(
                        "Analysing uploaded log file..."
                    ):

                        result = subprocess.run(
                            [
                                sys.executable,
                                str(MAIN_FILE),
                                str(upload_path)
                            ],
                            cwd=BASE_DIR,
                            capture_output=True,
                            text=True,
                            timeout=30
                        )

                    st.session_state.analysis_output = result.stdout

                    st.session_state.analysis_error = result.stderr

                    st.session_state.analysis_success = (
                        result.returncode == 0
                    )

                    st.rerun()

            except UnicodeDecodeError:

                st.error(
                    "Invalid file encoding. Please upload a UTF-8 text file."
                )

            except subprocess.TimeoutExpired:

                st.error("Analysis took too long and was stopped.")

            except OSError as error:

                st.error(f"File processing error: {error}")

            except Exception as error:

                st.error(f"Unexpected error: {error}")

else:

    st.info(
        "Upload a .log or .txt file to begin security analysis."
    )

# ==========================================
# 6. ANALYSIS EXECUTION RESULT
# ==========================================

if st.session_state.analysis_output:

    with st.expander("View Analysis Engine Output"):

        st.code(
            st.session_state.analysis_output,
            language="text"
        )

if st.session_state.analysis_error:

    with st.expander("View Analysis Errors"):

        st.code(
            st.session_state.analysis_error,
            language="text"
        )

if st.session_state.analysis_success:

    st.success("Log analysis completed successfully!")

elif st.session_state.analysis_output:

    st.error("The analysis engine did not complete successfully.")

st.divider()

# ==========================================
# 7. LOAD GENERATED JSON REPORT
# ==========================================

st.subheader("Security Analysis Results")

if not REPORT_FILE.exists():

    st.warning(
        "No security report available. Upload a log and analyse it first."
    )

    st.stop()

try:

    with REPORT_FILE.open("r", encoding="utf-8") as file:

        report = json.load(file)

except (json.JSONDecodeError, OSError) as error:

    st.error(f"Could not load security report: {error}")

    st.stop()

# ==========================================
# 8. EXTRACT REPORT DATA
# ==========================================

summary = report.get("summary", {})

risk = report.get("risk_assessment", {})

failed_logins = report.get(
    "users_with_failed_logins", {}
)

failed_ips = report.get(
    "failed_logins_by_ip", {}
)

alerts = report.get(
    "detailed_alerts", []
)

recommendations = report.get(
    "recommendations", []
)

timeline = report.get(
    "login_timeline", []
)

ip_activity = report.get(
    "ip_activity", []
)

# ==========================================
# 9. SIDEBAR FILTERS
# ==========================================

st.sidebar.title("Dashboard Controls")

st.sidebar.caption(
    f"Generated: {report.get('generated_at', 'Unknown')}"
)

selected_severity = st.sidebar.selectbox(
    "Filter alert severity",
    ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
)

ip_search = st.sidebar.text_input(
    "Search IP address"
)

username_search = st.sidebar.text_input(
    "Search username"
)

if st.sidebar.button("Refresh Dashboard"):

    st.rerun()

# ==========================================
# 10. RISK ASSESSMENT
# ==========================================

st.subheader("Overall Security Risk")

overall_risk = risk.get(
    "overall_risk", "UNKNOWN"
)

if overall_risk == "CRITICAL":

    st.error("CRITICAL RISK DETECTED")

elif overall_risk == "HIGH":

    st.warning("HIGH RISK DETECTED")

elif overall_risk == "MEDIUM":

    st.info("MEDIUM RISK DETECTED")

else:

    st.success(f"{overall_risk} RISK")

# ==========================================
# 11. SECURITY STATISTICS
# ==========================================

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Log Entries",
    summary.get("total_log_entries", 0)
)

col2.metric(
    "Failed Logins",
    summary.get("failed_login_attempts", 0)
)

col3.metric(
    "Unique IP Addresses",
    len(failed_ips)
)

col4.metric(
    "Security Alerts",
    risk.get("total_alerts", 0)
)

st.divider()

# ==========================================
# 12. LOG LEVEL ANALYSIS
# ==========================================

st.subheader("Log Level Analysis")

log_data = pd.DataFrame({
    "Log Level": ["INFO", "WARNING", "ERROR"],
    "Count": [
        summary.get("info", 0),
        summary.get("warnings", 0),
        summary.get("errors", 0)
    ]
})

col1, col2 = st.columns(2)

with col1:

    st.dataframe(
        log_data,
        use_container_width=True,
        hide_index=True
    )

with col2:

    st.bar_chart(
        log_data.set_index("Log Level")
    )

st.divider()

# ==========================================
# 13. FAILED LOGIN ANALYSIS
# ==========================================

st.subheader("Failed Login Analysis")

col1, col2 = st.columns(2)

with col1:

    st.write("Failed Logins by Username")

    if failed_logins:

        user_data = pd.DataFrame(
            list(failed_logins.items()),
            columns=["Username", "Attempts"]
        )

        st.bar_chart(
            user_data.set_index("Username")
        )

    else:

        st.info("No failed logins found.")

with col2:

    st.write("Failed Logins by IP")

    if failed_ips:

        ip_chart_data = pd.DataFrame(
            list(failed_ips.items()),
            columns=["IP Address", "Attempts"]
        )

        st.bar_chart(
            ip_chart_data.set_index("IP Address")
        )

    else:

        st.info("No IP activity found.")

st.divider()

# ==========================================
# 14. FILTER SECURITY ALERTS
# ==========================================

st.subheader("Security Alerts")

alert_data = pd.DataFrame(alerts)

if not alert_data.empty:

    filtered_alerts = alert_data.copy()

    if selected_severity != "ALL":

        filtered_alerts = filtered_alerts[
            filtered_alerts["severity"] == selected_severity
        ]

    st.write(
        f"Matching alerts: {len(filtered_alerts)}"
    )

    st.dataframe(
        filtered_alerts,
        use_container_width=True,
        hide_index=True
    )

else:

    st.success("No security alerts detected.")

st.divider()

# ==========================================
# 15. IP ACTIVITY
# ==========================================

st.subheader("IP Activity Summary")

ip_data = pd.DataFrame(ip_activity)

if not ip_data.empty:

    if ip_search:

        ip_data = ip_data[
            ip_data["ip_address"].str.contains(
                ip_search,
                case=False,
                na=False
            )
        ]

    st.dataframe(
        ip_data,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No IP activity available.")

st.divider()

# ==========================================
# 16. LOGIN TIMELINE
# ==========================================

st.subheader("Login Activity Timeline")

timeline_data = pd.DataFrame(timeline)

if not timeline_data.empty:

    if ip_search:

        timeline_data = timeline_data[
            timeline_data["ip_address"].str.contains(
                ip_search,
                case=False,
                na=False
            )
        ]

    if username_search:

        timeline_data = timeline_data[
            timeline_data["username"].str.contains(
                username_search,
                case=False,
                na=False
            )
        ]

    st.write(
        f"Matching events: {len(timeline_data)}"
    )

    st.dataframe(
        timeline_data,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No login activity available.")

st.divider()

# ==========================================
# 17. SECURITY RECOMMENDATIONS
# ==========================================

st.subheader("Security Recommendations")

for number, recommendation in enumerate(
    recommendations, start=1
):

    st.write(f"{number}. {recommendation}")

# ==========================================
# 18. DOWNLOAD REPORTS
# ==========================================

st.divider()

st.subheader("Download Security Reports")

col1, col2 = st.columns(2)

with col1:

    st.download_button(
        "Download JSON Report",
        data=json.dumps(report, indent=4),
        file_name="analysis_report.json",
        mime="application/json"
    )

with col2:

    if CSV_FILE.exists():

        st.download_button(
            "Download CSV Report",
            data=CSV_FILE.read_bytes(),
            file_name="security_report.csv",
            mime="text/csv"
        )

    else:

        st.warning("CSV report not found.")

# ==========================================
# 19. FOOTER
# ==========================================

st.divider()

st.caption(
    "Log Analyzer | Version 7 | "
    "Python + Streamlit + Pandas"
)
