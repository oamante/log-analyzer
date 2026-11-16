
from pathlib import Path
import json
import re
import csv
import sys
from datetime import datetime

# ==========================================
# 1. FILE LOCATIONS AND SETTINGS
# ==========================================

BASE_DIR = Path(__file__).resolve().parent

REPORT_FILE = BASE_DIR / "reports" / "analysis_report.json"
CSV_REPORT_FILE = BASE_DIR / "reports" / "security_report.csv"

FAILED_LOGIN_THRESHOLD = 3
RAPID_LOGIN_THRESHOLD = 3
TIME_WINDOW_SECONDS = 60

# Accept uploaded file or use default sample.log
if len(sys.argv) > 1:

    LOG_FILE = Path(sys.argv[1])

    if not LOG_FILE.is_absolute():
        LOG_FILE = (BASE_DIR / LOG_FILE).resolve()

else:

    LOG_FILE = BASE_DIR / "logs" / "sample.log"

# ==========================================
# 2. CHECK LOG FILE
# ==========================================

if not LOG_FILE.is_file():

    print(f"Error: Log file not found: {LOG_FILE}")
    raise SystemExit(1)

# ==========================================
# 3. CREATE COUNTERS AND DICTIONARIES
# ==========================================

total_lines = 0
info_count = 0
warning_count = 0
error_count = 0
failed_login_count = 0

failed_logins = {}
failed_logins_by_ip = {}

login_timeline = []
ip_login_times = {}

# ==========================================
# 4. READ AND ANALYSE LOG FILE
# ==========================================

with LOG_FILE.open("r", encoding="utf-8") as file:

    for line in file:

        total_lines += 1

        # Count log levels
        if "INFO" in line:
            info_count += 1

        elif "WARNING" in line:
            warning_count += 1

        elif "ERROR" in line:
            error_count += 1

        # Detect failed login attempts
        if "Failed login for user " in line:

            failed_login_count += 1

            # Extract timestamp
            timestamp_text = line[:19]

            try:

                timestamp = datetime.strptime(
                    timestamp_text,
                    "%Y-%m-%d %H:%M:%S"
                )

                timestamp_string = timestamp.isoformat()

            except ValueError:

                timestamp = None
                timestamp_string = "Unknown"

            # Extract username
            username = line.split(
                "Failed login for user ", 1
            )[1].split(" from ", 1)[0].strip()

            failed_logins[username] = (
                failed_logins.get(username, 0) + 1
            )

            # Extract IP address
            ip_match = re.search(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                line
            )

            if ip_match:

                ip_address = ip_match.group()

                failed_logins_by_ip[ip_address] = (
                    failed_logins_by_ip.get(ip_address, 0) + 1
                )

                if timestamp is not None:

                    if ip_address not in ip_login_times:

                        ip_login_times[ip_address] = []

                    ip_login_times[ip_address].append(timestamp)

            else:

                ip_address = "Unknown"

            # Store login event
            login_timeline.append({

                "timestamp": timestamp_string,
                "username": username,
                "ip_address": ip_address

            })

# ==========================================
# 5. CREATE SECURITY ALERTS
# ==========================================

security_alerts = []
detailed_alerts = []


def add_alert(alert_type, severity, message, evidence):

    alert = {

        "type": alert_type,
        "severity": severity,
        "message": message,
        "evidence": evidence

    }

    detailed_alerts.append(alert)
    security_alerts.append(message)


# Check repeated failed logins by username
for username, count in failed_logins.items():

    if count >= FAILED_LOGIN_THRESHOLD:

        add_alert(
            "Repeated username failures",
            "MEDIUM",
            f"Repeated failed logins for user {username}",
            f"{count} failed attempts"
        )


# Check repeated failed logins by IP
for ip_address, count in failed_logins_by_ip.items():

    if count >= 5:

        severity = "HIGH"

    elif count >= FAILED_LOGIN_THRESHOLD:

        severity = "MEDIUM"

    else:

        continue

    add_alert(
        "Repeated IP failures",
        severity,
        f"Repeated failed logins from IP {ip_address}",
        f"{count} failed attempts"
    )

# ==========================================
# 6. IMPROVED RAPID LOGIN DETECTION
# ==========================================

rapid_login_alerts = []

for ip_address, timestamps in ip_login_times.items():

    timestamps = sorted(timestamps)

    left = 0
    max_attempts = 0

    for right in range(len(timestamps)):

        while (
            timestamps[right] - timestamps[left]
        ).total_seconds() > TIME_WINDOW_SECONDS:

            left += 1

        attempts = right - left + 1

        max_attempts = max(
            max_attempts,
            attempts
        )

    # Generate one alert per IP
    if max_attempts >= RAPID_LOGIN_THRESHOLD:

        alert = (
            f"Potential brute-force pattern from IP "
            f"{ip_address}: {max_attempts} attempts "
            f"within {TIME_WINDOW_SECONDS} seconds"
        )

        rapid_login_alerts.append(alert)

        if max_attempts >= 10:

            severity = "CRITICAL"

        else:

            severity = "HIGH"

        add_alert(
            "Rapid login activity",
            severity,
            alert,
            f"{max_attempts} attempts within "
            f"{TIME_WINDOW_SECONDS} seconds"
        )

# ==========================================
# 7. CALCULATE OVERALL RISK
# ==========================================

severity_order = {

    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4

}

if detailed_alerts:

    highest_severity = max(
        detailed_alerts,
        key=lambda alert: severity_order[alert["severity"]]
    )["severity"]

else:

    highest_severity = "LOW"

# ==========================================
# 8. GENERATE RECOMMENDATIONS
# ==========================================

recommendations = []

if rapid_login_alerts:

    recommendations.append(
        "Investigate IP addresses associated with rapid login failures."
    )

if failed_logins_by_ip:

    recommendations.append(
        "Review repeated failed login attempts by source IP."
    )

if failed_logins:

    recommendations.append(
        "Review accounts experiencing repeated authentication failures."
    )

if error_count > 0:

    recommendations.append(
        "Investigate application errors and check related system logs."
    )

if not recommendations:

    recommendations.append(
        "No suspicious login patterns detected. "
        "Continue routine monitoring."
    )

# ==========================================
# 9. CREATE IP ACTIVITY SUMMARY
# ==========================================

ip_activity = []

for ip_address, count in failed_logins_by_ip.items():

    ip_activity.append({

        "ip_address": ip_address,
        "failed_attempts": count,

        "rapid_activity_detected": any(
            ip_address in alert
            for alert in rapid_login_alerts
        )

    })

# ==========================================
# 10. CREATE JSON REPORT
# ==========================================

report = {

    "generated_at": datetime.now().isoformat(
        timespec="seconds"
    ),

    "source_file": LOG_FILE.name,

    "risk_assessment": {

        "overall_risk": highest_severity,
        "total_alerts": len(detailed_alerts)

    },

    "summary": {

        "total_log_entries": total_lines,
        "info": info_count,
        "warnings": warning_count,
        "errors": error_count,
        "failed_login_attempts": failed_login_count

    },

    "users_with_failed_logins": failed_logins,

    "failed_logins_by_ip": failed_logins_by_ip,

    "ip_activity": ip_activity,

    "login_timeline": login_timeline,

    "rapid_login_alerts": rapid_login_alerts,

    "security_alerts": security_alerts,

    "detailed_alerts": detailed_alerts,

    "recommendations": recommendations

}

# ==========================================
# 11. SAVE JSON REPORT
# ==========================================

REPORT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

with REPORT_FILE.open(
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        report,
        file,
        indent=4
    )

# ==========================================
# 12. GENERATE CSV REPORT
# ==========================================

CSV_REPORT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

with CSV_REPORT_FILE.open(
    "w",
    newline="",
    encoding="utf-8"
) as file:

    fieldnames = [

        "alert_type",
        "severity",
        "message",
        "evidence"

    ]

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()

    if detailed_alerts:

        for alert in detailed_alerts:

            writer.writerow({

                "alert_type": alert["type"],
                "severity": alert["severity"],
                "message": alert["message"],
                "evidence": alert["evidence"]

            })

    else:

        writer.writerow({

            "alert_type": "Security status",
            "severity": "LOW",
            "message": "No security alerts detected",
            "evidence": "No alert conditions matched"

        })

# ==========================================
# 13. DISPLAY SECURITY REPORT
# ==========================================

print("\n========== SECURITY ANALYSIS REPORT ==========")

print(f"Analysed file: {LOG_FILE.name}")

print(f"Total log entries: {total_lines}")
print(f"INFO messages: {info_count}")
print(f"WARNING messages: {warning_count}")
print(f"ERROR messages: {error_count}")
print(f"Failed login attempts: {failed_login_count}")

# ==========================================
# 14. DISPLAY RISK ASSESSMENT
# ==========================================

print("\n========== RISK ASSESSMENT ==========")

print(f"Overall risk: {highest_severity}")
print(f"Total security alerts: {len(detailed_alerts)}")

# ==========================================
# 15. DISPLAY USER ANALYSIS
# ==========================================

print("\n========== FAILED LOGINS BY USER ==========")

for username, count in failed_logins.items():

    print(f"{username}: {count} attempts")

# ==========================================
# 16. DISPLAY IP ANALYSIS
# ==========================================

print("\n========== FAILED LOGINS BY IP ==========")

for ip_address, count in failed_logins_by_ip.items():

    print(f"{ip_address}: {count} attempts")

# ==========================================
# 17. DISPLAY DETAILED ALERTS
# ==========================================

print("\n========== DETAILED SECURITY ALERTS ==========")

if detailed_alerts:

    for alert in detailed_alerts:

        print(f"\nSeverity: {alert['severity']}")
        print(f"Type: {alert['type']}")
        print(f"Message: {alert['message']}")
        print(f"Evidence: {alert['evidence']}")

else:

    print("No security alerts detected.")

# ==========================================
# 18. DISPLAY RECOMMENDATIONS
# ==========================================

print("\n========== SECURITY RECOMMENDATIONS ==========")

for number, recommendation in enumerate(
    recommendations,
    start=1
):

    print(f"{number}. {recommendation}")

# ==========================================
# 19. DISPLAY RAPID LOGIN DETECTION
# ==========================================

print("\n========== RAPID LOGIN DETECTION ==========")

if rapid_login_alerts:

    for alert in rapid_login_alerts:

        print(f"ALERT: {alert}")

else:

    print("No rapid login patterns detected.")

# ==========================================
# 20. DISPLAY REPORT LOCATIONS
# ==========================================

print("\n========== REPORTS GENERATED ==========")

print(f"JSON report: {REPORT_FILE}")
print(f"CSV report: {CSV_REPORT_FILE}")

print("\nSecurity analysis completed successfully!")

print("==============================================")
