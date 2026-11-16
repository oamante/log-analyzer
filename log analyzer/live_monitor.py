
import time
from pathlib import Path
from datetime import datetime

LOG_FILE = Path("logs/sample.log")

# Event counters
total_events = 0
errors = 0
warnings = 0
login_alerts = 0
normal_events = 0

# Failed login detection
failed_login_attempts = 0
ALERT_THRESHOLD = 3
alert_generated = False


def show_dashboard():

    print("\n" + "=" * 55)
    print("             LIVE SECURITY DASHBOARD")
    print("=" * 55)

    print(f"Total Events          : {total_events}")
    print(f"Errors Detected       : {errors}")
    print(f"Warnings Detected     : {warnings}")
    print(f"Login Alerts          : {login_alerts}")
    print(f"Normal Events         : {normal_events}")
    print(f"Failed Login Attempts : {failed_login_attempts}")

    print("=" * 55)


def monitor_logs():

    global total_events, errors, warnings
    global login_alerts, normal_events
    global failed_login_attempts, alert_generated

    print("\nStarting Live Security Monitoring...")

    if not LOG_FILE.exists():
        print("ERROR: Log file not found!")
        return

    with LOG_FILE.open("r", encoding="utf-8") as file:

        file.seek(0, 2)

        try:
            while True:

                line = file.readline()

                if not line:
                    time.sleep(1)
                    continue

                line = line.strip()

                if not line:
                    continue

                total_events += 1

                timestamp = datetime.now().strftime("%H:%M:%S")

                if "login failed" in line.lower():

                    login_alerts += 1
                    failed_login_attempts += 1

                    print(f"[{timestamp}] LOGIN ALERT: {line}")

                    if (
                        failed_login_attempts >= ALERT_THRESHOLD
                        and not alert_generated
                    ):

                        print("\n" + "!" * 55)
                        print("SECURITY WARNING")
                        print("Repeated failed login attempts detected!")
                        print("Investigate the affected account.")
                        print("!" * 55 + "\n")

                        alert_generated = True

                elif "error" in line.lower():

                    errors += 1
                    print(f"[{timestamp}] ERROR: {line}")

                elif "warning" in line.lower():

                    warnings += 1
                    print(f"[{timestamp}] WARNING: {line}")

                else:

                    normal_events += 1
                    print(f"[{timestamp}] EVENT: {line}")

                show_dashboard()

        except KeyboardInterrupt:

            print("\nMonitoring stopped.")
            show_dashboard()


if __name__ == "__main__":
    monitor_logs()
