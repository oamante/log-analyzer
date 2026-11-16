# Python Log Analyzer – Cybersecurity Monitoring Tool

A Python-based cybersecurity project designed to analyze system logs, identify suspicious events, and monitor new log entries in real time.

## Features

- Log file analysis
- ERROR and WARNING classification
- Suspicious login activity detection
- CSV-based security reports
- Interactive Streamlit dashboard
- Live log monitoring
- Repeated failed-login detection

## Technologies Used

- Python
- Streamlit
- Pandas (if used in the final implementation)
- CSV
- File Handling

## Project Structure

- `main.py` – Main log analysis application
- `live_monitor.py` – Live log monitoring module
- `logs/` – Sample log files
- `reports/` – Generated reports

## How to Run

1. Clone this repository.
2. Install dependencies:

   `pip install -r requirements.txt`

3. Run the dashboard:

   `streamlit run main.py`

4. Run live monitoring in a separate terminal:

   `python live_monitor.py`

## Learning Objectives

This project demonstrates Python programming, file handling, log analysis, event classification, basic security monitoring, and dashboard development.

## Limitations

This is an educational prototype. Its keyword-based detection does not establish whether an actual cyberattack has occurred.

## Author

Aman Kumar Roy