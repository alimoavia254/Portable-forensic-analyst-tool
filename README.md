Portable Forensic Analyst Tool (PFAT)
Overview
PFAT is a Python-based digital forensic tool for collecting and analyzing artifacts across Windows, macOS, and Linux. It supports browser data, USB history, network forensics, system artifacts, and more, with machine learning for anomaly detection and detailed HTML reports.
Key Features

Cross-platform forensic collection (Windows, macOS, Linux).
Collects browser history, USB devices, network data, logs, and system artifacts.
Machine learning (IsolationForest) for anomaly detection.
Anti-forensic detection (rootkits, hidden processes).
HTML reports and optional zipped output with integrity hashing (SHA-256).
Tkinter GUI for user-friendly operation.

Requirements

Python 3.8+.
Dependencies (auto-installed): pandas, numpy, scikit-learn, matplotlib, seaborn, dpkt, jinja2, psutil, python-magic, tqdm, pywin32 (Windows).
Root/admin privileges recommended for full access (Linux/Windows).

Installation

Clone the repository:git clone https://github.com/alimoavia254/Portable-forensic-analyst-tool.git
cd Portable-forensic-analyst-tool


Run the tool:python pfat.py

Dependencies install automatically on first run.

Usage
CLI
python pfat.py [-o OUTPUT_DIR] [--no-zip] [-v] [--hash ALGORITHM]


-o: Output directory (default: Forensic_Collection).
--no-zip: Disable zipping output.
-v: Verbose logging.
--hash: Hash algorithm (default: sha256).

Example:
python pfat.py -o Forensic_Output -v

GUI
Run python pfat.py, click "Start Collection," and view progress in the Tkinter interface.
Output

Artifacts in Forensic_Collection/ (Browser_Data, USB_History, Reports, etc.).
HTML reports (forensic_report.html, browser_report.html, etc.).
ML results in ML_Models/ml_anomalies.csv.
Optional zip (forensic_collection_<timestamp>.zip) with hash.

Notes

Run as root on Linux (sudo) for full access.
Close browsers before collection to avoid locked files.
Errors logged to forensic_tool.log.

Contributing
Fork, create a feature branch, and submit a pull request. Follow PEP 8 guidelines.
License
MIT License. See LICENSE.
Disclaimer
For lawful use only. Developers are not liable for misuse.
Contact
Open issues at GitHub or email [alimoavia80@gmail.com].

PFAT v3.0
