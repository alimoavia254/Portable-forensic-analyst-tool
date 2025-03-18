# Forensic Analysis Tool

A cross-platform digital forensic tool designed to collect, analyze, and report system artifacts for Windows and Linux. It extracts browser history, USB device data, network profiles, file metadata, and generates timelines, visual charts, and PDF reports. Includes machine learning for anomaly detection.



**Features**

 **Core Functionalities**
- **Browser Artifact Collection**:  
  - Extracts history and bookmarks from Chrome, Firefox, and Edge.
- **USB Device Analysis**:  
  - Retrieves connected USB device details (manufacturer, serial number, timestamps).
- **Network Profiles**:  
  - Collects Wi-Fi SSIDs, creation dates, and last connection times.
- **File Metadata Extraction**:  
  - Captures file size, ownership, timestamps, and categorizes files (e.g., documents, executables).
- **Timeline Generation**:  
  - Aggregates events (browser visits, USB connections, file modifications) into a sorted JSON timeline.
- **Automated Reporting**:  
  - Generates PDF reports with tables, charts, and visual summaries.

 **Advanced Features**
- **Machine Learning Analysis**:  
  - Predicts file anomalies based on size, type, and attributes (example threshold: `0.5 MB`).
  - Supports Random Forest, SVM, and Gradient Boosting models.
- **Cross-Platform Support**:  
  - Windows: Uses registry analysis for USB/Wi-Fi data.  
  - Linux: Parses NetworkManager configurations and `lsusb` outputs.

---
** Installation **

**Prerequisites**
- Python 3.8+
- Administrative privileges (for accessing system artifacts).

** Step 1: Clone Repository **
```bash
git clone https://github.com/Portable-forensic-analyst-tool/forensic-tool.git
cd forensic-tool
