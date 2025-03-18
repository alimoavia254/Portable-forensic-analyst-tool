import platform
import os
import sys
import sqlite3
import json
from datetime import datetime, timedelta
from browser_history.browsers import Chrome, Firefox, Edge
from dateutil import parser
import pandas as pd
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import filedialog
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from imblearn.over_sampling import SMOTE
import joblib
from prettytable import PrettyTable


# Initialize SQLite database
def init_db():
    try:
        conn = sqlite3.connect('forensic_tool.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS browser_artifacts (
                     id INTEGER PRIMARY KEY,
                     browser TEXT,
                     url TEXT,
                     title TEXT,
                     visit_time TEXT
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS usb_artifacts (
                     id INTEGER PRIMARY KEY,
                     device TEXT,
                     manufacturer TEXT,
                     serial_number TEXT,
                     connection_time TEXT
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS file_metadata (
                     id INTEGER PRIMARY KEY,
                     file_path TEXT,
                     last_modified TEXT,
                     date_created TEXT,
                     file_size REAL,
                     item_type TEXT,
                     attributes TEXT,
                     owner TEXT
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS network_profiles (
                     id INTEGER PRIMARY KEY,
                     ssid TEXT,
                     date_created TEXT,
                     last_connected TEXT
                     )''')    
        c.execute('''CREATE TABLE IF NOT EXISTS browser_bookmarks (
                     id INTEGER PRIMARY KEY,
                     browser TEXT,
                     url TEXT,
                     visit_time TEXT
                     )''')
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")



#////////////////////////////// Artifact of Browser(chrome,firefox,edge) /////////////////////

def collect_browser_artifacts():
    print("Collecting browser artifacts...")
    browsers = {"chrome": Chrome, "firefox": Firefox, "edge": Edge}

    for browser_name, browser_class in browsers.items():
        try:
            # Collecting history
            browser = browser_class()
            history_output = browser.fetch_history()
            with sqlite3.connect('forensic_tool.db') as conn:
                c = conn.cursor()
                for entry in history_output.histories:
                    visit_time = entry[0].strftime('%Y-%m-%d %H:%M:%S') if isinstance(entry[0], datetime) else entry[0]
                    c.execute("INSERT INTO browser_artifacts (browser, url, title, visit_time) VALUES (?, ?, ?, ?)",
                              (browser_name, entry[1], entry[2], visit_time))

            # Collecting bookmarks
            bookmarks_output = browser.fetch_bookmarks()
            with sqlite3.connect('forensic_tool.db') as conn:
                c = conn.cursor()
                for entry in bookmarks_output.bookmarks:
                    c.execute("INSERT INTO browser_bookmarks (browser, url, visit_time) VALUES (?, ?, ?)",
                              (browser_name, entry[1], entry[0]))
        except Exception as e:
            print(f"Error collecting artifacts for {browser_name}: {e}")

    print("Browser artifacts collected.")

#//////////////////////////Timeline//////////////////////////////////
def generate_timeline():
    print("Generating timeline...")
    try:
        conn = sqlite3.connect('forensic_tool.db')
        c = conn.cursor()
        c.execute("SELECT browser, url, visit_time FROM browser_artifacts")
        browser_artifacts = c.fetchall()
        c.execute("SELECT device, manufacturer, connection_time FROM usb_artifacts")
        usb_artifacts = c.fetchall()
        c.execute("SELECT file_path, last_modified FROM file_metadata")
        file_metadata = c.fetchall()
        timeline = []

        for artifact in browser_artifacts:
            timeline.append({"event": "Browser Visit", "detail": artifact[1], "timestamp": artifact[2]})
        for artifact in usb_artifacts:
            timeline.append({"event": "USB Connection", "detail": artifact[1], "timestamp": artifact[2]})
        for artifact in file_metadata:
            timeline.append({"event": "File Modification", "detail": artifact[0], "timestamp": artifact[1]})

        # Ensure all timestamps are valid
        valid_timeline = []
        for event in timeline:
            try:
                event_time = parser.parse(event["timestamp"])
                event["timestamp"] = event_time.isoformat()
                valid_timeline.append(event)
            except (ValueError, parser.ParserError):
                print(f"Invalid timestamp format: {event['timestamp']}")

        valid_timeline.sort(key=lambda x: parser.parse(x["timestamp"]))
        with open('timeline.json', 'w') as f:
            json.dump(valid_timeline, f, indent=4)
        print("Timeline generated.")
    except sqlite3.Error as e:
        print(f"Error generating timeline: {e}")



#//////////////////////////Weekly chart//////////////////////////////
# Generate chart for the last week's most visited websites

def generate_weekly_chart():
    print("Generating weekly chart...")
    try:
        conn = sqlite3.connect('forensic_tool.db')
        c = conn.cursor()
        one_week_ago = datetime.now() - timedelta(days=7)
        c.execute("SELECT url, visit_time FROM browser_artifacts WHERE visit_time >= ?", (one_week_ago.isoformat(),))
        browser_artifacts = c.fetchall()

        df = pd.DataFrame(browser_artifacts, columns=["url", "visit_time"])
        df['visit_time'] = pd.to_datetime(df['visit_time'])
        df = df[df['visit_time'] >= one_week_ago]
        most_visited = df['url'].value_counts().head(10)

        plt.figure(figsize=(12, 8))  # Increased figure size for better readability
        most_visited.plot(kind='bar', color='skyblue')
        plt.title('Top 10 Most Visited Websites in the Last Week')
        plt.xlabel('URL')
        plt.ylabel('Visit Count')
        plt.xticks(rotation=45, ha='right', fontsize=10)  # Adjust font size for better readability

        # Wrap long URLs
        labels = [label if len(label) <= 30 else label[:30] + '...' for label in most_visited.index]
        plt.gca().set_xticklabels(labels)

        plt.tight_layout()
        plt.savefig('weekly_chart.png')
        plt.close()
        print("Weekly chart generated.")
    except Exception as e:
        print(f"Error generating weekly chart: {e}")


#//////////////////////////Report Genrate////////////////////////////

# Generate PDF report
from reportlab.lib.pagesizes import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import sqlite3

from reportlab.lib.pagesizes import inch, letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import sqlite3

def generate_pdf_report():
    try:
        # Set the page size to match the report (8.5x11 inches)
        pdf_report = SimpleDocTemplate("forensic_report.pdf", pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # Title
        elements.append(Paragraph("Forensic Analysis Report", styles['Title']))
        elements.append(Spacer(1, 12))  # Adjust spacing

        # USB Artifacts
        elements.append(Paragraph("USB Artifacts", styles['Heading2']))
        conn = sqlite3.connect('forensic_tool.db')
        c = conn.cursor()
        c.execute("SELECT device, manufacturer, serial_number, connection_time FROM usb_artifacts")
        usb_artifacts = c.fetchall()
        data = [["Device", "Manufacturer", "Serial Number", "Connection Time"]] + usb_artifacts
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('BOX', (0, 0), (-1, -1), 1, colors.black),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),  # Adjust grid line thickness
            ('FONTSIZE', (0, 0), (-1, -1), 6),  # Set font size to x points
        ]))
        elements.append(table)
        elements.append(Spacer(1, 12))  # Adjust spacing

        # File Metadata
        elements.append(Paragraph("File Metadata", styles['Heading2']))
        c.execute("SELECT file_path, last_modified, date_created, file_size, item_type, attributes, owner FROM file_metadata")
        file_metadata = c.fetchall()
        data = [["File Path", "Last Modified", "Date Created", "File Size (MB)", "Item Type", "Attributes", "Owner"]] + file_metadata
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('BOX', (0, 0), (-1, -1), 1, colors.black),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTSIZE', (0, 0), (-1, -1), 5),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 12))  # Adjust spacing

        # Last Weekly Image Chart
        elements.append(Paragraph("Top 10 Most Visited Websites in the Last Week", styles['Heading2']))
        elements.append(Spacer(1, 12))  # Adjust spacing
        elements.append(Image('weekly_chart.png', width=8*inch, height=6*inch))  # Adjust image size as needed

        # Build the PDF report
        pdf_report.build(elements)
        print("PDF report generated successfully.")
    except sqlite3.Error as e:
        print(f"Error generating PDF report: {e}")


#////////////////////////for WINDOW SYSTEM /////////////////////////////////////////////

def run_windows_code():
    import os
    import win32com.client
    import win32api
    import win32con
    import win32security
    import sqlite3
    import json
    from datetime import datetime, timedelta
    from browser_history.browsers import Chrome, Firefox, Edge
    from dateutil import parser
    import pandas as pd
    import win32com.client
    import win32api
    import win32con
    import win32security
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    import matplotlib.pyplot as plt
    import tkinter as tk
    from tkinter import filedialog, messagebox
    from tkinter import filedialog
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.svm import SVC
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    from imblearn.over_sampling import SMOTE
    import joblib
    import winreg
    from datetime import datetime
    import struct

    def systemtime_to_dt(systemtime_bin):
        """Convert SYSTEMTIME binary blob to datetime object."""
        try:
            systemtime = struct.unpack('<8H', systemtime_bin)
            return datetime.datetime(  
                systemtime[0], systemtime[1], systemtime[3],  # year, month, day
                systemtime[4], systemtime[5], systemtime[6], systemtime[7]  # hour, min, sec, ms
            )
        except Exception as e:
            print(f"Error converting SYSTEMTIME to datetime: {e}")
            return "N/A"

    # Function to store network profiles in SQLite database
    def store_network_profile(ssid, date_created, last_connected):
        """Insert network profile into the database."""
        try:
            conn = sqlite3.connect('forensic_tool.db')
            c = conn.cursor()
            c.execute("INSERT INTO network_profiles (ssid, date_created, last_connected) VALUES (?, ?, ?)",
                    (ssid, date_created, last_connected))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Error inserting into database: {e}")

    # Function to retrieve and store wireless network profiles
    def get_network_profiles_windows():
        """Retrieve wireless network profiles from the registry and store in database."""
        try:
            reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            profiles_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
            key = winreg.OpenKey(reg, profiles_key)

            table = PrettyTable()
            table.field_names = ["SSID", "Date Created (UTC)", "Last Connected (UTC)"]

            for i in range(0, winreg.QueryInfoKey(key)[0]):
                try:
                    profile_subkey_name = winreg.EnumKey(key, i)
                    profile_subkey = winreg.OpenKey(key, profile_subkey_name)

                    # Retrieve SSID
                    try:
                        ssid, _ = winreg.QueryValueEx(profile_subkey, "Description")
                    except FileNotFoundError:
                        ssid = "N/A"

                    # Retrieve and convert DateCreated
                    try:
                        date_created_bin, _ = winreg.QueryValueEx(profile_subkey, "DateCreated")
                        date_created = systemtime_to_dt(date_created_bin) if isinstance(date_created_bin, bytes) else "N/A"
                    except Exception as e:
                        print(f"Error reading DateCreated for {ssid}: {e}")
                        date_created = "N/A"

                    # Retrieve and convert DateLastConnected
                    try:
                        date_last_connected_bin, _ = winreg.QueryValueEx(profile_subkey, "DateLastConnected")
                        date_last_connected = systemtime_to_dt(date_last_connected_bin) if isinstance(date_last_connected_bin, bytes) else "N/A"
                    except Exception as e:
                        print(f"Error reading DateLastConnected for {ssid}: {e}")
                        date_last_connected = "N/A"

                    # Print output in table format
                    table.add_row([ssid, date_created, date_last_connected])

                    # Store result in database
                    store_network_profile(ssid, date_created, date_last_connected)

                    winreg.CloseKey(profile_subkey)
                except Exception as e:
                    print(f"Error reading profile {i}: {e}")

            winreg.CloseKey(key)
            winreg.CloseKey(reg)

        except Exception as e:
            print(f"Error: {e}")


     # Collect USB artifacts using pywin32
    import winreg
    import datetime
    import sqlite3

    def get_usb_devices_from_registry(reg_path):
        usb_devices = []
        try:
            reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key = winreg.OpenKey(reg, reg_path)

            for i in range(winreg.QueryInfoKey(key)[0]):  # Loop through USB entries
                device_name = winreg.EnumKey(key, i)
                sub_key = winreg.OpenKey(key, device_name)

                for j in range(winreg.QueryInfoKey(sub_key)[0]):  # Loop through subkeys (serial numbers)
                    serial_number = winreg.EnumKey(sub_key, j)
                    device_key = winreg.OpenKey(sub_key, serial_number)

                    try:
                        friendly_name, _ = winreg.QueryValueEx(device_key, "FriendlyName")
                    except FileNotFoundError:
                        friendly_name = "Unknown Device"

                    try:
                        manufacturer, _ = winreg.QueryValueEx(device_key, "Mfg")
                    except FileNotFoundError:
                        manufacturer = "Unknown Manufacturer"

                    # Get the last modified time of the registry key (Approximate Last Used Time)
                    try:
                        last_modified = winreg.QueryInfoKey(device_key)[2]  # Last write time in Windows timestamp
                        connection_time = datetime.datetime.utcfromtimestamp(last_modified / 10**7 - 11644473600).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        connection_time = "Unknown Date"

                    usb_devices.append({
                        "device": friendly_name,
                        "manufacturer": manufacturer,
                        "serial_number": serial_number,
                        "connection_time": connection_time
                    })

        except Exception as e:
            print(f"Error accessing registry: {e}")

        return usb_devices

    def store_usb_artifacts():
        usb_devices = get_usb_devices_from_registry(r"SYSTEM\CurrentControlSet\Enum\USBSTOR") + \
                    get_usb_devices_from_registry(r"SYSTEM\CurrentControlSet\Enum\USB")

        if not usb_devices:
            print(" No USB artifacts found to store!")
            return

        conn = sqlite3.connect('forensic_tool.db')
        c = conn.cursor()

        # Ensure table exists
        for usb_info in usb_devices:
            c.execute('''
                INSERT INTO usb_artifacts (device, manufacturer, serial_number, connection_time)
                VALUES (?, ?, ?, ?)
            ''', (usb_info['device'], usb_info['manufacturer'], usb_info['serial_number'], usb_info['connection_time']))

        conn.commit()
        conn.close()
        print("USB artifacts stored successfully in forensic_tool.db")
        
   # Extract metadata from files
    
    import os
    import sqlite3
    import win32api
    import win32con
    import win32security
    from datetime import datetime  # Correct Import

    def determine_item_type(file_extension):
        file_extension = file_extension.lower()
        video_extensions = ['.mp4', '.avi', '.mov', '.mkv', '.flv', '.wmv']
        audio_extensions = ['.mp3', '.wav', '.aac', '.flac', '.ogg', '.wma']
        image_extensions = ['.png', '.jpeg', '.jpg', '.gif', '.bmp', '.tiff', '.webp']
        document_extensions = ['.doc', '.docx', '.pdf', '.txt', '.ppt', '.pptx', '.xls', '.xlsx']
        archive_extensions = ['.zip', '.rar', '.tar', '.gz', '.7z']
        executable_extensions = ['.exe', '.bat', '.sh', '.bin']
        script_extensions = ['.py', '.js', '.html', '.css', '.java', '.c', '.cpp', '.php', '.rb']
        
        if file_extension in video_extensions:
            return "Video File"
        elif file_extension in audio_extensions:
            return "Audio File"
        elif file_extension in image_extensions:
            return "Image File"
        elif file_extension in document_extensions:
            return "Document File"
        elif file_extension in archive_extensions:
            return "Archive File"
        elif file_extension in executable_extensions:
            return "Executable File"
        elif file_extension in script_extensions:
            return "Script File"
        else:
            return "Unknown Type"

    def extract_file_metadata(directory):
        print(f"Extracting file metadata from {directory}...")
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Extract basic file information
                    stat = os.stat(file_path)
                    file_size = stat.st_size / (1024 * 1024)  # Size in MB
                    last_modified = datetime.fromtimestamp(stat.st_mtime).isoformat()
                    date_created = datetime.fromtimestamp(stat.st_ctime).isoformat()
                    
                    # Extract file attributes
                    file_attributes = win32api.GetFileAttributes(file_path)
                    attributes = []
                    if file_attributes & win32con.FILE_ATTRIBUTE_READONLY:
                        attributes.append("Read-Only")
                    if file_attributes & win32con.FILE_ATTRIBUTE_HIDDEN:
                        attributes.append("Hidden")
                    if file_attributes & win32con.FILE_ATTRIBUTE_SYSTEM:
                        attributes.append("System")
                    if file_attributes & win32con.FILE_ATTRIBUTE_DIRECTORY:
                        attributes.append("Directory")
                    if file_attributes & win32con.FILE_ATTRIBUTE_ARCHIVE:
                        attributes.append("Archive")
                    if file_attributes & win32con.FILE_ATTRIBUTE_TEMPORARY:
                        attributes.append("Temporary")
                    if file_attributes & win32con.FILE_ATTRIBUTE_OFFLINE:
                        attributes.append("Offline")
                    if file_attributes & win32con.FILE_ATTRIBUTE_COMPRESSED:
                        attributes.append("Compressed")
                    if not attributes:
                        attributes.append("None")
                    attributes = ", ".join(attributes)
                    
                    # Extract file owner
                    sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
                    owner_sid = sd.GetSecurityDescriptorOwner()
                    owner, _, _ = win32security.LookupAccountSid(None, owner_sid)

                    # Determine item type
                    file_extension = os.path.splitext(file)[1].lower()
                    item_type = determine_item_type(file_extension)
                    
                    # Store file metadata in database
                    conn = sqlite3.connect('forensic_tool.db')
                    c = conn.cursor()
                    c.execute('''INSERT INTO file_metadata (file_path, last_modified, date_created, file_size, item_type, attributes, owner)
                                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                            (file_path, last_modified, date_created, file_size, item_type, attributes, owner))
                    conn.commit()
                    conn.close()
        except Exception as e:
            print(f"Error extracting file metadata: {e}")
        print(f"File metadata extraction complete for {directory}.")


    import sqlite3
    import pandas as pd
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler
    from imblearn.over_sampling import SMOTE
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.svm import SVC
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    import joblib
    import logging

    def run_ml_analysis():
        logging.basicConfig(filename='ml_analysis.log', level=logging.ERROR)
        print("Running machine learning analysis...")

        try:
            conn = sqlite3.connect('forensic_tool.db')
            c = conn.cursor()
            c.execute("SELECT file_size, item_type, attributes FROM file_metadata")
            data = c.fetchall()
            conn.close()

            df = pd.DataFrame(data, columns=["file_size", "item_type", "attributes"])

            if df.empty:
                print("Error: No data found in database. Machine learning analysis cannot continue.")
                return

            df['item_type'] = df['item_type'].astype('category').cat.codes
            df['attributes'] = df['attributes'].astype('category').cat.codes

            threshold = 0.5 #Example threshold, consider making it user defined.
            df['target'] = (df['file_size'] > threshold).astype(int)

            if df['target'].nunique() <= 1:
                print("Error: The target variable must have more than one class.")
                return

            X = df.drop('target', axis=1)
            y = df['target']

            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            min_samples = y.value_counts().min()

            if min_samples <= 1:
                print("Warning: Not enough samples for SMOTE. Skipping SMOTE step.")
                X_res, y_res = X_scaled, y
            else:
                smote_neighbors = min(3, min_samples - 1)
                if smote_neighbors > 0 :
                    smote = SMOTE(k_neighbors=smote_neighbors)
                    X_res, y_res = smote.fit_resample(X_scaled, y)
                else:
                    print("Warning: Not enough neighbors for SMOTE. Skipping SMOTE step.")
                    X_res, y_res = X_scaled, y

            X_train, X_test, y_train, y_test = train_test_split(X_res, y_res, test_size=0.2, random_state=42)

            models = {
                'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42),
                'SVM': SVC(kernel='rbf', probability=True),
                'GradientBoosting': GradientBoostingClassifier(n_estimators=100, learning_rate=0.1)
            }

            best_model = None
            best_score = 0

            for name, model in models.items():
                try:
                    if len(y_train) >= 4:
                        scores = cross_val_score(model, X_train, y_train, cv=min(4, len(y_train)))
                        print(f"{name} CV Accuracy: {scores.mean():.2f}")
                        if scores.mean() > best_score:
                            best_score = scores.mean()
                            best_model = model
                    else:
                        print(f"Skipping {name} - Not enough samples for cross-validation")

                except ValueError as e:
                    logging.error(f"Cross-validation error for {name}: {e}")
                    print(f"Cross-validation error for {name}: {e}")

            if best_model is None:
                print("No model passed cross-validation. Training RandomForest as fallback.")
                best_model = RandomForestClassifier(n_estimators=100, random_state=42)

            best_model.fit(X_train, y_train)
            y_pred = best_model.predict(X_test)

            accuracy = accuracy_score(y_test, y_pred)
            #...rest of the code...

        except sqlite3.Error as e:
            logging.error(f"Database Error: {e}")
            print(f"Database Error: {e}")
        except Exception as e:
            logging.error(f"Unexpected Error: {e}")
            print(f"Unexpected Error: {e}")


    # GUI Setup
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog

    # Main window setup
    root = tk.Tk()
    root.title("Forensic Analysis Tool")
    root.geometry("500x500")  # Window size
    root.resizable(False, False)  # Prevent resizing

    # Apply modern style
    style = ttk.Style()
    style.configure("TButton", font=("Arial", 12), padding=10, width=25)

    # Function placeholders (replace with actual implementations)
    def init_db_gui():
        messagebox.showinfo("Info", "Database Initialized")

    def get_network_profiles_gui():
        messagebox.showinfo("Info", "Network Profiles Retrieved")

    def collect_browser_artifacts_gui():
        messagebox.showinfo("Info", "Browser Artifacts Collected")

    def store_usb_artifacts_gui():
        messagebox.showinfo("Info", "USB Artifacts Stored")

    def extract_file_metadata_gui():
        directory = filedialog.askdirectory()
        if directory:
            messagebox.showinfo("Info", f"Metadata extracted from {directory}")

    def generate_timeline_gui():
        messagebox.showinfo("Info", "Timeline Generated")

    def generate_weekly_chart_gui():
        messagebox.showinfo("Info", "Weekly Chart Generated")

    def generate_pdf_report_gui():
        messagebox.showinfo("Info", "PDF Report Generated")

    def run_ml_analysis_gui():
        messagebox.showinfo("Info", "Machine Learning Analysis Completed")

    # Create a frame for buttons
    frame = tk.Frame(root)
    frame.pack(pady=20)

    # Buttons with equal size and better layout
    buttons = [
        ("Initialize Database", init_db_gui),
        ("Get Network Profiles", get_network_profiles_gui),
        ("Collect Browser Artifacts", collect_browser_artifacts_gui),
        ("Store USB Artifacts", store_usb_artifacts_gui),
        ("Extract File Metadata", extract_file_metadata_gui),
        ("Generate Timeline", generate_timeline_gui),
        ("Generate Weekly Chart", generate_weekly_chart_gui),
        ("Generate PDF Report", generate_pdf_report_gui),
        ("Run ML Analysis", run_ml_analysis_gui),
    ]

    # Using grid layout for better alignment
    for i, (text, command) in enumerate(buttons):
        ttk.Button(frame, text=text, command=command).grid(row=i, column=0, padx=10, pady=5)

    # Start GUI loop
    root.mainloop()

def run_linux_code():
    import os
    import sqlite3
    import json
    from datetime import datetime
    from browser_history.browsers import Chrome, Firefox, Edge
    import pandas as pd
    import pwd  # For getting file owner on Linux
    import grp
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    import tkinter as tk
    from tkinter import filedialog, messagebox

    ## for wifi artifact linux 
    import os
    import sqlite3
    import configparser
    from datetime import datetime
    from prettytable import PrettyTable

    # Function to store network profiles in SQLite database
    def store_network_profile(ssid, date_created, last_connected):
        """Insert network profile into the database."""
        try:
            conn = sqlite3.connect('forensic_tool.db')
            c = conn.cursor()
            c.execute("INSERT INTO network_profiles (ssid, date_created, last_connected) VALUES (?, ?, ?)",
                    (ssid, date_created, last_connected))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Error inserting into database: {e}")

    # Function to retrieve wireless network profiles on Linux
    def get_network_profiles_linux():
        """Retrieve wireless network profiles from NetworkManager configuration files and store in database."""
        nm_path = "/etc/NetworkManager/system-connections/"
        
        if not os.path.exists(nm_path):
            print("NetworkManager configuration directory not found. Ensure NetworkManager is installed.")
            return

        table = PrettyTable()
        table.field_names = ["SSID", "Date Created", "Last Connected"]

        for file in os.listdir(nm_path):
            file_path = os.path.join(nm_path, file)
            
            if os.path.isfile(file_path):
                try:
                    config = configparser.ConfigParser()
                    config.read(file_path)

                    ssid = config.get("wifi", "ssid", fallback="N/A")
                    
                    # Get timestamps from file metadata
                    date_created = datetime.fromtimestamp(os.path.getctime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
                    last_connected = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S")

                    table.add_row([ssid, date_created, last_connected])

                    # Store result in database
                    store_network_profile(ssid, date_created, last_connected)

                except Exception as e:
                    print(f"Error reading {file_path}: {e}")

        # Collect USB artifacts on Linux
    import os
    import sqlite3
    import datetime
    import subprocess

    def get_usb_devices():
        usb_devices = []
        
        try:
            # Run `lsusb` command to get USB devices list
            output = subprocess.check_output("lsusb", shell=True, text=True).strip().split("\n")

            for line in output:
                parts = line.split()
                bus = parts[1]  # USB Bus Number
                device_id = parts[3][:-1]  # Device ID
                vendor_id, product_id = parts[5].split(":")  # Vendor & Product ID
                manufacturer = "Unknown Manufacturer"
                product_name = "Unknown Device"

                # Fetch additional details from /sys
                device_path = f"/sys/bus/usb/devices/{bus}-{device_id}"
                if os.path.exists(device_path):
                    try:
                        with open(f"{device_path}/manufacturer", "r") as f:
                            manufacturer = f.read().strip()
                    except FileNotFoundError:
                        pass

                    try:
                        with open(f"{device_path}/product", "r") as f:
                            product_name = f.read().strip()
                    except FileNotFoundError:
                        pass

                # Approximate Last Used Time
                try:
                    last_modified = os.path.getmtime(device_path)
                    connection_time = datetime.datetime.utcfromtimestamp(last_modified).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    connection_time = "Unknown Date"

                usb_devices.append({
                    "device": product_name,
                    "manufacturer": manufacturer,
                    "serial_number": f"{vendor_id}:{product_id}",
                    "connection_time": connection_time
                })

        except Exception as e:
            print(f"Error fetching USB details: {e}")

        return usb_devices

    def store_usb_artifacts():
        usb_devices = get_usb_devices()

        if not usb_devices:
            print("No USB artifacts found to store!")
            return

        conn = sqlite3.connect('forensic_tool.db')
        c = conn.cursor()

        for usb_info in usb_devices:
            c.execute('''
                INSERT INTO usb_artifacts (device, manufacturer, serial_number, connection_time)
                VALUES (?, ?, ?, ?)
            ''', (usb_info['device'], usb_info['manufacturer'], usb_info['serial_number'], usb_info['connection_time']))

        conn.commit()
        conn.close()
        print("USB artifacts stored successfully in forensic_tool.db")

    # Extract metadata from files
    def determine_item_type(file_extension):
        file_extension = file_extension.lower()
        video_extensions = ['.mp4', '.avi', '.mov', '.mkv', '.flv', '.wmv']
        audio_extensions = ['.mp3', '.wav', '.aac', '.flac', '.ogg', '.wma']
        image_extensions = ['.png', '.jpeg', '.jpg', '.gif', '.bmp', '.tiff', '.webp']
        document_extensions = ['.doc', '.docx', '.pdf', '.txt', '.ppt', '.pptx', '.xls', '.xlsx']
        archive_extensions = ['.zip', '.rar', '.tar', '.gz', '.7z']
        executable_extensions = ['.exe', '.bat', '.sh', '.bin']
        script_extensions = ['.py', '.js', '.html', '.css', '.java', '.c', '.cpp', '.php', '.rb']
        
        if file_extension in video_extensions:
            return "Video File"
        elif file_extension in audio_extensions:
            return "Audio File"
        elif file_extension in image_extensions:
            return "Image File"
        elif file_extension in document_extensions:
            return "Document File"
        elif file_extension in archive_extensions:
            return "Archive File"
        elif file_extension in executable_extensions:
            return "Executable File"
        elif file_extension in script_extensions:
            return "Script File"
        else:
            return "Unknown Type"

    def extract_file_metadata(directory):
        print(f"Extracting file metadata from {directory}...")
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Extract basic file information
                    stat = os.stat(file_path)
                    file_size = stat.st_size / (1024 * 1024)  # Convert to MB
                    last_modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    date_created = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Determine file owner
                    owner = pwd.getpwuid(stat.st_uid).pw_name
                    
                    # Determine file type
                    item_type = determine_item_type(os.path.splitext(file)[1])
                    
                    # Store metadata in the database
                    conn = sqlite3.connect('forensic_tool.db')
                    c = conn.cursor()
                    c.execute('''INSERT INTO file_metadata (file_path, last_modified, date_created, file_size, item_type, attributes, owner)
                                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
                              (file_path, last_modified, date_created, file_size, item_type, "N/A", owner))
                    conn.commit()
                    conn.close()
        except Exception as e:
            print(f"Error extracting file metadata: {e}")


    # GUI for collecting and displaying metadata
    class MetadataApp:
        def __init__(self, root):
            self.root = root
            self.root.title("File Metadata Collector")

            self.lbl = tk.Label(root, text="Select a folder to extract file metadata:")
            self.lbl.pack(pady=10)

            self.btn_browse = tk.Button(root, text="Browse", command=self.browse_folder)
            self.btn_browse.pack(pady=5)

            self.lbl_status = tk.Label(root, text="", fg="green")
            self.lbl_status.pack(pady=10)

        def browse_folder(self):
            folder_selected = filedialog.askdirectory()
            if folder_selected:
                extract_file_metadata(folder_selected)
                self.lbl_status.config(text="File metadata extraction completed.")

    if __name__ == "__main__":
        
        # GUI Setup
        root = tk.Tk()
        root.title("Forensic Analysis Tool")
        root.geometry("400x400")

        def init_db_gui():
            init_db()
            messagebox.showinfo("Info", "Database Initialized")

        def collect_browser_artifacts_gui():
            collect_browser_artifacts()
            messagebox.showinfo("Info", "Browser Artifacts Collected")

        def store_usb_artifacts_gui():
            store_usb_artifacts()
            messagebox.showinfo("Info", "USB Artifacts Stored")

        def extract_file_metadata_gui():
            directory = filedialog.askdirectory()
            if directory:
                extract_file_metadata(directory)
                messagebox.showinfo("Info", f"Metadata extracted from {directory}")

        def generate_timeline_gui():
            generate_timeline()
            messagebox.showinfo("Info", "Timeline Generated")

        def generate_weekly_chart_gui():
            generate_weekly_chart()
            messagebox.showinfo("Info", "Weekly Chart Generated")

        def generate_pdf_report_gui():
            generate_pdf_report()
            messagebox.showinfo("Info", "PDF Report Generated")

        def get_network_profiles_gui():
            get_network_profiles_linux()
            messagebox.showinfo("Info", "Network Profiles Retrieved and Stored in Database")


    # GUI Layout
    tk.Button(root, text="Initialize Database", command=init_db_gui).pack(pady=10)
    tk.Button(root, text="Collect Browser Artifacts", command=collect_browser_artifacts_gui).pack(pady=10)
    tk.Button(root, text="Store USB Artifacts", command=store_usb_artifacts_gui).pack(pady=10)
    tk.Button(root, text="Extract File Metadata", command=extract_file_metadata_gui).pack(pady=10)
    tk.Button(root, text="Generate Timeline", command=generate_timeline_gui).pack(pady=10)
    tk.Button(root, text="Generate Weekly Chart", command=generate_weekly_chart_gui).pack(pady=10)
    tk.Button(root, text="Generate PDF Report", command=generate_pdf_report_gui).pack(pady=10)
    tk.Button(root, text="Get Network Profiles", command=get_network_profiles_gui).pack(pady=10)
    # Start the GUI loop
    root.mainloop()

def main():
    os_name = platform.system()
    if os_name == 'Windows':
        run_windows_code()
    elif os_name == 'Linux':
        run_linux_code()
    else:
        print(f"Unsupported operating system: {os_name}")
        sys.exit(1)

if __name__ == "__main__":
    main()
