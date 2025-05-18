import os
import sys
import shutil
import json
import sqlite3
import hashlib
import csv
import platform
import logging
import threading
import subprocess
import concurrent.futures
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
import zipfile
import tempfile
import argparse
import pickle
import socket
import psutil
import time
import warnings
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, messagebox

# Platform detection
WINDOWS = sys.platform.startswith('win')
MACOS = sys.platform == 'darwin'
LINUX = sys.platform.startswith('linux')

# Suppress warnings
warnings.filterwarnings('ignore')

# Third-party imports with automatic installation
try:
    import pandas as pd
    from pandas import DataFrame
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    from sklearn.preprocessing import LabelEncoder
    import matplotlib.pyplot as plt
    import seaborn as sns
    import dpkt
    from jinja2 import Environment, FileSystemLoader
    import psutil
except ImportError as e:
    print(f"Missing dependencies: {str(e)}")
    print("Attempting to install required packages...")
    try:
        import pip
        packages = [
            'pandas', 'numpy', 'scikit-learn', 'matplotlib', 'seaborn',
            'dpkt', 'jinja2', 'psutil', 'python-magic', 'tqdm'
        ]
        if WINDOWS:
            packages.append('pywin32')
        for package in packages:
            cmd = [sys.executable, '-m', 'pip', 'install', package]
            if not WINDOWS and hasattr(os, 'geteuid') and os.geteuid() != 0:
                cmd.append('--user')
            subprocess.check_call(cmd)
        print("Packages installed successfully. Restarting the tool...")
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as install_error:
        print(f"Failed to install packages: {str(install_error)}")
        sys.exit(1)

# Windows-only imports
if WINDOWS:
    import winreg

# Constants
VERSION = "3.0"
AUTHOR = "Advanced Digital Forensic Tool"
OUTPUT_FORMATS = ['csv', 'json', 'html', 'xlsx']
DEFAULT_HASH_ALGORITHM = 'sha256'
MAX_THREADS = 8  # For multi-threaded operations
ML_MODEL_FILE = 'forensic_rf_model.pkl'
TIMELINE_FILE = 'forensic_timeline.csv'
SIGNATURE_DATABASE = 'file_signatures.json'
MAX_TIMELINE_EVENTS = 100000  # or another reasonable number

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensic_tool.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = [
    'darkweb', 'tor', 'onion', 'illegal', 'pirate'
]
SUSPICIOUS_DOMAINS = [
    '.onion', 'thepiratebay', '1337x', 'kickass', 'porn', 'bet', 'casino', 'darkmarket', 'hydra', 'malware', 'phish'
]

class ForensicCollector:
    """Advanced forensic collection class with machine learning capabilities."""
    
    def __init__(self, output_dir: str = "Forensic_Collection", zip_output: bool = True):
        """
        Initialize the forensic collector.
        
        Args:
            output_dir: Directory to store collected artifacts
            zip_output: Whether to zip the output directory
        """
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.zip_output = zip_output
        self.system_info = self._get_system_info()
        self.setup_output_structure()
        
        # Initialize counters and trackers
        self.files_collected = 0
        self.errors_encountered = 0
        self.suspicious_files = []
        self.anti_forensic_detected = False
        
        # Initialize forensic hasher
        self.hash_algorithm = DEFAULT_HASH_ALGORITHM
        
        # Initialize browser paths
        self.browser_paths = self._initialize_browser_paths()
        
        # Initialize ML model
        self.ml_model = None
        self.ml_features = None
        self.label_encoder = LabelEncoder()
        
        # Load file signatures
        self.file_signatures = self._load_file_signatures()
        
        logger.info(f"Initialized Advanced Forensic Collector v{VERSION}")
    
    def _get_system_info(self) -> Dict:
        """Collect comprehensive system information."""
        info = {
            'system': platform.system(),
            'node': platform.node(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'timestamp': self.timestamp,
            'tool_version': VERSION,
            'python_version': platform.python_version(),
            'architecture': platform.architecture()[0],
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            'cpu_count': psutil.cpu_count(),
            'total_memory': f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
            'disks': [],
            'network_interfaces': [],
            'users': []
        }
        
        # Disk information
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                info['disks'].append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total': f"{usage.total / (1024**3):.2f} GB",
                    'used': f"{usage.used / (1024**3):.2f} GB",
                    'free': f"{usage.free / (1024**3):.2f} GB"
                })
            except Exception as e:
                logger.warning(f"Error getting disk info for {partition.mountpoint}: {str(e)}")
        
        # Network information
        for name, addrs in psutil.net_if_addrs().items():
            interface = {'name': name, 'addresses': []}
            for addr in addrs:
                interface['addresses'].append({
                    'family': addr.family.name,
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                })
            info['network_interfaces'].append(interface)
        
        # User information
        for user in psutil.users():
            info['users'].append({
                'name': user.name,
                'terminal': user.terminal,
                'host': user.host,
                'started': datetime.fromtimestamp(user.started).isoformat()
            })
        
        return info
    
    def setup_output_structure(self) -> None:
        """Create the output directory structure."""
        directories = [
            "Browser_Data",
            "USB_History",
            "Logs",
            "Reports",
            "Temp",
            "Metadata",
            "Network_Forensics",
            "Software_Inventory",
            # "Timeline",  # <-- Remove or comment out this line
            "ML_Models",
            "Anti_Forensic_Detection"
        ]
        for directory in directories:
            (self.output_dir / directory).mkdir(parents=True, exist_ok=True)
            
        # Save system info
        with open(self.output_dir / "Metadata" / "system_info.json", 'w') as f:
            json.dump(self.system_info, f, indent=4)
            
        logger.info(f"Created output structure at {self.output_dir}")
    
    def _load_file_signatures(self) -> Dict:
        """Load file signatures for anomaly detection."""
        try:
            # Try to load from local file first
            if Path(SIGNATURE_DATABASE).exists():
                with open(SIGNATURE_DATABASE, 'r') as f:
                    return json.load(f)
            
            # Default signatures (would be more comprehensive in production)
            return {
                "executable": {
                    "extensions": [".exe", ".dll", ".so", ".bin"],
                    "magic_numbers": {
                        "MZ": "PE executable",
                        "\x7FELF": "ELF executable"
                    }
                },
                "document": {
                    "extensions": [".doc", ".docx", ".pdf", ".xls", ".xlsx"],
                    "magic_numbers": {
                        "\xD0\xCF\x11\xE0": "Microsoft Office",
                        "%PDF": "PDF document"
                    }
                },
                "archive": {
                    "extensions": [".zip", ".rar", ".7z", ".tar"],
                    "magic_numbers": {
                        "PK\x03\x04": "ZIP archive",
                        "Rar!\x1A\x07": "RAR archive"
                    }
                }
            }
        except Exception as e:
            logger.error(f"Error loading file signatures: {str(e)}")
            return {}
    
    def _initialize_browser_paths(self) -> Dict:
        """Initialize paths for all supported browsers across platforms."""
        browsers = {
            'Chrome': {
                'win_path': Path(os.getenv('LOCALAPPDATA', '')) / 'Google' / 'Chrome' / 'User Data',
                'mac_path': Path('~/Library/Application Support/Google/Chrome/').expanduser(),
                'linux_path': Path('~/.config/google-chrome/').expanduser(),
                'databases': [
                    'History', 'Cookies', 'Login Data', 'Web Data', 
                    'Shortcuts', 'Top Sites', 'Favicons'
                ],
                'files': [],
                'process_name': 'chrome.exe'
            },
            'Firefox': {
                'win_path': Path(os.getenv('APPDATA', '')) / 'Mozilla' / 'Firefox' / 'Profiles',
                'mac_path': Path('~/Library/Application Support/Firefox/Profiles/').expanduser(),
                'linux_path': Path('~/.mozilla/firefox/').expanduser(),
                'databases': [
                    'places.sqlite', 'cookies.sqlite', 'formhistory.sqlite',
                    'permissions.sqlite', 'content-prefs.sqlite'
                ],
                'files': [
                    'logins.json', 'key4.db', 'cert9.db', 'prefs.js'
                ],
                'process_name': 'firefox.exe'
            },
            'Edge': {
                'win_path': Path(os.getenv('LOCALAPPDATA', '')) / 'Microsoft' / 'Edge' / 'User Data',
                'mac_path': Path('~/Library/Application Support/Microsoft Edge/').expanduser(),
                'databases': [
                    'History', 'Cookies', 'Login Data', 'Web Data'
                ],
                'files': [],
                'process_name': 'msedge.exe'
            },
            'Brave': {
                'win_path': Path(os.getenv('LOCALAPPDATA', '')) / 'BraveSoftware' / 'Brave-Browser' / 'User Data',
                'mac_path': Path('~/Library/Application Support/BraveSoftware/Brave-Browser/').expanduser(),
                'databases': [
                    'History', 'Cookies', 'Login Data', 'Web Data'
                ],
                'files': [],
                'process_name': 'brave.exe'
            },
            'Opera': {
                'win_path': Path(os.getenv('APPDATA', '')) / 'Opera Software' / 'Opera Stable',
                'mac_path': Path('~/Library/Application Support/com.operasoftware.Opera/').expanduser(),
                'databases': [
                    'History', 'Cookies', 'Login Data', 'Web Data'
                ],
                'files': [],
                'process_name': 'opera.exe'
            },
            'Safari': {
                'mac_path': Path('~/Library/Safari/').expanduser(),
                'files': [
                    'History.db', 'Downloads.plist', 'TopSites.plist',
                    'LastSession.plist', 'Bookmarks.plist'
                ],
                'process_name': 'Safari'
            }
        }
        return browsers
    
    def collect_all_artifacts(self) -> None:
        """Main method to collect all forensic artifacts using multi-threading."""
        logger.info("Starting comprehensive forensic collection")
        
        try:
            # Check for anti-forensic techniques first
            self.detect_anti_forensic()
            
            # Phase 1: System Information (already collected in init)
            
            # Phase 2: Multi-threaded collection
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                futures = [
                    executor.submit(self.collect_browser_artifacts),
                    executor.submit(self.collect_installed_software),
                    executor.submit(self.collect_network_forensics),
                    executor.submit(self.collect_usb_history if WINDOWS else self.collect_unix_usb_history),
                    executor.submit(self.collect_system_artifacts),
                    executor.submit(self.collect_memory_artifacts),
                    executor.submit(self.collect_log_files)
                ]
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error in collection thread: {str(e)}")
                        self.errors_encountered += 1
            
            # Phase 3: Timeline generation
            # self.generate_timeline()
            
            # Phase 4: Machine Learning Analysis
            self.perform_ml_analysis()
            
            # Phase 5: Generate Reports
            self.generate_reports()
            
            # Phase 6: Package Results
            if self.zip_output:
                self.package_results()
                
        except Exception as e:
            logger.error(f"Fatal error during collection: {str(e)}", exc_info=True)
            self.errors_encountered += 1
            
        logger.info(f"Collection complete. Files collected: {self.files_collected}, Errors: {self.errors_encountered}")
        if self.suspicious_files:
            logger.warning(f"Found {len(self.suspicious_files)} suspicious files")
        if self.anti_forensic_detected:
            logger.warning("Anti-forensic techniques detected!")
    
    def detect_anti_forensic(self) -> None:
        """Detect potential anti-forensic techniques."""
        logger.info("Checking for anti-forensic techniques")
        
        try:
            # Check for rootkits (basic checks)
            rootkit_paths = [
                "/dev/kmem", "/dev/mem", "/dev/port", 
                "/dev/kmem", "/dev/mem", "/dev/port"
            ]
            
            for path in rootkit_paths:
                if Path(path).exists():
                    self.anti_forensic_detected = True
                    logger.warning(f"Potential rootkit found: {path}")
            
            # Check for hidden processes
            all_pids = {p.pid for p in psutil.process_iter()}
            if not WINDOWS:
                proc_pids = {int(f.name) for f in Path('/proc').iterdir() if f.name.isdigit()}
                # Unix specific checks
                hidden_pids = all_pids - proc_pids
                if hidden_pids:
                    self.anti_forensic_detected = True
                    logger.warning(f"Found {len(hidden_pids)} hidden processes")
            else:
                # Windows specific checks
                try:
                    winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services")
                except Exception:
                    self.anti_forensic_detected = True
                    logger.warning("Registry access blocked - possible anti-forensic technique")
            
            # Check for time stomping
            recent_files = 0
            for root, _, files in os.walk(str(Path.home())):
                for file in files:
                    try:
                        file_path = Path(root) / file
                        stat = file_path.stat()
                        if (datetime.now().timestamp() - stat.st_mtime) < 3600:
                            recent_files += 1
                    except:
                        continue
            
            if recent_files > 1000:
                self.anti_forensic_detected = True
                logger.warning(f"Excessive recent file modifications ({recent_files}) - possible time stomping")
            
            # Save anti-forensic findings
            with open(self.output_dir / "Anti_Forensic_Detection" / "findings.json", 'w') as f:
                json.dump({
                    'anti_forensic_detected': self.anti_forensic_detected,
                    'suspicious_files': self.suspicious_files,
                    'timestamp': self.timestamp
                }, f, indent=4)
                
        except Exception as e:
            logger.error(f"Error in anti-forensic detection: {str(e)}")
            self.errors_encountered += 1
    
    def collect_browser_artifacts(self) -> None:
        """Collect artifacts from all detected browsers using multi-threading."""
        logger.info("Starting browser artifact collection")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = []
            for browser, paths in self.browser_paths.items():
                futures.append(executor.submit(self._collect_single_browser, browser, paths))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error in browser collection: {str(e)}")
                    self.errors_encountered += 1
    
    def _collect_single_browser(self, browser: str, paths: Dict) -> None:
        """Collect artifacts from a single browser."""
        try:
            path = None
            if self.system_info['system'] == 'Windows':
                path = paths.get('win_path')
            elif self.system_info['system'] == 'Darwin':  # macOS
                path = paths.get('mac_path')
            else:  # Linux
                path = paths.get('linux_path')
            
            if path and path.exists():
                logger.info(f"Found {browser} at {path}")
                
                # Warn if browser is running
                for proc in psutil.process_iter(['name']):
                    if proc.info['name'] and browser.lower() in proc.info['name'].lower():
                        logger.warning(f"{browser} appears to be running. Please close it for best results.")
                        break
                
                self._process_browser(browser, path)
            else:
                logger.debug(f"{browser} not found at {path}")
                
        except Exception as e:
            logger.error(f"Error processing {browser}: {str(e)}", exc_info=True)
            self.errors_encountered += 1
    
    def _process_browser(self, browser: str, base_path: Path) -> None:
        """Process a single browser's artifacts."""
        dest_dir = self.output_dir / "Browser_Data" / browser
        dest_dir.mkdir(exist_ok=True)
        
        # Copy profile directories with multi-threaded
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = []
            
            if browser == 'Firefox':
                for profile_dir in base_path.glob('*'):
                    if profile_dir.is_dir() and profile_dir.name.endswith('.default'):
                        futures.append(executor.submit(
                            self._copy_firefox_profile, 
                            profile_dir, 
                            dest_dir / profile_dir.name
                        ))
            else:
                default_profile = base_path / 'Default'
                if default_profile.exists():
                    futures.append(executor.submit(
                        self._copy_browser_profile, 
                        default_profile, 
                        dest_dir / 'Default'
                    ))
                
                # Handle other profiles
                for profile_dir in base_path.glob('Profile *'):
                    if profile_dir.is_dir():
                        futures.append(executor.submit(
                            self._copy_browser_profile, 
                            profile_dir, 
                            dest_dir / profile_dir.name
                        ))
        
            # Special handling for Safari
            if browser == 'Safari':
                futures.append(executor.submit(
                    self._copy_safari_data, 
                    base_path, 
                    dest_dir
                ))
            
            # Wait for all copies to complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error copying browser data: {str(e)}")
                    self.errors_encountered += 1
        
        # Scan for suspicious history after copying profiles
        for profile_dir in dest_dir.glob('*'):
            if profile_dir.is_dir():
                history = self._extract_browser_history(browser, profile_dir)
                flagged = self._scan_browser_history_for_suspicious(history)
                if flagged:
                    suspicious_history_file = profile_dir / "suspicious_history.json"
                    with open(suspicious_history_file, 'w', encoding='utf-8') as f:
                        json.dump(flagged, f, indent=2)
                    logger.warning(f"Suspicious browser history found in {browser} profile {profile_dir.name}")
    
    def _copy_browser_profile(self, src_profile: Path, dest_profile: Path) -> None:
        """Copy all files from a browser profile."""
        try:
            if src_profile.exists():
                for root, dirs, files in os.walk(src_profile):
                    for file in files:
                        src_file = Path(root) / file
                        dest_file = dest_profile / Path(root).relative_to(src_profile) / file
                        dest_file.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            shutil.copy2(src_file, dest_file)
                            self.files_collected += 1
                        except PermissionError as e:
                            logger.debug(f"Permission denied copying {src_file}: {str(e)}")
                            continue
                        except Exception as e:
                            logger.error(f"Error copying {src_file}: {str(e)}")
                            self.errors_encountered += 1
        except Exception as e:
            logger.error(f"Error copying browser profile {src_profile}: {str(e)}")
            self.errors_encountered += 1
    
    def _copy_firefox_profile(self, src_profile: Path, dest_profile: Path) -> None:
        """Special handling for Firefox profiles with integrity checks."""
        dest_profile.mkdir(exist_ok=True)
        
        # Copy databases
        for db in self.browser_paths['Firefox']['databases']:
            src_db = src_profile / db
            if src_db.exists():
                try:
                    # REMOVE hash before/after copy and hash log
                    shutil.copy2(src_db, dest_profile / db)
                    self.files_collected += 1
                    self._check_file_anomalies(src_db)
                except Exception as e:
                    logger.error(f"Error copying Firefox DB {src_db}: {str(e)}")
                    self.errors_encountered += 1
        
        # Copy other files
        for file in self.browser_paths['Firefox']['files']:
            src_file = src_profile / file
            if src_file.exists():
                try:
                    # Create hash before copy
                    original_hash = self._calculate_file_hash(src_file)
                    
                    # Copy file
                    shutil.copy2(src_file, dest_profile / file)
                    
                    # Verify copied file hash
                    copied_hash = self._calculate_file_hash(dest_profile / file)
                    
                    if original_hash != copied_hash:
                        raise ValueError(f"Hash mismatch for {file} - possible corruption")
                    
                    self._create_hash_log(src_file, dest_profile / "file_hashes.log")
                    self.files_collected += 1
                    
                    # Check for file anomalies
                    self._check_file_anomalies(src_file)
                    
                except Exception as e:
                    logger.error(f"Error copying Firefox file {src_file}: {str(e)}")
                    self.errors_encountered += 1
    
    def _copy_safari_data(self, src_path: Path, dest_path: Path) -> None:
        """Special handling for Safari browser with integrity checks."""
        for file in self.browser_paths['Safari']['files']:
            src_file = src_path / file
            if src_file.exists():
                try:
                    # Create hash before copy
                    original_hash = self._calculate_file_hash(src_file)
                    
                    # Copy file
                    shutil.copy2(src_file, dest_path / file)
                    
                    # Verify copied file hash
                    copied_hash = self._calculate_file_hash(dest_path / file)
                    
                    if original_hash != copied_hash:
                        raise ValueError(f"Hash mismatch for {file} - possible corruption")
                    
                    self._create_hash_log(src_file, dest_path / "file_hashes.log")
                    self.files_collected += 1
                    
                    # Check for file anomalies
                    self._check_file_anomalies(src_file)
                    
                except Exception as e:
                    logger.error(f"Error copying Safari file {src_file}: {str(e)}")
                    self.errors_encountered += 1
    
    def _check_file_anomalies(self, file_path: Path) -> None:
        """Check a file for anomalies that might indicate tampering."""
        try:
            anomalies = []
            
            # Check extension vs actual content
            file_type = self._get_file_type(file_path)
            if file_type and file_path.suffix.lower() not in self.file_signatures.get(file_type, {}).get('extensions', []):
                anomalies.append(f"Extension mismatch: {file_path.suffix} for {file_type}")
            
            # Check for unusually large small files
            file_size = file_path.stat().st_size
            if file_size == 0:
                anomalies.append("Zero-byte file")
            elif file_size > 100 * 1024 * 1024:  # 100MB
                anomalies.append(f"Unusually large file: {file_size} bytes")
            
            # Check timestamps
            stat = file_path.stat()
            modified_time = datetime.fromtimestamp(stat.st_mtime)
            created_time = datetime.fromtimestamp(stat.st_ctime)
            accessed_time = datetime.fromtimestamp(stat.st_atime)
            
            if modified_time < created_time:
                anomalies.append("Modified time before creation time")
            
            if (datetime.now() - modified_time).days < 1 and file_size > 1024 * 1024:  # 1MB
                anomalies.append("Recently modified large file")
            
            if anomalies:
                self.suspicious_files.append({
                    'path': str(file_path),
                    'anomalies': anomalies,
                    'size': file_size,
                    'modified': modified_time.isoformat(),
                    'created': created_time.isoformat(),
                    'accessed': accessed_time.isoformat()
                })
                
        except Exception as e:
            logger.warning(f"Error checking file anomalies for {file_path}: {str(e)}")
    
    def _get_file_type(self, file_path: Path) -> Optional[str]:
        """Determine file type based on magic numbers."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)  # Read first 32 bytes
            
            for file_type, signatures in self.file_signatures.items():
                for magic, _ in signatures.get('magic_numbers', {}).items():
                    if header.startswith(magic.encode() if isinstance(magic, str) else magic):
                        return file_type
            return None
        except Exception:
            return None
    
    def collect_installed_software(self) -> None:
        """Collect inventory of installed software."""
        logger.info("Collecting installed software inventory")
        
        try:
            software_list = []
            
            if WINDOWS:
                # Windows software from registry
                uninstall_keys = [
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                ]
                
                for key_path in uninstall_keys:
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                            for i in range(winreg.QueryInfoKey(key)[0]):
                                try:
                                    subkey_name = winreg.EnumKey(key, i)
                                    with winreg.OpenKey(key, subkey_name) as subkey:
                                        software = {'Source': 'Windows Registry'}
                                        try:
                                            software['Name'] = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                                            software['Version'] = winreg.QueryValueEx(subkey, 'DisplayVersion')[0]
                                            software['Publisher'] = winreg.QueryValueEx(subkey, 'Publisher')[0]
                                            software['InstallDate'] = winreg.QueryValueEx(subkey, 'InstallDate')[0]
                                            software['InstallLocation'] = winreg.QueryValueEx(subkey, 'InstallLocation')[0]
                                            software['UninstallString'] = winreg.QueryValueEx(subkey, 'UninstallString')[0]
                                            software_list.append(software)
                                        except WindowsError:
                                            continue
                                except WindowsError:
                                    continue
                    except WindowsError:
                        continue
                
                # Windows features
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages") as key:
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            subkey_name = winreg.EnumKey(key, i)
                            if subkey_name.startswith('Package_'):
                                software_list.append({
                                    'Name': subkey_name,
                                    'Source': 'Windows Features'
                                })
                except WindowsError:
                    pass
            else:
                # Linux/macOS software
                # Check package managers
                package_managers = {
                    'dpkg': ['dpkg', '-l'],
                    'rpm': ['rpm', '-qa'],
                    'pacman': ['pacman', '-Q'],
                    'brew': ['brew', 'list'],
                    'port': ['port', 'installed']
                }
                
                for pm, cmd in package_managers.items():
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        if result.returncode == 0:
                            for line in result.stdout.splitlines():
                                software_list.append({
                                    'Name': line.strip(),
                                    'Source': pm
                                })
                    except FileNotFoundError:
                        continue
                
                # Check applications directories
                if self.system_info['system'] == 'Darwin':  # macOS
                    app_dir = Path('/Applications')
                    for app in app_dir.glob('*.app'):
                        software_list.append({
                            'Name': app.stem,
                            'Source': 'macOS Applications',
                            'Path': str(app)
                        })
                
                # Check flatpak and snap
                for pm in ['flatpak', 'snap']:
                    try:
                        result = subprocess.run([pm, 'list'], capture_output=True, text=True)
                        if result.returncode == 0:
                            for line in result.stdout.splitlines()[1:]:  # Skip header
                                parts = line.split()
                                software_list.append({
                                    'Name': parts[0],
                                    'Version': parts[1] if len(parts) > 1 else None,
                                    'Source': pm
                                })
                    except FileNotFoundError:
                        continue
            
            # Save software inventory
            software_csv = self.output_dir / "Software_Inventory" / f"installed_software_{self.timestamp}.csv"
            with open(software_csv, 'w', newline='', encoding='utf-8') as f:
                if software_list:
                    writer = csv.DictWriter(f, fieldnames=software_list[0].keys())
                    writer.writeheader()
                    writer.writerows(software_list)
            
            logger.info(f"Saved software inventory with {len(software_list)} items")
            self.files_collected += 1
            
        except Exception as e:
            logger.error(f"Error collecting software inventory: {str(e)}")
            self.errors_encountered += 1
    
    def collect_network_forensics(self) -> None:
        """Collect network forensic artifacts."""
        logger.info("Collecting network forensic artifacts")
        
        try:
            net_dir = self.output_dir / "Network_Forensics"
            net_dir.mkdir(exist_ok=True)
            
            # Collect active connections
            with open(net_dir / 'active_connections.txt', 'w') as f:
                for conn in psutil.net_connections():
                    f.write(f"{conn}\n")
            
            # Collect interface information
            with open(net_dir / 'interface_details.txt', 'w') as f:
                for name, addrs in psutil.net_if_addrs().items():
                    f.write(f"Interface: {name}\n")
                    for addr in addrs:
                        f.write(f"  {addr.family.name}: {addr.address}\n")
                        if addr.netmask:
                            f.write(f"    Netmask: {addr.netmask}\n")
                        if addr.broadcast:
                            f.write(f"    Broadcast: {addr.broadcast}\n")
                    f.write("\n")
            
            # Collect DNS cache (Windows only)
            if WINDOWS:
                try:
                    with open(net_dir / 'dns_cache.txt', 'w') as f:
                        subprocess.run(['ipconfig', '/displaydns'], stdout=f)
                except Exception as e:
                    logger.warning(f"Could not collect DNS cache: {str(e)}")
            
            # Collect ARP cache
            with open(net_dir / 'arp_cache.txt', 'w') as f:
                if WINDOWS:
                    subprocess.run(['arp', '-a'], stdout=f)
                else:
                    subprocess.run(['arp', '-an'], stdout=f)
            
            # Collect routing table
            with open(net_dir / 'routing_table.txt', 'w') as f:
                if WINDOWS:
                    subprocess.run(['route', 'print'], stdout=f)
                else:
                    subprocess.run(['netstat', '-rn'], stdout=f)
            
            # Collect firewall rules
            with open(net_dir / 'firewall_rules.txt', 'w') as f:
                if WINDOWS:
                    subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], stdout=f)
                elif self.system_info['system'] == 'Darwin':  # macOS
                    subprocess.run(['pfctl', '-sr'], stdout=f)
                else:  # Linux
                    subprocess.run(['iptables', '-L', '-n', '-v'], stdout=f)
            
            # Collect recent network connections from logs
            self._collect_network_logs(net_dir)
            
            # Packet capture analysis (would need root privileges)
            # self._analyze_packet_captures(net_dir)
            
            self.files_collected += 6
            
        except Exception as e:
            logger.error(f"Error collecting network artifacts: {str(e)}")
            self.errors_encountered += 1
    
    def _collect_network_logs(self, net_dir: Path) -> None:
        """Collect relevant network logs."""
        try:
            log_files = []
            
            if WINDOWS:
                # Windows event logs would require special handling
                pass
            else:
                # Common Unix log files
                log_files.extend([
                    '/var/log/syslog',  # Add this for Debian/Kali
                    '/var/log/messages',
                    '/var/log/auth.log',
                    '/var/log/secure',
                    '/var/log/dmesg',
                    '/var/log/kern.log',
                    '/var/log/ufw.log',
                    '/var/log/firewalld'
                ])
                
                # macOS specific
                if self.system_info['system'] == 'Darwin':
                    log_files.extend([
                        '/var/log/system.log',
                        '/var/log/install.log',
                        '/var/log/accountpolicy.log'
                    ])
            
            # Filter to existing logs
            log_files = [Path(f) for f in log_files if Path(f).exists()]
            
            # Copy relevant logs
            for log_file in log_files:
                try:
                    shutil.copy2(log_file, net_dir / log_file.name)
                    self.files_collected += 1
                except Exception as e:
                    logger.warning(f"Could not copy log file {log_file}: {str(e)}")
                    continue
            
            # Parse logs for network connections
            self._parse_network_logs(net_dir)
            
        except Exception as e:
            logger.error(f"Error collecting network logs: {str(e)}")
            self.errors_encountered += 1
    
    def _parse_network_logs(self, net_dir: Path) -> None:
        """Parse network logs for connection attempts."""
        try:
            connections = []
            
            for log_file in net_dir.glob('*.log'):
                with open(log_file, 'r', errors='ignore') as f:
                    for line in f:
                        # Simple pattern matching (would be more sophisticated in production)
                        if 'connect' in line.lower() or 'connection' in line.lower():
                            connections.append({
                                'log_file': log_file.name,
                                'timestamp': line[:20] if len(line) > 20 else None,
                                'entry': line.strip()
                            })
            
            if connections:
                conn_csv = net_dir / 'network_connections.csv'
                with open(conn_csv, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=connections[0].keys())
                    writer.writeheader()
                    writer.writerows(connections)
                
                self.files_collected += 1
                
        except Exception as e:
            logger.error(f"Error parsing network logs: {str(e)}")
            self.errors_encountered += 1
    
    def collect_usb_history(self) -> None:
        """Collect USB history from Windows systems with enhanced details."""
        if not WINDOWS:
            logger.warning("USB history collection only available on Windows")
            return
            
        logger.info("Collecting USB history from Windows Registry")
        
        usb_data = []
        try:
            # USBSTOR - Mass storage devices
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR") as usbstor_key:
                self._enumerate_usb_devices(usbstor_key, usb_data, 'USBSTOR')
                
            # USB - Other USB devices
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USB") as usb_key:
                self._enumerate_usb_devices(usb_key, usb_data, 'USB')
                
            # SetupAPI logs for more history
            self._parse_setupapi_logs(usb_data)
                
            # Save USB data
            self._save_usb_data(usb_data)
            
        except Exception as e:
            logger.error(f"Error accessing USB registry: {str(e)}", exc_info=True)
            self.errors_encountered += 1
    
    def _parse_setupapi_logs(self, usb_data: List) -> None:
        """Parse Windows SetupAPI logs for USB connection history."""
        try:
            setupapi_log = Path(os.getenv('WINDIR', 'C:\\Windows')) / 'INF' / 'setupapi.dev.log'
            if not setupapi_log.exists():
                return
                
            current_device = None
            with open(setupapi_log, 'r', errors='ignore') as f:
                for line in f:
                    if 'Device Install (Hardware initiated)' in line and 'USBSTOR' in line:
                        # New device entry
                        if current_device:
                            usb_data.append(current_device)
                        current_device = {
                            'type': 'SetupAPI',
                            'timestamp': line[:23],
                            'device_id': line.split('USBSTOR\\')[1].split('&')[0] if 'USBSTOR\\' in line else None,
                            'events': []
                        }
                    elif current_device and '>>>  Section start' in line:
                        current_device['events'].append(line.strip())
                    elif current_device and '<<<  Section end' in line:
                        current_device['events'].append(line.strip())
                        usb_data.append(current_device)
                        current_device = None
            
            if current_device:
                usb_data.append(current_device)
                
        except Exception as e:
            logger.error(f"Error parsing SetupAPI logs: {str(e)}")
            self.errors_encountered += 1
    
    def collect_unix_usb_history(self) -> None:
        """Collect USB history from Unix-like systems (Linux/macOS) with enhanced details."""
        logger.info("Collecting USB history from Unix system")
        usb_data = []
        try:
            # Linux USB detection
            if self.system_info['system'] == 'Linux':
                # Check /sys/bus/usb/devices
                sys_usb = Path('/sys/bus/usb/devices')
                if sys_usb.exists():
                    for device in sys_usb.iterdir():
                        product = (device / 'product')
                        manufacturer = (device / 'manufacturer')
                        serial = (device / 'serial')
                        vid = (device / 'idVendor')
                        pid = (device / 'idProduct')
                        entry = {
                            'device': device.name,
                            'product': product.read_text().strip() if product.exists() else None,
                            'manufacturer': manufacturer.read_text().strip() if manufacturer.exists() else None,
                            'serial': serial.read_text().strip() if serial.exists() else None,
                            'vendor_id': vid.read_text().strip() if vid.exists() else None,
                            'product_id': pid.read_text().strip() if pid.exists() else None,
                        }
                        if any(entry.values()):
                            usb_data.append(entry)
                # Check udev database (legacy)
                udev_db = Path('/var/lib/udev/udev.db')
                if udev_db.exists():
                    self._parse_udev_database(udev_db, usb_data)
                # Check kernel messages
                messages = Path('/var/log/messages')
                syslog = Path('/var/log/syslog')
                if messages.exists():
                    self._parse_log_for_usb(messages, usb_data)
                elif syslog.exists():
                    self._parse_log_for_usb(syslog, usb_data)
                # dmesg output
                try:
                    dmesg = subprocess.run(['dmesg'], capture_output=True, text=True)
                    if dmesg.returncode == 0:
                        for line in dmesg.stdout.splitlines():
                            if 'usb' in line.lower():
                                usb_data.append({
                                    'type': 'dmesg',
                                    'timestamp': line[:15] if len(line) > 15 else None,
                                    'entry': line.strip()
                                })
                except Exception:
                    pass
            # macOS USB detection (unchanged)
            elif self.system_info['system'] == 'Darwin':
                system_log = Path('/var/log/system.log')
                if system_log.exists():
                    self._parse_log_for_usb(system_log, usb_data)
                self._parse_macos_ioreg(usb_data)
                try:
                    usb_info = subprocess.run(['system_profiler', 'SPUSBDataType'], capture_output=True, text=True)
                    if usb_info.returncode == 0:
                        usb_data.append({
                            'type': 'system_profiler',
                            'data': usb_info.stdout
                        })
                except Exception:
                    pass
            # Save collected USB data
            self._save_usb_data(usb_data)
            if not usb_data:
                logger.warning("No USB devices found on this Unix system.")
        except Exception as e:
            logger.error(f"Error collecting Unix USB history: {str(e)}", exc_info=True)
            self.errors_encountered += 1
    
    def collect_system_artifacts(self) -> None:
        """Collect additional system artifacts with multi-threading."""
        logger.info("Collecting additional system artifacts")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [
                executor.submit(self._collect_recent_documents),
                executor.submit(self._collect_shell_history),
                executor.submit(self._collect_scheduled_tasks),
                executor.submit(self._collect_environment_variables),
                executor.submit(self._collect_user_profiles)
            ]
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error in system artifact collection: {str(e)}")
                    self.errors_encountered += 1
    
    def _collect_recent_documents(self) -> None:
        """Collect recent documents with full metadata."""
        if WINDOWS:
            self._collect_windows_recent()

        recent_dirs = [
            Path('~/Recent').expanduser(),
            Path('~/.local/share/recently-used.xbel').expanduser()
        ]

        dest_dir = self.output_dir / "System_Artifacts" / "Recent_Documents"
        dest_dir.mkdir(parents=True, exist_ok=True)

        metadata_list = []
        for recent_dir in recent_dirs:
            if recent_dir.exists():
                if recent_dir.is_file():
                    files = [recent_dir]
                else:
                    files = list(recent_dir.iterdir())
                for item in files:
                    if item.is_file():
                        try:
                            stat = item.stat()
                            meta = {
                                'name': item.name,
                                'path': str(item),
                                'size': stat.st_size,
                                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                                'mode': oct(stat.st_mode),
                                'owner': stat.st_uid if hasattr(stat, 'st_uid') else None,
                                'group': stat.st_gid if hasattr(stat, 'st_gid') else None
                            }
                            metadata_list.append(meta)
                            shutil.copy2(item, dest_dir / item.name)
                            self.files_collected += 1
                        except Exception as e:
                            logger.warning(f"Error copying recent file {item}: {str(e)}")
                            self.errors_encountered += 1
        # Save metadata as JSON in the main output directory
        with open(self.output_dir / "recent_files_metadata.json", 'w') as f:
            json.dump(metadata_list, f, indent=2)
    
    def _collect_windows_recent(self) -> None:
        """Collect Windows recent documents."""
        try:
            recent_dir = Path(os.getenv('APPDATA', '')) / 'Microsoft' / 'Windows' / 'Recent'
            if recent_dir.exists():
                dest_dir = self.output_dir / "System_Artifacts" / "Recent_Documents"
                dest_dir.mkdir(parents=True, exist_ok=True)
                
                for item in recent_dir.iterdir():
                    try:
                        if item.is_file():
                            # Create hash before copy
                            original_hash = self._calculate_file_hash(item)
                            
                            # Copy file
                            shutil.copy2(item, dest_dir / item.name)
                            
                            # Verify copied file hash
                            copied_hash = self._calculate_file_hash(dest_dir / item.name)
                            
                            if original_hash != copied_hash:
                                raise ValueError(f"Hash mismatch for {item.name} - possible corruption")
                            
                            self._create_hash_log(item, dest_dir / "recent_files_hashes.log")
                            self.files_collected += 1
                            
                            # Check for file anomalies
                            self._check_file_anomalies(item)
                    except Exception as e:
                        if isinstance(e, FileNotFoundError):
                            logger.debug(f"File not found when copying recent file {item}: {str(e)}")
                        else:
                            logger.error(f"Error copying recent file {item}: {str(e)}")
                        self.errors_encountered += 1
                        
        except Exception as e:
            logger.error(f"Error collecting recent documents: {str(e)}")
            self.errors_encountered += 1
    
    def _collect_shell_history(self) -> None:
        """Collect shell history from Unix systems."""
        try:
            histories = [
                Path('~/.bash_history').expanduser(),
                Path('~/.zsh_history').expanduser(),
                Path('~/.history').expanduser(),
                Path('~/.sh_history').expanduser(),
                Path('~/.bash_sessions').expanduser(),
                Path('~/.zsh_sessions').expanduser()
            ]
            
            dest_dir = self.output_dir / "System_Artifacts" / "Shell_History"
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            for history in histories:
                if history.exists():
                    try:
                        # Create hash before copy
                        original_hash = self._calculate_file_hash(history)
                        
                        # Copy file
                        shutil.copy2(history, dest_dir / history.name)
                        
                        # Verify copied file hash
                        copied_hash = self._calculate_file_hash(dest_dir / history.name)
                        
                        if original_hash != copied_hash:
                            raise ValueError(f"Hash mismatch for {history.name} - possible corruption")
                        
                        self._create_hash_log(history, dest_dir / "shell_history_hashes.log")
                        self.files_collected += 1
                        
                        # Check for file anomalies
                        self._check_file_anomalies(history)
                    except Exception as e:
                        logger.error(f"Error copying shell history {history}: {str(e)}")
                        self.errors_encountered += 1
                    
        except Exception as e:
            logger.error(f"Error collecting shell history: {str(e)}")
    
    def _collect_scheduled_tasks(self) -> None:
        """Collect scheduled tasks/cron jobs."""
        try:
            tasks_dir = self.output_dir / "System_Artifacts" / "Scheduled_Tasks"
            tasks_dir.mkdir(parents=True, exist_ok=True)
            
            if WINDOWS:
                # Windows Task Scheduler
                try:
                    with open(tasks_dir / 'scheduled_tasks.txt', 'w') as f:
                        subprocess.run(['schtasks', '/query', '/fo', 'LIST', '/v'], stdout=f)
                    self.files_collected += 1
                except Exception as e:
                    logger.warning(f"Could not collect scheduled tasks: {str(e)}")
            else:
                # Unix cron jobs
                cron_files = [
                    '/etc/crontab',
                    '/etc/cron.d/',
                    '/etc/cron.hourly/',
                    '/etc/cron.daily/',
                    '/etc/cron.weekly/',
                    '/etc/cron.monthly/'
                ]
                
                for cron_file in cron_files:
                    cron_path = Path(cron_file)
                    if cron_path.exists():
                        if cron_path.is_dir():
                            for item in cron_path.iterdir():
                                if item.is_file():
                                    shutil.copy2(item, tasks_dir / item.name)
                                    self.files_collected += 1
                        else:
                            shutil.copy2(cron_path, tasks_dir / cron_path.name)
                            self.files_collected += 1
                
                # User crontabs
                for user in psutil.users():
                    user_cron = Path(f'/var/spool/cron/crontabs/{user.name}')
                    if user_cron.exists():
                        shutil.copy2(user_cron, tasks_dir / f'crontab_{user.name}')
                        self.files_collected += 1
                
        except Exception as e:
            logger.error(f"Error collecting scheduled tasks: {str(e)}")
            self.errors_encountered += 1
    
    def _collect_environment_variables(self) -> None:
        """Collect environment variables."""
        try:
            env_dir = self.output_dir / "System_Artifacts" / "Environment"
            env_dir.mkdir(parents=True, exist_ok=True)
            
            with open(env_dir / 'environment_variables.txt', 'w') as f:
                for key, value in os.environ.items():
                    f.write(f"{key}={value}\n")
            
            self.files_collected += 1
            
        except Exception as e:
            logger.error(f"Error collecting environment variables: {str(e)}")
            self.errors_encountered += 1
    
    def _collect_user_profiles(self) -> None:
        """Collect basic user profile information."""
        try:
            users_dir = self.output_dir / "System_Artifacts" / "User_Profiles"
            users_dir.mkdir(parents=True, exist_ok=True)
            
            if WINDOWS:
                # Windows user profiles from registry
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") as key:
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, subkey_name) as subkey:
                                    profile = {
                                        'SID': subkey_name,
                                        'ProfileImagePath': winreg.QueryValueEx(subkey, 'ProfileImagePath')[0],
                                        'Flags': winreg.QueryValueEx(subkey, 'Flags')[0],
                                        'State': winreg.QueryValueEx(subkey, 'State')[0]
                                    }
                                    
                                    with open(users_dir / f'user_{subkey_name}.json', 'w') as f:
                                        json.dump(profile, f, indent=4)
                                    self.files_collected += 1
                            except WindowsError:
                                continue
                except WindowsError:
                    pass
            else:
                # Unix user profiles from /etc/passwd
                try:
                    with open('/etc/passwd', 'r') as f:
                        with open(users_dir / 'passwd', 'w') as out_f:
                            out_f.write(f.read())
                    self.files_collected += 1
                except Exception:
                    pass
                
                # Shadow file if accessible
                try:
                    with open('/etc/shadow', 'r') as f:
                        with open(users_dir / 'shadow', 'w') as out_f:
                            out_f.write(f.read())
                    self.files_collected += 1
                except Exception:
                    pass
                
        except Exception as e:
            logger.error(f"Error collecting user profiles: {str(e)}")
            self.errors_encountered += 1
    
    def collect_memory_artifacts(self) -> None:
        """Collect memory-related artifacts (limited without full memory dump)."""
        logger.info("Collecting memory artifacts")
        
        try:
            mem_dir = self.output_dir / "Memory_Artifacts"
            mem_dir.mkdir(parents=True, exist_ok=True)
            
            # Process list
            with open(mem_dir / 'process_list.txt', 'w') as f:
                for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info']):
                    try:
                        f.write(f"{proc.info}\n")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            # Network connections by process
            with open(mem_dir / 'process_connections.txt', 'w') as f:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        connections = proc.connections()
                        if connections:
                            f.write(f"Process {proc.info['name']} (PID: {proc.info['pid']}):\n")
                            for conn in connections:
                                f.write(f"  {conn}\n")
                            f.write("\n")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            # Open files by process
            with open(mem_dir / 'open_files.txt', 'w') as f:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        files = proc.open_files()
                        if files:
                            f.write(f"Process {proc.info['name']} (PID: {proc.info['pid']}):\n")
                            for file in files:
                                f.write(f"  {file}\n")
                            f.write("\n")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            self.files_collected += 3
            
        except Exception as e:
            logger.error(f"Error collecting memory artifacts: {str(e)}")
            self.errors_encountered += 1
    
    def collect_log_files(self) -> None:
        """Collect system and application log files."""
        logger.info("Collecting log files")
        
        try:
            logs_dir = self.output_dir / "Logs"
            logs_dir.mkdir(parents=True, exist_ok=True)
            
            log_locations = []
            
            if WINDOWS:
                # Windows Event Logs would require special handling
                log_locations.extend([
                    Path(os.getenv('WINDIR', 'C:\\Windows')) / 'System32' / 'winevt' / 'Logs',
                    Path(os.getenv('WINDIR', 'C:\\Windows')) / 'Logs'
                ])
            else:
                # Unix log files
                log_locations.extend([
                    Path('/var/log'),
                    Path('/var/adm'),
                    Path('/var/run'),
                    Path('/Library/Logs')  # macOS
                ])
            
            # Copy log files
            for log_location in log_locations:
                if log_location.exists():
                    for log_file in log_location.rglob('*'):
                        try:
                            if log_file.is_file():
                                dest_path = logs_dir / log_file.relative_to(log_location)
                                dest_path.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(log_file, dest_path)
                                self.files_collected += 1
                        except Exception as e:
                            logger.warning(f"Could not copy log file {log_file}: {str(e)}")
                            continue
            
        except Exception as e:
            logger.error(f"Error collecting log files: {str(e)}")
            self.errors_encountered += 1
    
    def generate_timeline(self) -> None:
        """Generate a comprehensive timeline of system events."""
        logger.info("Generating forensic timeline")
        
        try:
            timeline = []
            
            # Process file system timestamps
            for root, _, files in os.walk(str(self.output_dir)):
                for file in files:
                    if len(timeline) > MAX_TIMELINE_EVENTS:
                        break
                    try:
                        file_path = Path(root) / file
                        stat = file_path.stat()
                        
                        timeline.append({
                            'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'type': 'file_modification',
                            'path': str(file_path.relative_to(self.output_dir)),
                            'size': stat.st_size
                        })
                        
                        timeline.append({
                            'timestamp': datetime.fromtimestamp(stat.st_atime).isoformat(),
                            'type': 'file_access',
                            'path': str(file_path.relative_to(self.output_dir)),
                            'size': stat.st_size
                        })
                        
                        timeline.append({
                            'timestamp': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            'type': 'file_creation',
                            'path': str(file_path.relative_to(self.output_dir)),
                            'size': stat.st_size
                        })
                    except Exception:
                        continue
            
            # Process log entries
            for log_file in (self.output_dir / "Logs").rglob('*'):
                if log_file.is_file():
                    try:
                        with open(log_file, 'r', errors='ignore') as f:
                            for line in f:
                                if len(line) > 20:
                                    # Simple timestamp extraction (would be more sophisticated in production)
                                    timeline.append({
                                        'timestamp': line[:20],
                                        'type': 'log_entry',
                                        'source': str(log_file.relative_to(self.output_dir)),
                                        'entry': line.strip()})
                    except Exception:
                        continue
            
            # Process registry timestamps (Windows)
            if WINDOWS:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion") as key:
                        timestamp = winreg.QueryInfoKey(key)[2]  # Last write time
                        timeline.append({
                            'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                            'type': 'registry_modification',
                            'key': r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion"
                        })
                except WindowsError:
                    pass
            
            # Sort timeline by timestamp
            timeline.sort(key=lambda x: x['timestamp'])

            # Save timeline
            timeline_csv = self.output_dir / "Timeline" / TIMELINE_FILE
            if timeline:
                # Collect all fieldnames
                fieldnames = set()
                for entry in timeline:
                    fieldnames.update(entry.keys())
                fieldnames = list(fieldnames)
                with open(timeline_csv, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(timeline)
            
            logger.info(f"Generated timeline with {len(timeline)} events")
            self.files_collected += 1
            
        except Exception as e:
            logger.error(f"Error generating timeline: {str(e)}")
            self.errors_encountered += 1
    
    def perform_ml_analysis(self) -> None:
        """Perform advanced machine learning analysis on collected data."""
        logger.info("Starting advanced machine learning analysis")
        try:
            features = self._prepare_ml_features()
            logger.debug(f"ML features prepared: {len(features)}")
            if not features:
                logger.warning("No features prepared for ML analysis")
                return

            df = pd.DataFrame(features)
            # Encode categorical features
            for col in df.select_dtypes(include=['object']).columns:
                df[col] = self.label_encoder.fit_transform(df[col].astype(str))

            # Use only original features for model fitting
            feature_cols = [col for col in df.columns if col not in ('label', 'anomaly_score', 'anomaly')]
            X = df[feature_cols]

            # Use IsolationForest for anomaly detection
            model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            model.fit(X)
            df['anomaly_score'] = model.decision_function(X)
            df['anomaly'] = model.predict(X)  # -1 = anomaly, 1 = normal

            # Save the model
            model_path = self.output_dir / "ML_Models" / ML_MODEL_FILE
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)

            # Save anomaly results (including anomaly columns)
            anomaly_csv = self.output_dir / "ML_Models" / "ml_anomalies.csv"
            df.to_csv(anomaly_csv, index=False)

            # Generate feature importance plot (IsolationForest uses feature_importances_ if available)
            if hasattr(model, "feature_importances_"):
                self._plot_feature_importance(model, feature_cols)

            logger.info(f"ML analysis complete. Anomalies found: {(df['anomaly'] == -1).sum()}")
            self.files_collected += 1

        except Exception as e:
            logger.error(f"Error in advanced machine learning analysis: {str(e)}")
            self.errors_encountered += 1
    
    def _prepare_ml_features(self) -> List[Dict]:
        """Prepare features for machine learning analysis."""
        features = []
        
        try:
            # File anomalies
            for suspicious in self.suspicious_files:
                features.append({
                    'type': 'file_anomaly',
                    'anomaly_count': len(suspicious['anomalies']),
                    'size': suspicious['size'],
                    'days_since_modified': (datetime.now() - datetime.fromisoformat(suspicious['modified'])).days,
                    'label': 'suspicious'
                })
            
            # Suspicious browser history
            browser_dir = self.output_dir / "Browser_Data"
            for browser in browser_dir.iterdir():
                for profile in browser.iterdir():
                    suspicious_history = profile / "suspicious_history.json"
                    if suspicious_history.exists():
                        with open(suspicious_history, 'r') as f:
                            flagged = json.load(f)
                            for entry in flagged:
                                features.append({
                                    'type': 'browser_history',
                                    'url': entry.get('url', ''),
                                    'title': entry.get('title', ''),
                                    'label': 'suspicious'
                                })
            
            # Recent files metadata
            recent_meta = self.output_dir / "System_Artifacts" / "Recent_Documents" / "recent_files_metadata.json"
            if recent_meta.exists():
                with open(recent_meta, 'r') as f:
                    for meta in json.load(f):
                        features.append({
                            'type': 'recent_file',
                            'name': meta['name'],
                            'size': meta['size'],
                            'days_since_modified': (datetime.now() - datetime.fromisoformat(meta['modified'])).days,
                            'label': 'normal'
                        })
            
            # Process and network anomalies as before...
            # (keep your existing code for processes and network)
        except Exception as e:
            logger.error(f"Error preparing ML features: {str(e)}")
            return []
        
        # If no features, add a dummy row so ML doesn't fail
        if not features:
            features.append({
                'type': 'dummy',
                'anomaly_count': 0,
                'size': 0,
                'days_since_modified': 0,
                'label': 'normal'
            })
        
        return features
    
    def _plot_feature_importance(self, model, feature_names) -> None:
        """Generate and save feature importance plot."""
        try:
            importances = model.feature_importances_
            indices = np.argsort(importances)[::-1]
            
            plt.figure(figsize=(10, 6))
            plt.title("Feature Importance")
            plt.bar(range(len(importances)), importances[indices], align="center")
            plt.xticks(range(len(importances)), [feature_names[i] for i in indices], rotation=45)
            plt.tight_layout()
            
            plot_path = self.output_dir / "ML_Models" / 'feature_importance.png'
            plt.savefig(plot_path)
            plt.close()
            
            self.files_collected += 1
        except Exception as e:
            logger.error(f"Error generating feature importance plot: {str(e)}")
    
    def generate_reports(self) -> None:
        """Generate comprehensive reports from collected data."""
        logger.info("Generating forensic reports")
        
        try:
            # Generate browser report
            self._generate_browser_report()
            
            # Generate USB report
            self._generate_usb_report()
            
            # Generate system report
            self._generate_system_report()
            
            # Generate network report
            self._generate_network_report()
            
            # Generate anti-forensic report
            self._generate_anti_forensic_report()
            
            # Generate ML report
            self._generate_ml_report()
            
            # Generate master report
            self._generate_master_report()
            
        except Exception as e:
            logger.error(f"Error generating reports: {str(e)}", exc_info=True)
            self.errors_encountered += 1
    
    def _generate_browser_report(self) -> None:
        """Generate browser artifacts report with enhanced details."""
        report_path = self.output_dir / "Reports" / "browser_report.html"
        
        # Load template environment
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('browser_report_template.html') if Path('browser_report_template.html').exists() else None
        
        browser_data = []
        browser_dir = self.output_dir / "Browser_Data"
        if browser_dir.exists():
            for browser in browser_dir.iterdir():
                if browser.is_dir():
                    browser_info = {
                        'name': browser.name,
                        'profiles': [],
                        'file_count': 0,
                        'total_size': 0
                    }
                    
                    for profile in browser.iterdir():
                        if profile.is_dir():
                            profile_info = {
                                'name': profile.name,
                                'files': [],
                                'size': 0
                            }
                            
                            for item in profile.glob('*'):
                                if item.is_file():
                                    stat = item.stat()
                                    profile_info['files'].append({
                                        'name': item.name,
                                        'size': stat.st_size,
                                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                                    })
                                    profile_info['size'] += stat.st_size
                            
                            browser_info['profiles'].append(profile_info)
                            browser_info['file_count'] += len(profile_info['files'])
                            browser_info['total_size'] += profile_info['size']
                    
                    browser_data.append(browser_info)
        
        if template:
            # Render from template
            html = template.render(
                title="Browser Artifacts Report",
                browsers=browser_data,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                version=VERSION
            )
        else:
            # Fallback to simple HTML
            html = "<html><head><title>Browser Artifacts Report</title></head><body>"
            html += "<h1>Browser Artifacts Report</h1>"
            html += f"<p>Generated on {datetime.now()} by {AUTHOR} v{VERSION}</p>"
            
            if browser_data:
                html += "<h2>Collected Browser Data</h2>"
                for browser in browser_data:
                    html += f"<h3>{browser['name']}</h3>"
                    html += f"<p>Total Files: {browser['file_count']}, Total Size: {browser['total_size'] / 1024:.2f} KB</p>"
                    
                    for profile in browser['profiles']:
                        html += f"<h4>Profile: {profile['name']}</h4>"
                        html += "<table border='1'><tr><th>File</th><th>Size</th><th>Modified</th></tr>"
                        for file in profile['files']:
                            html += f"<tr><td>{file['name']}</td><td>{file['size']}</td><td>{file['modified']}</td></tr>"
                        html += "</table>"
            else:
                html += "<p>No browser data collected.</p>"
            
            html += "</body></html>"
        
        with open(report_path, 'w') as f:
            f.write(html)
            
        logger.info(f"Generated browser report at {report_path}")
        self.files_collected += 1
    
    def _generate_usb_report(self) -> None:
        """Generate USB devices report with enhanced details."""
        report_path = self.output_dir / "Reports" / "usb_report.html"
        
        usb_data = []
        usb_csv = self.output_dir / "USB_History" / f"usb_devices_{self.timestamp}.csv"
        if usb_csv.exists():
            try:
                usb_data = pd.read_csv(usb_csv).to_dict('records')
            except Exception:
                with open(usb_csv, 'r') as f:
                    reader = csv.DictReader(f)
                    usb_data = list(reader)
        
        # Columns to exclude
        exclude_fields = {
            'timestamp', 'serial_number', 'events', 'first_connected',
            'last_connected', 'vendor_id', 'product_id'
        }
        
        # Load template environment
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('usb_report_template.html') if Path('usb_report_template.html').exists() else None
        
        if template:
            # Render from template, filter fields in template if needed
            html = template.render(
                title="USB Devices Report",
                devices=[
                    {k: v for k, v in device.items() if k not in exclude_fields}
                    for device in usb_data
                ],
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                version=VERSION
            )
        else:
            # Fallback to simple HTML
            html = "<html><head><title>USB Devices Report</title></head><body>"
            html += "<h1>USB Devices Report</h1>"
            html += f"<p>Generated on {datetime.now()} by {AUTHOR} v{VERSION}</p>"
            
            if usb_data:
                # Filter out excluded fields from headers
                headers = [h for h in usb_data[0].keys() if h not in exclude_fields]
                html += "<table border='1'><tr>"
                for header in headers:
                    html += f"<th>{header}</th>"
                html += "</tr>"
                
                for device in usb_data:
                    html += "<tr>"
                    for header in headers:
                        html += f"<td>{device.get(header, '')}</td>"
                    html += "</tr>"
                html += "</table>"
            else:
                html += "<p>No USB device data collected.</p>"
            
            html += "</body></html>"
        
        with open(report_path, 'w') as f:
            f.write(html)
            
        logger.info(f"Generated USB report at {report_path}")
        self.files_collected += 1
    
    def _generate_system_report(self) -> None:
        """Generate system artifacts report with enhanced details."""
        report_path = self.output_dir / "Reports" / "system_report.html"
        
        # Load template environment
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('system_report_template.html') if Path('system_report_template.html').exists() else None
        
        # System info
        system_info = self.system_info
        
        # Recent documents
        recent_docs = []
        recent_dir = self.output_dir / "System_Artifacts" / "Recent_Documents"
        if recent_dir.exists():
            for item in recent_dir.iterdir():
                if item.is_file():
                    stat = item.stat()
                    recent_docs.append({
                        'name': item.name,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
        
        # Scheduled tasks
        scheduled_tasks = []
        tasks_dir = self.output_dir / "System_Artifacts" / "Scheduled_Tasks"
        if tasks_dir.exists():
            for item in tasks_dir.iterdir():
                if item.is_file():
                    scheduled_tasks.append(item.name)
        
        if template:
            # Render from template
            html = template.render(
                title="System Artifacts Report",
                system_info=system_info,
                recent_docs=recent_docs,
                scheduled_tasks=scheduled_tasks,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                version=VERSION
            )
        else:
            # Fallback to simple HTML
            html = "<html><head><title>System Artifacts Report</title></head><body>"
            html += "<h1>System Artifacts Report</h1>"
            html += f"<p>Generated on {datetime.now()} by {AUTHOR} v{VERSION}</p>"
            
            # System info
            html += "<h2>System Information</h2>"
            for key, value in system_info.items():
                html += f"<p><strong>{key}:</strong> {value}</p>"
            
            # Recent documents
            if recent_docs:
                html += "<h2>Recent Documents</h2>"
                html += "<table border='1'><tr><th>File</th><th>Size</th><th>Modified</th></tr>"
                for doc in recent_docs:
                    html += f"<tr><td>{doc['name']}</td><td>{doc['size']}</td><td>{doc['modified']}</td></tr>"
                html += "</table>"
            
            # Scheduled tasks
            if scheduled_tasks:
                html += "<h2>Scheduled Tasks</h2><ul>"
                for task in scheduled_tasks:
                    html += f"<li>{task}</li>"
                html += "</ul>"
            
            html += "</body></html>"
        
        with open(report_path, 'w') as f:
            f.write(html)
            
        logger.info(f"Generated system report at {report_path}")
        self.files_collected += 1
    
    def _generate_network_report(self) -> None:
        """Generate network forensic report."""
        report_path = self.output_dir / "Reports" / "network_report.html"
        
        # Collect network data
        connections = []
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED':
                connections.append({
                    'family': conn.family.name,
                    'type': conn.type.name,
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
        
        # Load template environment
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('network_report_template.html') if Path('network_report_template.html').exists() else None
        
        if template:
            # Render from template
            html = template.render(
                title="Network Forensic Report",
                connections=connections,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                version=VERSION
            )
        else:
            # Fallback to simple HTML
            html = "<html><head><title>Network Forensic Report</title></head><body>"
            html += "<h1>Network Forensic Report</h1>"
            html += f"<p>Generated on {datetime.now()} by {AUTHOR} v{VERSION}</p>"
            
            if connections:
                html += "<h2>Active Connections</h2>"
                html += "<table border='1'><tr><th>Protocol</th><th>Local Address</th><th>Remote Address</th><th>Status</th><th>PID</th></tr>"
                for conn in connections:
                    html += f"<tr><td>{conn['family']}</td><td>{conn['local_address']}</td><td>{conn['remote_address'] or 'N/A'}</td><td>{conn['status']}</td><td>{conn['pid']}</td></tr>"
                html += "</table>"
            else:
                html += "<p>No active connections found.</p>"
            
            html += "</body></html>"
        
        with open(report_path, 'w') as f:
            f.write(html)
            
        logger.info(f"Generated network report at {report_path}")
        self.files_collected += 1
    
    def _generate_anti_forensic_report(self) -> None:
        """Generate anti-forensic detection report."""
        report_path = self.output_dir / "Reports" / "anti_forensic_report.html"
        
        # Load findings
        findings = {
            'anti_forensic_detected': self.anti_forensic_detected,
            'suspicious_files': self.suspicious_files,
            'timestamp': self.timestamp
        }
        
        # Load template environment
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('anti_forensic_report_template.html') if Path('anti_forensic_report_template.html').exists() else None
        
        if template:
            # Render from template
            html = template.render(
                title="Anti-Forensic Detection Report",
                findings=findings,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                version=VERSION
            )
        else:
            # Fallback to simple HTML
            html = "<html><head><title>Anti-Forensic Detection Report</title></head><body>"
            html += "<h1>Anti-Forensic Detection Report</h1>"
            html += f"<p>Generated on {datetime.now()} by {AUTHOR} v{VERSION}</p>"
            
            html += f"<h2>Summary</h2><p>Anti-forensic techniques detected: {'Yes' if findings['anti_forensic_detected'] else 'No'}</p>"
            
            if findings['suspicious_files']:
                html += "<h2>Suspicious Files</h2>"
                html += "<table border='1'><tr><th>File</th><th>Anomalies</th><th>Size</th><th>Modified</th></tr>"
                for file in findings['suspicious_files']:
                    html += f"<tr><td>{file['path']}</td><td>{', '.join(file['anomalies'])}</td><td>{file['size']}</td><td>{file['modified']}</td></tr>"
                html += "</table>"
            else:
                html += "<p>No suspicious files detected.</p>"
            
            html += "</body></html>"
        
        with open(report_path, 'w') as f:
            f.write(html)
            
        logger.info(f"Generated anti-forensic report at {report_path}")
        self.files_collected += 1
    
    def _generate_ml_report(self) -> None:
        """Generate machine learning analysis report."""
        report_path = self.output_dir / "Reports" / "ml_report.html"
        model_path = self.output_dir / "ML_Models" / ML_MODEL_FILE
        anomaly_csv = self.output_dir / "ML_Models" / "ml_anomalies.csv"
        if not model_path.exists():
            logger.warning("No ML model found for reporting")
            return

        # Load model
        with open(model_path, 'rb') as f:
            model = pickle.load(f)

        # Load anomaly results
        anomalies = []
        all_rows = []
        if anomaly_csv.exists():
            try:
                df = pd.read_csv(anomaly_csv)
                anomalies = df[df['anomaly'] == -1].to_dict('records')
                all_rows = df.to_dict('records')
            except Exception as e:
                logger.error(f"Error loading ML anomalies: {str(e)}")

        html = "<html><head><title>Machine Learning Analysis Report</title></head><body>"
        html += "<h1>Machine Learning Analysis Report</h1>"
        html += f"<p>Generated on {datetime.now()} by {AUTHOR} v{VERSION}</p>"
        html += f"<h2>Model Information</h2>"
        html += f"<p>Model type: {type(model).__name__}</p>"
        html += f"<p>Number of estimators: {getattr(model, 'n_estimators', 'N/A')}</p>"

        if anomalies:
            html += "<h2>Flagged Anomalies</h2><table border='1'><tr>"
            for key in anomalies[0].keys():
                html += f"<th>{key}</th>"
            html += "</tr>"
            for row in anomalies:
                html += "<tr>" + "".join(f"<td>{row[k]}</td>" for k in anomalies[0].keys()) + "</tr>"
            html += "</table>"
        else:
            html += "<p>No anomalies detected by ML model.</p>"

        # Always show all analyzed rows for transparency
        if all_rows:
            html += "<h2>All Analyzed Entries</h2><table border='1'><tr>"
            for key in all_rows[0].keys():
                html += f"<th>{key}</th>"
            html += "</tr>"
            for row in all_rows:
                html += "<tr>" + "".join(f"<td>{row[k]}</td>" for k in all_rows[0].keys()) + "</tr>"
            html += "</table>"

        html += "</body></html>"

        with open(report_path, 'w') as f:
            f.write(html)
        logger.info(f"Generated ML report at {report_path}")
        self.files_collected += 1
    
    def _generate_master_report(self) -> None:
        """Generate master summary report with links to all sub-reports."""
        report_path = self.output_dir / "Reports" / "forensic_report.html"
        
        # Load template environment
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('master_report_template.html') if Path('master_report_template.html').exists() else None
        
        reports = [
            {'name': 'Browser Artifacts', 'path': 'browser_report.html'},
            {'name': 'USB Devices', 'path': 'usb_report.html'},
            {'name': 'System Artifacts', 'path': 'system_report.html'},
            {'name': 'Network Forensics', 'path': 'network_report.html'},
            {'name': 'Anti-Forensic Detection', 'path': 'anti_forensic_report.html'},
            {'name': 'Machine Learning Analysis', 'path': 'ml_report.html'},
            # {'name': 'Forensic Timeline', 'path': f'../Timeline/{TIMELINE_FILE}'},  # Remove or comment out
        ]
        
        if template:
            # Render from template
            html = template.render(
                title="Digital Forensic Report",
                reports=reports,
                files_collected=self.files_collected,
                errors_encountered=self.errors_encountered,
                suspicious_files=len(self.suspicious_files),
                anti_forensic_detected=self.anti_forensic_detected,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                version=VERSION
            )
        else:
            # Fallback to simple HTML
            html = "<html><head><title>Digital Forensic Report</title></head><body>"
            html += f"<h1>Digital Forensic Report</h1>"
            html += f"<p>Generated on {datetime.now()} by {AUTHOR} v{VERSION}</p>"
            
            # Summary
            html += "<h2>Collection Summary</h2>"
            html += f"<p>Files Collected: {self.files_collected}</p>"
            html += f"<p>Errors Encountered: {self.errors_encountered}</p>"
            html += f"<p>Suspicious Files Detected: {len(self.suspicious_files)}</p>"
            html += f"<p>Anti-Forensic Techniques Detected: {'Yes' if self.anti_forensic_detected else 'No'}</p>"
            
            # Links to sub-reports
            html += "<h2>Detailed Reports</h2>"
            html += "<ul>"
            for report in reports:
                html += f'<li><a href="{report["path"]}">{report["name"]} Report</a></li>'
            html += "</ul>"
            
            html += "</body></html>"
        
        with open(report_path, 'w') as f:
            f.write(html)
            
        logger.info(f"Generated master report at {report_path}")
        self.files_collected += 1
    
    def package_results(self) -> None:
        """Package all results into a zip file and generate a hash for the zip only."""
        zip_path = self.output_dir.parent / f"forensic_collection_{self.timestamp}.zip"
        try:
            # Create a manifest of all files (without hashes)
            manifest = []
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(self.output_dir):
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(self.output_dir.parent)
                        zipf.write(file_path, arcname)
                        manifest.append({
                            'path': str(arcname),
                            'size': file_path.stat().st_size,
                            'modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                        })
                # Add manifest to zip
                manifest_str = json.dumps(manifest, indent=4)
                zipf.writestr('collection_manifest.json', manifest_str)

            # Verify zip integrity
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                if zipf.testzip() is not None:
                    raise ValueError("Zip file integrity check failed")

            # Calculate and save hash for the zip file only
            zip_hash = self._calculate_file_hash(zip_path)
            hash_log_path = zip_path.with_suffix('.zip.hash.txt')
            with open(hash_log_path, 'w') as f:
                f.write(f"{zip_path.name}: {zip_hash}\n")

            logger.info(f"Created forensic package at {zip_path}")
            logger.info(f"Zip file hash ({self.hash_algorithm}): {zip_hash}")
            self.files_collected += 1

        except Exception as e:
            logger.error(f"Error creating zip package: {str(e)}")
            self.errors_encountered += 1
    
    def _calculate_file_hash(self, file_path: Path) -> Optional[str]:
        """Calculate hash of a file."""
        try:
            hasher = hashlib.new(self.hash_algorithm)
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.warning(f"Could not hash file {file_path}: {str(e)}")
            return None
    
    def _get_file_hash_from_log(self, file_path: Path, log_file: Path) -> Optional[str]:
        """Get file hash from log file if exists."""
        if not log_file.exists():
            return None
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if file_path.name in line and ': ' in line:
                        return line.split(': ')[1].strip()
        except Exception:
            return None
        return None
    
    def _create_hash_log(self, file_path: Path, log_file: Path) -> None:
        """Create hash log entry for a file."""
        try:
            file_hash = self._calculate_file_hash(file_path)
                    
            with open(log_file, 'a') as f:
                f.write(f"{file_path.name}: {file_hash}\n")
                
        except Exception as e:
            logger.error(f"Error creating hash for {file_path}: {str(e)}")
            self.errors_encountered += 1
    
    def _save_usb_data(self, usb_data: List) -> None:
        """Save collected USB data to CSV."""
        if not usb_data:
            logger.warning("No USB data to save")
            return
        
        usb_csv = self.output_dir / "USB_History" / f"usb_devices_{self.timestamp}.csv"
        
        try:
            # Collect all unique fieldnames
            fieldnames = set()
            for d in usb_data:
                fieldnames.update(d.keys())
            fieldnames = list(fieldnames)
            with open(usb_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(usb_data)
            logger.info(f"Saved USB data to {usb_csv}")
            self.files_collected += 1
        except Exception as e:
            logger.error(f"Error saving USB data: {str(e)}")
            self.errors_encountered += 1

    def _enumerate_usb_devices(self, key, usb_data: List, key_type: str) -> None:
        """Enumerate USB devices from registry key (Windows)."""
        try:
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        for j in range(winreg.QueryInfoKey(subkey)[0]):
                            try:
                                device_key_name = winreg.EnumKey(subkey, j)
                                with winreg.OpenKey(subkey, device_key_name) as device_key:
                                    device_data = {
                                        'type': key_type,
                                        'device_id': subkey_name,
                                        'instance_id': device_key_name,
                                        'first_connected': None,
                                        'last_connected': None,
                                        'friendly_name': None,
                                        'vendor_id': None,
                                        'product_id': None,
                                        'serial_number': None
                                    }
                                    # Try to get additional info
                                    try:
                                        device_data['friendly_name'] = winreg.QueryValueEx(device_key, "FriendlyName")[0]
                                    except OSError:
                                        pass
                                    # Try to get timestamps (custom logic, may need adjustment)
                                    # device_data['first_connected'] = self._get_device_timestamp(device_key_name)
                                    # Parse VID/PID if available
                                    if key_type == 'USBSTOR':
                                        parts = subkey_name.split('&')
                                        for part in parts:
                                            if part.startswith('VID_'):
                                                device_data['vendor_id'] = part[4:]
                                            elif part.startswith('PID_'):
                                                device_data['product_id'] = part[4:]
                                    usb_data.append(device_data)
                            except Exception as e:
                                logger.error(f"Error processing USB device instance: {str(e)}")
                                self.errors_encountered += 1
                                continue
                except Exception as e:
                    logger.error(f"Error processing USB device: {str(e)}")
                    self.errors_encountered += 1
                    continue
        except Exception as e:
            logger.error(f"Error enumerating USB devices: {str(e)}")
            self.errors_encountered += 1

    def _parse_udev_database(self, db_path: Path, usb_data: List) -> None:
        """Parse Linux udev database for USB devices."""
        try:
            conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT devpath, subsystem, sysname, devnode, env_key, env_value 
                FROM device_properties
                WHERE subsystem='usb' OR subsystem='usb_device'
            """)
            devices = {}
            for row in cursor.fetchall():
                devpath, subsystem, sysname, devnode, env_key, env_value = row
                if devpath not in devices:
                    devices[devpath] = {
                        'devpath': devpath,
                        'subsystem': subsystem,
                        'sysname': sysname,
                        'devnode': devnode,
                        'properties': {}
                    }
                devices[devpath]['properties'][env_key] = env_value
            for device in devices.values():
                usb_data.append({
                    'type': 'Linux',
                    'device_id': device['devpath'],
                    'vendor_id': device['properties'].get('ID_VENDOR_ID'),
                    'product_id': device['properties'].get('ID_MODEL_ID'),
                    'vendor': device['properties'].get('ID_VENDOR_FROM_DATABASE'),
                    'product': device['properties'].get('ID_MODEL_FROM_DATABASE'),
                    'serial': device['properties'].get('ID_SERIAL_SHORT'),
                    'connected': device['properties'].get('USEC_INITIALIZED')
                })
            conn.close()
        except Exception as e:
            logger.error(f"Error parsing udev database: {str(e)}")
            self.errors_encountered += 1

    def _parse_log_for_usb(self, log_path: Path, usb_data: List) -> None:
        """Parse system logs for USB connection events."""
        try:
            with open(log_path, 'r', errors='ignore') as f:
                for line in f:
                    if 'usb' in line.lower():
                        timestamp = line[:15]  # Simple timestamp extraction
                        usb_data.append({
                            'type': 'LogEntry',
                            'log_file': log_path.name,
                            'timestamp': timestamp,
                            'entry': line.strip()
                        })
        except Exception as e:
            logger.error(f"Error parsing log file {log_path}: {str(e)}")
            self.errors_encountered += 1

    def _parse_macos_ioreg(self, usb_data: List) -> None:
        """Parse macOS IO Registry for USB devices."""
        try:
            ioreg = os.popen('ioreg -p IOUSB -l -w 0').read()
            current_device = {}
            for line in ioreg.splitlines():
                line = line.strip()
                if line.startswith('+-o'):
                    if current_device:
                        usb_data.append(current_device)
                        current_device = {}
                    parts = line.split(' ')
                    if len(parts) > 1:
                        current_device['name'] = parts[1].strip('"')
                elif '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip().strip('"')
                    value = value.strip().strip('"')
                    current_device[key] = value
            if current_device:
                usb_data.append(current_device)
        except Exception as e:
            logger.error(f"Error parsing macOS IO Registry: {str(e)}")
            self.errors_encountered += 1

    def _scan_browser_history_for_suspicious(self, browser_history: List[Dict]) -> List[Dict]:
        """Scan browser history for suspicious/illegal website visits."""
        flagged = []
        for entry in browser_history:
            url = entry.get('url', '').lower()
            title = entry.get('title', '').lower()
            if any(kw in url or kw in title for kw in SUSPICIOUS_KEYWORDS) or \
               any(domain in url for domain in SUSPICIOUS_DOMAINS):
                flagged.append(entry)
        return flagged

    def _extract_browser_history(self, browser: str, profile_path: Path) -> List[Dict]:
        """Extract browser history from supported browsers (Chrome/Edge/Brave/Opera/Firefox)."""
        history = []
        try:
            if browser in ['Chrome', 'Edge', 'Brave', 'Opera']:
                db_path = profile_path / 'History'
                if db_path.exists():
                    conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url, title, last_visit_time FROM urls")
                    for url, title, last_visit_time in cursor.fetchall():
                        # Chrome stores time as microseconds since 1601-01-01
                        try:
                            visit_time = datetime(1601, 1, 1) + timedelta(microseconds=last_visit_time)
                            visit_time = visit_time.isoformat()
                        except Exception:
                            visit_time = None
                        history.append({'url': url, 'title': title, 'visit_time': visit_time})
                    conn.close()
            elif browser == 'Firefox':
                db_path = profile_path / 'places.sqlite'
                if db_path.exists():
                    conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url, title, last_visit_date FROM moz_places")
                    for url, title, last_visit_date in cursor.fetchall():
                        try:
                            visit_time = datetime.fromtimestamp(last_visit_date / 1_000_000).isoformat() if last_visit_date else None
                        except Exception:
                            visit_time = None
                        history.append({'url': url, 'title': title, 'visit_time': visit_time})
                    conn.close()
        except Exception as e:
            logger.error(f"Error extracting browser history for {browser}: {str(e)}")
        return history

    def hash_directory(self, directory: Path, hash_algorithm: str = None) -> str:
        """Calculate a single hash for all files in a directory (recursively)."""
        if hash_algorithm is None:
            hash_algorithm = self.hash_algorithm
        hasher = hashlib.new(hash_algorithm)
        total_files = 0
        hashed_files = 0
        for file_path in sorted(directory.rglob('*')):
            if file_path.is_file():
                total_files += 1
                try:
                    with open(file_path, 'rb') as f:
                        while True:
                            chunk = f.read(8192)
                            if not chunk:
                                break
                            hasher.update(chunk)
                    hasher.update(str(file_path.relative_to(directory)).encode())
                    hashed_files += 1
                except Exception as e:
                    logger.warning(f"Could not hash file {file_path}: {str(e)}")
        if hashed_files < total_files:
            logger.warning(f"Hashed {hashed_files} out of {total_files} files. Some files could not be read (permissions?).")
        else:
            logger.info(f"All {hashed_files} files hashed successfully.")
        return hasher.hexdigest()

class ForensicGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Digital Forensic Tool")
        self.progress = tk.DoubleVar()
        self.status = tk.StringVar(value="Ready")
        self.create_widgets()
        self.thread = None

    def create_widgets(self):
        tk.Label(self.root, text="Advanced Digital Forensic Tool", font=("Arial", 16)).pack(pady=10)
        self.progressbar = ttk.Progressbar(self.root, variable=self.progress, maximum=100)
        self.progressbar.pack(fill='x', padx=20, pady=10)
        self.status_label = tk.Label(self.root, textvariable=self.status)
        self.status_label.pack(pady=5)
        self.start_btn = tk.Button(self.root, text="Start Collection", command=self.start_collection)
        self.start_btn.pack(pady=10)
        self.quit_btn = tk.Button(self.root, text="Quit", command=self.root.quit)
        self.quit_btn.pack(pady=5)

    def start_collection(self):
        self.start_btn.config(state='disabled')
        self.status.set("Starting collection...")
        self.thread = threading.Thread(target=self.run_collection)
        self.thread.start()
        self.root.after(100, self.check_thread)

    def check_thread(self):
        if self.thread.is_alive():
            self.root.after(100, self.check_thread)
        else:
            self.status.set("Collection complete.")
            messagebox.showinfo("Done", "Forensic collection completed.")

    def run_collection(self):
        try:
            collector = ForensicCollector()
            phases = [
                ("Anti-forensic detection", collector.detect_anti_forensic),
                ("Browser artifacts", collector.collect_browser_artifacts),
                ("Installed software", collector.collect_installed_software),
                ("Network forensics", collector.collect_network_forensics),
                ("USB history", collector.collect_usb_history if WINDOWS else collector.collect_unix_usb_history),
                ("System artifacts", collector.collect_system_artifacts),
                ("Memory artifacts", collector.collect_memory_artifacts),
                ("Log files", collector.collect_log_files),
                ("Machine learning analysis", collector.perform_ml_analysis),
                ("Report generation", collector.generate_reports),
                #("Packaging results", collector.package_results)
            ]
            total = len(phases)
            for idx, (desc, func) in enumerate(phases, 1):
                percent = int((idx-1) / total * 100)
                self.progress.set(percent)
                self.status.set(f"{desc}...")
                self.root.update_idletasks()
                try:
                    func()
                except Exception as e:
                    logger.error(f"Error in phase '{desc}': {str(e)}", exc_info=True)
                    collector.errors_encountered += 1
            self.progress.set(100)
            self.status.set("Done.")
        except Exception as e:
            self.status.set(f"Fatal error: {str(e)}")
            logger.error(f"Fatal error in forensic collection: {str(e)}", exc_info=True)

def main():
    """Main entry point for the forensic tool with progress display."""
    parser = argparse.ArgumentParser(
        description=f"{AUTHOR} v{VERSION} - Advanced Digital Forensic Collection Tool"
    )
    parser.add_argument('-o', '--output', default="Forensic_Collection",
                       help="Output directory for collected artifacts")
    parser.add_argument('--no-zip', action='store_false', dest='zip_output',
                       help="Disable automatic zip packaging of results")
    parser.add_argument('-v', '--verbose', action='store_true',
                       help="Enable verbose logging")
    parser.add_argument('--hash', default=DEFAULT_HASH_ALGORITHM,
                       help=f"Hash algorithm to use (default: {DEFAULT_HASH_ALGORITHM})")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        collector = ForensicCollector(output_dir=args.output, zip_output=args.zip_output)
        collector.hash_algorithm = args.hash
        
        logger.info("Starting forensic collection...")
        start_time = time.time()

        # Define phases for progress
        phases = [
            ("Anti-forensic detection", collector.detect_anti_forensic),
            ("Browser artifacts", collector.collect_browser_artifacts),
            ("Installed software", collector.collect_installed_software),
            ("Network forensics", collector.collect_network_forensics),
            ("USB history", collector.collect_usb_history if WINDOWS else collector.collect_unix_usb_history),
            ("System artifacts", collector.collect_system_artifacts),
            ("Memory artifacts", collector.collect_memory_artifacts),
            ("Log files", collector.collect_log_files),
            ("Machine learning analysis", collector.perform_ml_analysis),
            ("Report generation", collector.generate_reports),
           # ("Packaging results", collector.package_results if args.zip_output else lambda: None)
        ]
        total = len(phases)
        for idx, (desc, func) in enumerate(phases, 1):
            elapsed = time.time() - start_time
            percent = int((idx-1) / total * 100)
            print(f"\r[{percent:3}%] {desc}... (Elapsed: {elapsed:.1f}s)", end='', flush=True)
            try:
                func()
            except Exception as e:
                logger.error(f"Error in phase '{desc}': {str(e)}", exc_info=True)
                collector.errors_encountered += 1
        print(f"\r[100%] Done. (Total time: {time.time() - start_time:.1f}s)           ")

        logger.info(f"Forensic collection completed in {time.time() - start_time:.2f} seconds")
        
        if collector.errors_encountered > 0:
            logger.warning(f"Completed with {collector.errors_encountered} errors")
        if collector.suspicious_files:
            logger.warning(f"Found {len(collector.suspicious_files)} suspicious files")
        if collector.anti_forensic_detected:
            logger.warning("Anti-forensic techniques detected!")
        
        # Calculate and log directory hash
        dir_hash = collector.hash_directory(Path(collector.output_dir))
        hash_file = Path(collector.output_dir).parent / f"{Path(collector.output_dir).name}.hash.txt"
        with open(hash_file, 'w') as f:
            f.write(f"{Path(collector.output_dir).name}: {dir_hash}\n")
        self.status.set(f"Done. Directory hash: {dir_hash}")
        logger.info(f"Directory hash ({collector.hash_algorithm}): {dir_hash}")
        
    except Exception as e:
        logger.error(f"Fatal error in forensic collection: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    if sys.platform.startswith('linux') and os.geteuid() != 0:
        logger.warning("For best results, run this tool as root on Linux.")
    root = tk.Tk()
    app = ForensicGUI(root)
    root.mainloop()
