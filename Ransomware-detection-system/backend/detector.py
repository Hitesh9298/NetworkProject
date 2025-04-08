import os
import sys
import time
import yara
import psutil
import shutil
import warnings
import pandas as pd
from sklearn.ensemble import IsolationForest
from flask import Flask, jsonify, request
from flask_cors import CORS
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import numpy as np
from datetime import datetime
from test_utils import generate_test_files, cleanup_test_files, TEST_DIR
import socket
import random

app = Flask(__name__)
CORS(app)

# Global variables with thread safety
DETECTION_RULES = {
    'file_activity': [],
    'process_activity': [],
    'network_activity': []
}

ALERTS = []
ALERTS_LOCK = threading.Lock()
DETECTION_MODEL = None
BASELINE_STATS = {}
BLOCK_MODE = True

# Directory paths
QUARANTINE_DIR = os.path.join(os.path.dirname(__file__), 'quarantine')

# YARA rules
yara_rules = """
rule ransomware_indicators {
    meta:
        description = "Detects common ransomware patterns"
    strings:
        $encryption_keywords = { 6A 40 68 00 30 00 00 6A 14 8D 91 }
        $ransom_note = "HOW_TO_DECRYPT" nocase
        $extension_change = /\\.[a-zA-Z0-9]{5,10}$/
    condition:
        any of them
}
"""
compiled_yara_rules = yara.compile(source=yara_rules)

class FileEventHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.last_alert_times = {}
        self.alert_rate_limit = 5  # Max alerts per minute per file

    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def process_file(self, file_path):
        # Count recent alerts for this file
        now = time.time()
        recent_alerts = [t for t in self.last_alert_times.get(file_path, []) if now - t < 60]
        
        if len(recent_alerts) < self.alert_rate_limit:
            if self.is_suspicious_file(file_path):
                self.handle_malicious_file(file_path)
                self.last_alert_times.setdefault(file_path, []).append(now)

    def is_suspicious_file(self, file_path):
        # Skip system and application directories
        excluded_dirs = [
            os.path.expanduser('~\\AppData'),
            'Windows\\System32',
            'Program Files',
            'Program Files (x86)',
            'node_modules',
            'Microsoft VS Code',
            'MSTeams',
            'Google\\Chrome',
            'BraveSoftware\\Brave-Browser',
            'Local\\Temp'
        ]
        
        # Normalize path for comparison
        normalized_path = os.path.normpath(file_path).lower()
        
        if any(excluded_dir.lower() in normalized_path for excluded_dir in excluded_dirs):
            return False
            
        # Check extensions
        suspicious_extensions = ('.encrypted', '.locked', '.crypt', '.ransom', '.cryp1', '.locky')
        if file_path.lower().endswith(suspicious_extensions):
            return True
            
        # Check YARA rules
        try:
            if compiled_yara_rules.match(filepath=file_path):
                return True
        except:
            pass
            
        # Check rapid modification
        try:
            stat = os.stat(file_path)
            if time.time() - stat.st_mtime < 2 and os.path.getsize(file_path) > 102400:
                return True
        except:
            pass
            
        return False

    def handle_malicious_file(self, file_path):
        now = time.time()
        action = "Detected"
        
        if BLOCK_MODE:
            try:
                os.makedirs(QUARANTINE_DIR, exist_ok=True)
                base_name = os.path.basename(file_path)
                quarantine_path = os.path.join(QUARANTINE_DIR, f"{int(now)}_{base_name}")
                
                try:
                    if os.path.exists(file_path):
                        shutil.move(file_path, quarantine_path)
                        action = "Quarantined"
                except PermissionError:
                    action = "Detection only (file in use)"
                except Exception as e:
                    action = f"Quarantine failed: {str(e)}"
            except Exception as e:
                action = f"System error: {str(e)}"

        alert = {
            'type': 'file',
            'severity': 'high',
            'message': f'{action} suspicious file: {os.path.basename(file_path)}',
            'path': file_path,
            'timestamp': datetime.now().isoformat(),
            'action_taken': action
        }
        
        # Thread-safe alert addition
        with ALERTS_LOCK:
            if not any(a.get('path') == file_path and 
                      (now - datetime.fromisoformat(a['timestamp']).timestamp()) < 60 
                      for a in ALERTS):
                ALERTS.append(alert)
                print(f"[ALERT] {alert['message']}")

def monitor_file_system():
    event_handler = FileEventHandler()
    observer = Observer()
    
    # Monitor test directory
    try:
        os.makedirs(TEST_DIR, exist_ok=True)
        observer.schedule(event_handler, TEST_DIR, recursive=True)
        print(f"[MONITOR] Watching test directory: {TEST_DIR}")
    except Exception as e:
        print(f"[ERROR] Failed to monitor test directory: {e}")

    # Monitor system drives
    for drive in psutil.disk_partitions():
        try:
            if not any(excluded in drive.mountpoint.lower() 
                      for excluded in ['windows', 'program files']):
                observer.schedule(event_handler, drive.mountpoint, recursive=True)
                print(f"[MONITOR] Watching drive: {drive.mountpoint}")
        except Exception as e:
            print(f"[ERROR] Failed to monitor {drive.mountpoint}: {e}")
    
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def monitor_processes():
    baseline_cpu = psutil.cpu_percent(interval=1)
    BASELINE_STATS['cpu'] = baseline_cpu
    
    while True:
        time.sleep(5)
        current_cpu = psutil.cpu_percent(interval=1)
        
        if current_cpu > baseline_cpu * 2:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                if proc.info['cpu_percent'] > 30:
                    action = "Detected"
                    if BLOCK_MODE:
                        try:
                            proc.kill()
                            action = "Terminated"
                        except:
                            action = "Failed to terminate"
                    
                    alert = {
                        'type': 'process',
                        'severity': 'high',
                        'message': f'{action} high-CPU process: {proc.info["name"]} (PID: {proc.info["pid"]}, CPU: {proc.info["cpu_percent"]}%)',
                        'timestamp': datetime.now().isoformat(),
                        'action_taken': action
                    }
                    
                    with ALERTS_LOCK:
                        ALERTS.append(alert)
                    print(f"[ALERT] {alert['message']}")

def monitor_network():
    baseline_network = psutil.net_io_counters()
    BASELINE_STATS['network'] = {
        'bytes_sent': baseline_network.bytes_sent,
        'bytes_recv': baseline_network.bytes_recv
    }
    
    while True:
        time.sleep(10)
        current_network = psutil.net_io_counters()
        
        sent_diff = current_network.bytes_sent - BASELINE_STATS['network']['bytes_sent']
        recv_diff = current_network.bytes_recv - BASELINE_STATS['network']['bytes_recv']
        
        if sent_diff > 10 * 1024 * 1024 or recv_diff > 10 * 1024 * 1024:
            alert = {
                'type': 'network',
                'severity': 'high',
                'message': f'Unusual network activity detected: Sent {sent_diff/1024/1024:.2f}MB, Received {recv_diff/1024/1024:.2f}MB',
                'timestamp': datetime.now().isoformat(),
                'action_taken': 'Detected'
            }
            
            with ALERTS_LOCK:
                ALERTS.append(alert)
            print(f"[ALERT] {alert['message']}")
        
        BASELINE_STATS['network'] = {
            'bytes_sent': current_network.bytes_sent,
            'bytes_recv': current_network.bytes_recv
        }

def train_anomaly_detection():
    """Train the machine learning model for anomaly detection"""
    np.random.seed(42)
    normal_data = np.random.normal(50, 10, (100, 3))
    anomaly_data = np.random.normal(150, 30, (10, 3))
    X = np.vstack([normal_data, anomaly_data])
    global DETECTION_MODEL
    DETECTION_MODEL = IsolationForest(contamination=0.1, random_state=42)
    DETECTION_MODEL.fit(X)
    print("[MODEL] Anomaly detection model trained")

def start_monitoring():
    """Start all monitoring threads"""
    def start_file_monitoring():
        monitor_file_system()
        
    def start_process_monitoring():
        monitor_processes()
        
    def start_network_monitoring():
        monitor_network()

    fs_thread = threading.Thread(target=start_file_monitoring, daemon=True)
    proc_thread = threading.Thread(target=start_process_monitoring, daemon=True)
    net_thread = threading.Thread(target=start_network_monitoring, daemon=True)
    
    fs_thread.start()
    proc_thread.start()
    net_thread.start()
    print("[SYSTEM] Monitoring threads started")

# API Endpoints
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    with ALERTS_LOCK:
        return jsonify(ALERTS)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    stats = {
        'cpu': psutil.cpu_percent(interval=1),
        'memory': psutil.virtual_memory().percent,
        'network': psutil.net_io_counters()._asdict()
    }
    return jsonify(stats)

@app.route('/api/block_mode', methods=['POST'])
def set_block_mode():
    global BLOCK_MODE
    BLOCK_MODE = request.json.get('enabled', False)
    return jsonify({'status': 'success', 'block_mode': BLOCK_MODE})

@app.route('/api/test/create_files', methods=['POST'])
def create_test_files():
    try:
        print(f"[TEST] Attempting to create test files in: {TEST_DIR}")
        if not os.path.exists(TEST_DIR):
            os.makedirs(TEST_DIR, exist_ok=True)
            print(f"[TEST] Created test directory at: {TEST_DIR}")
        
        results = generate_test_files()
        print(f"[TEST] Test file creation results: {results}")
        return jsonify({
            'status': 'success',
            'results': results,
            'message': f'Test files created in {TEST_DIR}'
        })
    except Exception as e:
        print(f"[ERROR] Creating test files: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

        # Add to imports at the top
import socket
import random

# Add these new endpoints
@app.route('/api/test/network', methods=['POST'])
def test_network_activity():
    """Simulate suspicious network activity"""
    try:
        # Simulate large data transfer
        bytes_sent = random.randint(50*1024*1024, 100*1024*1024)  # 50-100 MB
        bytes_recv = random.randint(50*1024*1024, 100*1024*1024)  # 50-100 MB
        
        # Create an alert for the simulated activity
        alert = {
            'type': 'network',
            'severity': 'high',
            'message': f'Simulated network test: Sent {bytes_sent/1024/1024:.2f}MB, Received {bytes_recv/1024/1024:.2f}MB',
            'timestamp': datetime.now().isoformat(),
            'action_taken': 'Detected (Test)'
        }
        
        with ALERTS_LOCK:
            ALERTS.append(alert)
        
        return jsonify({
            'status': 'success',
            'stats': {
                'bytes_sent': bytes_sent,
                'bytes_recv': bytes_recv
            },
            'message': 'Network test executed successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/test/block_connection', methods=['POST'])
def test_block_connection():
    """Test blocking a malicious connection"""
    try:
        if not BLOCK_MODE:
            return jsonify({
                'status': 'success',
                'blocked': False,
                'message': 'Block mode is disabled - no action taken'
            })
        
        # Simulate blocking a connection
        malicious_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        
        alert = {
            'type': 'network',
            'severity': 'critical',
            'message': f'Blocked connection to malicious IP: {malicious_ip}',
            'timestamp': datetime.now().isoformat(),
            'action_taken': 'Blocked (Test)'
        }
        
        with ALERTS_LOCK:
            ALERTS.append(alert)
        
        return jsonify({
            'status': 'success',
            'blocked': True,
            'ip': malicious_ip,
            'message': f'Successfully blocked test connection to {malicious_ip}'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/test/cleanup', methods=['POST'])
def cleanup_test_files_endpoint():
    try:
        success = cleanup_test_files()
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Test files and quarantine cleaned up'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Partial cleanup completed with some errors'
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    # Create directories
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(TEST_DIR, exist_ok=True)
    
    # Train model
    train_anomaly_detection()
    
    # Start monitoring
    start_monitoring()
    
    # Start API
    print("[SYSTEM] Starting Ransomware Detection System...")
    app.run(host='0.0.0.0', port=5000)