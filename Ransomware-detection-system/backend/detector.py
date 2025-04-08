import os
import sys
import time
import yara
import psutil
import pandas as pd
from sklearn.ensemble import IsolationForest
from flask import Flask, jsonify, request
from flask_cors import CORS
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import numpy as np
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Global variables for detection
DETECTION_RULES = {
    'file_activity': [],
    'process_activity': [],
    'network_activity': []
}

ALERTS = []
DETECTION_MODEL = None
BASELINE_STATS = {}

# YARA rules for ransomware detection
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

# Initialize YARA rules
compiled_yara_rules = yara.compile(source=yara_rules)

class FileEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            if self.is_suspicious_file(event.src_path):
                alert = {
                    'type': 'file',
                    'severity': 'high',
                    'message': f'Suspicious file activity detected: {event.src_path}',
                    'timestamp': datetime.now().isoformat()
                }
                ALERTS.append(alert)
                print(f"[ALERT] {alert['message']}")

    def on_created(self, event):
        if not event.is_directory:
            if self.is_suspicious_file(event.src_path):
                alert = {
                    'type': 'file',
                    'severity': 'high',
                    'message': f'Suspicious file creation detected: {event.src_path}',
                    'timestamp': datetime.now().isoformat()
                }
                ALERTS.append(alert)
                print(f"[ALERT] {alert['message']}")

    def is_suspicious_file(self, file_path):
        # Check file extension changes
        if file_path.endswith('.encrypted') or file_path.endswith('.locked'):
            return True
        
        # Check with YARA rules
        try:
            matches = compiled_yara_rules.match(filepath=file_path)
            if matches:
                return True
        except:
            pass
        
        # Check for rapid file modifications
        file_stats = os.stat(file_path)
        if time.time() - file_stats.st_mtime < 5:  # Modified within last 5 seconds
            return True
            
        return False

def monitor_file_system():
    event_handler = FileEventHandler()
    observer = Observer()
    
    # Watch all drives (in a real system, you'd want to be more selective)
    for drive in psutil.disk_partitions():
        observer.schedule(event_handler, drive.mountpoint, recursive=True)
    
    observer.start()
    print("Starting file system monitoring...")
    
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
        
        # Detect unusual CPU usage
        if current_cpu > baseline_cpu * 2:  # If CPU usage doubled
            alert = {
                'type': 'process',
                'severity': 'medium',
                'message': f'Unusual CPU usage detected: {current_cpu}%',
                'timestamp': datetime.now().isoformat()
            }
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
        
        # Detect unusual network activity
        sent_diff = current_network.bytes_sent - BASELINE_STATS['network']['bytes_sent']
        recv_diff = current_network.bytes_recv - BASELINE_STATS['network']['bytes_recv']
        
        if sent_diff > 10 * 1024 * 1024 or recv_diff > 10 * 1024 * 1024:  # 10MB threshold
            alert = {
                'type': 'network',
                'severity': 'high',
                'message': f'Unusual network activity detected: Sent {sent_diff/1024/1024:.2f}MB, Received {recv_diff/1024/1024:.2f}MB',
                'timestamp': datetime.now().isoformat()
            }
            ALERTS.append(alert)
            print(f"[ALERT] {alert['message']}")
        
        # Update baseline
        BASELINE_STATS['network'] = {
            'bytes_sent': current_network.bytes_sent,
            'bytes_recv': current_network.bytes_recv
        }

def train_anomaly_detection():
    # In a real system, you'd use historical data here
    # For demo, we'll create some synthetic data
    np.random.seed(42)
    normal_data = np.random.normal(50, 10, (100, 3))  # Normal behavior
    anomaly_data = np.random.normal(150, 30, (10, 3))  # Anomalous behavior
    
    X = np.vstack([normal_data, anomaly_data])
    
    # Train Isolation Forest model
    global DETECTION_MODEL
    DETECTION_MODEL = IsolationForest(contamination=0.1, random_state=42)
    DETECTION_MODEL.fit(X)
    print("Anomaly detection model trained")

# Flask API endpoints
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    return jsonify(ALERTS)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    stats = {
        'cpu': psutil.cpu_percent(interval=1),
        'memory': psutil.virtual_memory().percent,
        'network': psutil.net_io_counters()._asdict()
    }
    return jsonify(stats)

@app.route('/api/scan', methods=['POST'])
def scan_file():
    file_path = request.json.get('path')
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'Invalid file path'}), 400
    
    try:
        matches = compiled_yara_rules.match(filepath=file_path)
        result = {
            'path': file_path,
            'is_malicious': len(matches) > 0,
            'matches': [str(m) for m in matches]
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def start_monitoring():
    # Start file system monitoring in a separate thread
    fs_thread = threading.Thread(target=monitor_file_system, daemon=True)
    fs_thread.start()
    
    # Start process monitoring
    proc_thread = threading.Thread(target=monitor_processes, daemon=True)
    proc_thread.start()
    
    # Start network monitoring
    net_thread = threading.Thread(target=monitor_network, daemon=True)
    net_thread.start()

if __name__ == '__main__':
    # Train the ML model
    train_anomaly_detection()
    
    # Start monitoring threads
    start_monitoring()
    
    # Start Flask API
    app.run(host='0.0.0.0', port=5000)