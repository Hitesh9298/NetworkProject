import os
import time
from datetime import datetime
import shutil

# Use relative paths
TEST_DIR = os.path.join(os.path.dirname(__file__), 'test_files')
QUARANTINE_DIR = os.path.join(os.path.dirname(__file__), 'quarantine')

def generate_test_files():
    """Generate test files that should trigger detection"""
    os.makedirs(TEST_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    
    test_files = [
        {
            'filename': 'malicious.encrypted',
            'content': 'This file has a suspicious extension',
            'should_detect': True,
            'type': 'extension'
        },
        {
            'filename': 'ransom_note.txt',
            'content': 'HOW_TO_DECRYPT your files to get them back!',
            'should_detect': True,
            'type': 'content'
        },
        {
            'filename': 'large_modified.bin',
            'content': os.urandom(1024*200),  # 200KB
            'should_detect': True,
            'type': 'size',
            'modify': True
        },
        {
            'filename': 'normal_file.txt',
            'content': 'This is a normal file',
            'should_detect': False,
            'type': 'normal'
        }
    ]
    
    results = []
    for test_file in test_files:
        file_path = os.path.join(TEST_DIR, test_file['filename'])
        try:
            mode = 'wb' if isinstance(test_file['content'], bytes) else 'w'
            with open(file_path, mode) as f:
                f.write(test_file['content'])
            
            if test_file.get('modify', False):
                time.sleep(0.5)
                with open(file_path, 'ab') as f:
                    f.write(os.urandom(1024*50))
                print(f"[TEST] Modified {file_path}")
            
            results.append({
                'filename': test_file['filename'],
                'path': file_path,
                'type': test_file['type'],
                'status': 'created',
                'should_detect': test_file['should_detect'],
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            print(f"[ERROR] Failed to create {file_path}: {e}")
            results.append({
                'filename': test_file['filename'],
                'error': str(e),
                'should_detect': test_file['should_detect']
            })
    
    return results

def cleanup_test_files():
    """Clean up test files and quarantine with better error handling"""
    success = True
    for dir_path in [TEST_DIR, QUARANTINE_DIR]:
        if os.path.exists(dir_path):
            for filename in os.listdir(dir_path):
                file_path = os.path.join(dir_path, filename)
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print(f"[ERROR] Failed to remove {file_path}: {e}")
                    success = False
    return success