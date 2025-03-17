import sys
import os
import hashlib
import base64

def check_log_integrity():
    log_file = "log.txt"
    head_file = "loghead.txt"

    if not os.path.exists(log_file):
        print("failed: log file missing")
        sys.exit(1)
    
    if not os.path.exists(head_file):
        print("failed: head pointer file missing")
        sys.exit(1)
    
    with open(log_file, "r") as f:
        lines = f.readlines()
    
    with open(head_file, "r") as f:
        expected_hash = f.read().strip()
    
    if not lines:
        print("failed: log file is empty")
        sys.exit(1)
    
    computed_hash = "start"
    
    for i, line in enumerate(lines):
        parts = line.strip().split(" - ", 2)
        if len(parts) < 3:
            print(f"failed: malformed log entry at line {i+1}")
            sys.exit(1)
        
        timestamp, stored_hash, message = parts
        
        if i == 0 and stored_hash != "start":
            print("failed: first entry hash is not 'start'")
            sys.exit(1)
        
        if i > 0 and stored_hash != computed_hash:
            print(f"failed: log corruption detected at line {i+1}")
            sys.exit(1)
        
        computed_hash = base64.b64encode(hashlib.sha256(line.strip().encode()).digest()).decode()[-24:]
    
    if computed_hash != expected_hash:
        print("failed: head pointer mismatch")
        sys.exit(1)
    
    print("Valid")
    sys.exit(0)

if __name__ == "__main__":
    check_log_integrity()
