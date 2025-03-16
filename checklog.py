import sys
import socket
import hashlib
import time
import string
import itertools
import os
import base64
from datetime import datetime

def generate_proof_of_work(message):
    message = message.replace('\n', ' ').replace('\t', ' ')
    for length in range(1, 6):  # Try proofs of increasing length
        for proof in map(''.join, itertools.product(string.ascii_letters + string.digits, repeat=length)):
            attempt = f"{proof}:{message}"
            hash_value = hashlib.sha256(attempt.encode()).hexdigest()
            if bin(int(hash_value, 16))[2:].zfill(256)[:22] == "0" * 22:
                return proof
    return None

def handle_client(connection):
    try:
        data = connection.recv(1024).decode().strip()
        if not data or ":" not in data:
            connection.sendall(b"error: invalid message\n")
            return
        
        proof, message = data.split(":", 1)
        expected_hash = hashlib.sha256(data.encode()).hexdigest()
        if bin(int(expected_hash, 16))[2:].zfill(256)[:22] != "0" * 22:
            connection.sendall(b"error: invalid proof of work\n")
            return
        
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        log_file = "log.txt"
        head_file = "loghead.txt"
        
        if not os.path.exists(log_file):
            head_hash = "start"
        elif not os.path.exists(head_file):
            connection.sendall(b"error: missing head pointer file\n")
            return
        else:
            with open(head_file, "r") as f:
                head_hash = f.read().strip()
        
        log_entry = f"{timestamp} - {head_hash} {message}\n"
        with open(log_file, "a") as f:
            f.write(log_entry)
        
        new_hash = base64.b64encode(hashlib.sha256(log_entry.encode()).digest()).decode()[-24:]
        with open(head_file, "w") as f:
            f.write(new_hash)
        
        connection.sendall(b"ok\n")
    except Exception as e:
        connection.sendall(f"error: {str(e)}\n".encode())
    finally:
        connection.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("localhost", 0))
        server.listen(5)
        port = server.getsockname()[1]
        print(f"Log server listening on port {port}")
        
        while True:
            conn, _ = server.accept()
            handle_client(conn)

def checklog():
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
        elif i > 0 and stored_hash != computed_hash:
            print(f"failed: log corruption detected at line {i+1}")
            sys.exit(1)
        
        computed_hash = base64.b64encode(hashlib.sha256(line.strip().encode()).digest()).decode()[-24:]
    
    if computed_hash != expected_hash:
        print("failed: head pointer mismatch")
        sys.exit(1)
    
    print("Valid")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "checklog":
        checklog()
    else:
        main()