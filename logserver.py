import socket
import hashlib
import base64
import time
import os
from datetime import datetime

def compute_log_hash(log_entry):
    """Compute a base64-encoded hash for the log entry."""
    sha256_hash = hashlib.sha256(log_entry.encode()).digest()
    return base64.b64encode(sha256_hash).decode()[-24:]

def validate_proof_of_work(message):
    """Validate that the first 22 bits of the SHA-256 hash of the message are 0."""
    hash_value = hashlib.sha256(message.encode()).hexdigest()
    return bin(int(hash_value, 16))[2:].zfill(256)[:22] == "0" * 22

def process_log_entry(log_message):
    """Process and store the log entry, maintaining the hash chain."""
    log_file = "log.txt"
    loghead_file = "loghead.txt"
    
    if os.path.exists(log_file) and not os.path.exists(loghead_file):
        return "Error: loghead.txt is missing. Cannot trust log integrity."
    
    previous_hash = "start"
    if os.path.exists(loghead_file):
        with open(loghead_file, "r") as f:
            previous_hash = f.read().strip() or "start"
    
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {previous_hash} {log_message}"
    
    with open(log_file, "a") as f:
        f.write(log_entry + "\n")
    
    new_hash = compute_log_hash(log_entry)
    with open(loghead_file, "w") as f:
        f.write(new_hash)
    
    return "ok"

def handle_client_connection(client_socket):
    """Handle a single client connection."""
    message = client_socket.recv(256).decode().strip()
    
    if ":" not in message:
        client_socket.sendall(b"Error: Invalid message format.\n")
        return
    
    proof, log_message = message.split(":", 1)
    
    if not validate_proof_of_work(message):
        client_socket.sendall(b"Error: Invalid proof-of-work.\n")
        return
    
    response = process_log_entry(log_message)
    client_socket.sendall(response.encode() + b"\n")

def start_server():
    """Start the log server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 0))
    server.listen(5)
    
    port = server.getsockname()[1]
    print(f"Log server listening on port {port}")
    
    while True:
        client_socket, _ = server.accept()
        handle_client_connection(client_socket)
        client_socket.close()

if __name__ == "__main__":
    start_server()
