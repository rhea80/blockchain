#!/usr/bin/python3
import socket
import hashlib
import base64
import os
from datetime import datetime, timezone

def compute_hash(log_entry):
    hash_obj = hashlib.sha256(log_entry.encode('utf-8'))
    hash_b64 = base64.b64encode(hash_obj.digest()).decode('utf-8')
    return hash_b64[-24:]

def handle_client(client_socket):
    try:
        with client_socket.makefile('r') as client_in, client_socket.makefile('w') as client_out:
            message = client_in.readline().strip()
            print(f"Received: {message}")

            if not message:
                client_out.write("error: Empty message\n")
                client_out.flush()
                return


            loghead_path = "loghead.txt"
            log_path = "log.txt"
            
            if not os.path.exists(loghead_path) and not os.path.exists(log_path):
                last_hash = "start"
                with open(loghead_path, "w") as loghead_file:
                    loghead_file.write(last_hash)
            elif os.path.exists(loghead_path):
                with open(loghead_path, "r") as f:
                    last_hash = f.read().strip()
                if not last_hash:
                    client_out.write("error: Missing head pointer\n")
                    client_out.flush()
                    return
            else:
                client_out.write("error: Missing head pointer but log exists\n")
                client_out.flush()
                return
            
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"{timestamp} - {last_hash} {message}"
            new_hash = compute_hash(log_entry)

            

            # Append the received string to log.txt
            with open(log_path, "a") as log_file:
                log_file.write(log_entry + "\n")
            with open(loghead_path, "w") as loghead_file:
                loghead_file.write(new_hash)

            # Send a response message back to the client (terminated by a newline)
            response = "ok\n"
            client_out.write(response)
            client_out.flush()

    except Exception as e:
        print(f"logserver: {e}")
    finally:
        client_socket.close()

def start_server():
    # Create a socket and bind it to any available port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 0))  # Bind to any available port
    server_socket.listen(5)

    # Get the port number and print it
    port = server_socket.getsockname()[1]
    print(f"Server listening on port {port}")

    # Continuously accept and handle clients
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        handle_client(client_socket)

if __name__ == "__main__":
    start_server()

