import sys
import socket
import hashlib
import string
import itertools

def generate_proof_of_work(message):
    message = message.replace("\n", " ").replace("\t", " ")
    for length in range(1, 10):
        for proof in map(''.join, itertools.product(string.ascii_letters + string.digits, repeat=length)):
            candidate = f"{proof}:{message}"
            hash_value = hashlib.sha256(candidate.encode()).hexdigest()
            if bin(int(hash_value, 16))[2:].zfill(256)[:22] == "0" * 22:
                return proof
    raise RuntimeError("Failed to generate proof of work")

def send_log_message(server_port, message):
    proof = generate_proof_of_work(message)
    final_message = f"{proof}:{message}"
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(("localhost", int(server_port)))
        sock.sendall(final_message.encode())
        response = sock.recv(256).decode()
        print(f"Server response: {response}")

def main():
    if len(sys.argv) != 3:
        print("Usage: log server_port_number message")
        sys.exit(1)
    
    server_port = sys.argv[1]
    message = sys.argv[2]
    send_log_message(server_port, message)

if __name__ == "__main__":
    main()
