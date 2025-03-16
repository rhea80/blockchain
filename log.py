#!/usr/bin/python3
import socket
import sys
import hashlib
import itertools
import string

def generate_proof_of_work(message):
    message = " ".join(message.split()) 
    chars = string.ascii_letters + string.digits 
    
    for length in range(1, 6):
        for proof in ("".join(p) for p in itertools.product(chars, repeat=length)):
            test_string = proof + ":" + message
            hash_result = hashlib.sha256(test_string.encode()).hexdigest()
            if hash_result[:6] == "000000": 
                return proof + ":" + message
    
    raise ValueError("Proof-of-work not found within reasonable limits")

def send_string_to_server(port, message):
    try:
        # Connect to the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', port))
        pow_message = generate_proof_of_work(message)  


        with client_socket.makefile('r') as server_in, client_socket.makefile('w') as server_out:
            server_out.write(pow_message + "\n")
            server_out.flush()

            # Receive and print the confirmation message from the server
            response = server_in.readline().strip()
            print(f"Server response: {response}")

    except Exception as e:
        print(f"Error communicating with server: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: log <port> <message>")
    else:
        port = int(sys.argv[1])
        message = sys.argv[2]
        send_string_to_server(port, message)