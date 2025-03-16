#!/usr/bin/python3
import socket

def handle_client(client_socket):
    try:
        with client_socket.makefile('r') as client_in, client_socket.makefile('w') as client_out:
            message = client_in.readline().strip()
            print(f"Received: {message}")


            ########## YOUR CODE HERE ############
            ### Validate the the PoW in the message
            ### Stril the PoW from the message
            ### Read the last hash from loghead.txt
            ### Create the full line for the log entry
            ### Compute its hash
            ### Append the line to the log
            ### Update loghead.txt
            ### Add error checking
            #######################################

            # Append the received string to log.txt
            with open("log.txt", "a") as log_file:
                log_file.write(message + "\n")

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

