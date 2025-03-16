#!/usr/bin/python3
import socket
import sys

def send_string_to_server(port, message):
    try:
        # Connect to the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', port))

        ######################
        ### Convert any whitespace to spaces
        ### Modify the messsage to include the proof-of-work (Pow+':'+message)
        ######################

        with client_socket.makefile('r') as server_in, client_socket.makefile('w') as server_out:
            # Send the message to the server, terminated by a newline
            server_out.write(message + "\n")
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