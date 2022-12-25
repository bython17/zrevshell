import socket
import reverse_shell.consts as ct


def log(focus_message: str, description):
    print(f"[{focus_message.upper()}] {description}")


def send_message(message: str, sock: socket.socket):
    message_length = len(message)  # this is the lenght of the message we are going to send
    # Now we need to add white spacess to the message_length inorder to make it fit to the HEADER_SIZE
    message_length = f"{message_length:<{ct.HEADER_SIZE}}"  # here what i did was just adding white spaces to the message_length.
    sock.send(message_length.encode(ct.ENCODING))  # then send that to the server or client

    # Now let's send the actual message which is simple
    sock.send(message.encode(ct.ENCODING))


def recieve_message(sock: socket.socket):
    message_length = sock.recv(ct.HEADER_SIZE).decode(ct.ENCODING)

    if not message_length:
        return None

    message_length = int(message_length)

    if message_length <= 16:
        return sock.recv(message_length).decode(ct.ENCODING)

    full_message = ""

    ################ Nython's Logic##########################
    # while message_length > 16:
    #     message_part = sock.recv(16).decode(ct.ENCODING)
    #     full_message += message_part
    #     message_length -= 16

    # if message_length:
    #     full_message += sock.recv(message_length).decode(ct.ENCODING)
    #######################################################

    ############### Bython's Logic##########################
    recieve_sizes = [16] * (message_length // 16)
    recieve_sizes.append(message_length % 16)

    for recieve_size in recieve_sizes:
        part_message = sock.recv(recieve_size).decode(ct.ENCODING)
        full_message += part_message
    #####################################################

    return full_message
