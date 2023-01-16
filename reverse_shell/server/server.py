from http.server import HTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
from functools import partial
import json
import uuid
import base64

HOST = "0.0.0.0"
PORT = 80


class ZrevshellServer(BaseHTTPRequestHandler):
    def __init__(self, auth_token: str,  *args, **kwargs):
        # auth_token is a base64 message i.e it is a string that has been decoded from a base64 byte using ascii.
        self.auth_token = auth_token
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


def initialize_server(auth_token: str | None = None):
    # auth_token is a base64 message i.e it is a string that has been decoded from a base64 byte using ascii.
    if not auth_token:
        random_encoded_bytes = str(uuid.uuid4()).encode('ascii')
        base64_encoded_bytes = base64.b64encode(random_encoded_bytes)
        auth_token = base64_encoded_bytes.decode('ascii')

    handler = partial(ZrevshellServer, auth_token)
    print(f"Server is running on {HOST} port {PORT}...")
    server = HTTPServer((HOST, PORT), handler)
    print(f"Generated authentication token -> {auth_token}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    print("Server has shutdown.")


initialize_server()
