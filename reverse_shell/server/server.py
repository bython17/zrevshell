""" The reverse shell server and request handler. """

# ---- imports
import sys
import reverse_shell.utils as ut
from http.server import BaseHTTPRequestHandler, HTTPServer
from http import HTTPStatus
from functools import partial
from binascii import Error as b64decodeError
from config import Config


class ZrevshellServer(BaseHTTPRequestHandler):
    """ Request handling. """

    def __init__(self, config: Config, *args, **kwargs):
        # Our configuration: tokens, ip, port and etc...
        self.config = config
        super().__init__(*args, **kwargs)

    def c_send_error(self, code: HTTPStatus):
        self.send_error(code)
        self.end_headers()

    def check_verified_request(self):
        """ Check if the request is verified by ensuring the existence and validity of auth_token 
        and existence of the client-id header """

        client_id = self.headers.get("client-id")  # This might be None if the client_id doesn't exist
        auth_token = self.headers.get("Authorization")  # same goes here

        # If the client_id header doesn't exist then we tell the user
        # that he is sending a bad request
        if client_id is None:
            self.c_send_error(HTTPStatus.BAD_REQUEST)
            return False

        if auth_token is not None:
            # Let's check if the auth_token matches ours
            # First let's decode the token, it might not be valid
            # base64 so we'll error handle it.
            try:
                # Remove the Basic string from the token
                auth_token = auth_token.removeprefix("Basic").strip()
                decoded_token = ut.decode_token(auth_token)
            except b64decodeError:
                pass
            else:
                if decoded_token == self.config.auth_token:
                    return True

        # Well if the user doesn't pass through the above it means the client ain't
        # verified so let's tell that to the client
        self.c_send_error(HTTPStatus.UNAUTHORIZED)
        return False

    def do_GET(self):
        """ Handle the GET requests. """
        pass

    def do_POST(self):
        """ Handle POST requests. """
        # Check if the request is valid
        if not self.check_verified_request():
            return

        # Check if the user is allowed to access this path
        # according to the privileges.

        # Just for testing more things are to be done.
        self.send_response(HTTPStatus.OK)
        self.end_headers()


def start_server():
    """ Start the HTTP server """

    # Initializing our configuration
    configuration = Config()

    # Getting the ip and port from the config
    ip, port = configuration.ip, configuration.port

    # We are using partials because only can pass the class to
    # HTTPServer not an object so we can use functools.partial to solve
    # the issue.
    zrevshell_server = partial(ZrevshellServer, configuration)

    # Initiate the server
    ut.log("debug", f"Server is starting on ({ip}:{port})...")
    httpd = HTTPServer((ip, port), zrevshell_server)
    ut.log("success", "Server has successfully started!")
    # Means print an empty line, i think...
    print("\r")
    ut.log("info", "-------- Tokens --------")
    ut.log("info", f"Authentication Token: {configuration.auth_token}")
    ut.log("info", f"Administration Token: {configuration.admin_token}")
    ut.log("info", f"Hacking Token: {configuration.hacker_token}")

    # Create some empty space for the proceeding
    print("\r")
    # Create a header for the logs that the http server generates
    ut.log("info", "--------- Server Logs --------")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        # It's because we use keyboard interrupt normally to stop
        # the server.
        pass

    # Actually does nothing, but incase we override it
    # and need to clean up our server
    httpd.server_close()

    ut.log("debug", f"Server has shutdown!")
    sys.exit(0)


def main():
    """ Run the reverse shell server """
    start_server()


if __name__ == "__main__":
    main()
