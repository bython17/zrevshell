from reverse_shell import __app_name__, __version__
from reverse_shell.server import ErrorCodes
import reverse_shell.utils as ut
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from http import HTTPStatus
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, Namespace
from functools import partial
import sys


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

        # ---- IP and PORT
        self.port = self.config.port
        self.ip = self.config.ip

    def get_session_data(self):
        """ Get the data from our session file if it exists else generate one with the default mockup """
        # Defining the default contents of the data field
        # The data field is not complete, it'll be soon tho

        default_data_contents = {
            "victim_specs": {},
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
            sys.exit(ErrorCodes.incorrect_file_format)

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
            sys.exit(ErrorCodes.incorrect_file_format)

        # Check if the given key exists in the session file else return None
        try:
            value = session_details[key]
        except KeyError:
            ut.log("error", "Invalid session file. Please use server generated session files.")
            sys.exit(ErrorCodes.incorrect_file_format)

        return value


class DespicableServer(BaseHTTPRequestHandler):
    """ Handles all http requests """

    def __init__(self, config: Config, *args, **kwargs):
        self.configuration = config

        # Initialize the BaseHTTPRequestHandler
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html")
        if length := self.headers.get("content-length"):
            content = self.rfile.read(length)
            print(self.address_string, content, sep=": ")
        self.end_headers()

        self.wfile.write(bytes("<html><head><title>We are running a server</title></head> <body> <h1> Hello World </h1> </body></html>", "utf-8"))


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

        parser.add_argument("-p", "--port", type=int, required=False, help="The port on which the server runs on.", default=80)

        parser.add_argument("-i", "--ip", type=str, required=False, help="The ip where the server is hosted on.", default="0.0.0.0")

        parser.add_argument("--version", "-v", action="version", version=f"{__app_name__} server v{__version__}")

        config = Config(parser.parse_args())

        return config


if __name__ == "__main__":
    # Well let's do this
    StartServer()
