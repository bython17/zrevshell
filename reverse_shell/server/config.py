"""The configuration manager for the server"""
# --- the imports
import json as js
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, Namespace

# from http.client import HTTPMessage
from pathlib import Path
from typing import Optional

import reverse_shell.server.database as db
import reverse_shell.utils as ut
from reverse_shell import __app_name__, __version__
from reverse_shell.server import ErrorCodes as ec


class DefaultCLIArgumentValues:
    port = 8080
    ip = "0.0.0.0"
    min_reconnect_timeout = 10
    max_reconnect_timeout = 1200
    request_rate = 1
    client_idle_duration = 1800


class Config:
    def __init__(
        self,
        config: Namespace,
        database: Optional[db.Database] = None,
    ):
        self.config = config

        # ---- Get the base directory
        self.base_dir = self.get_server_base_dir()

        # ---- Setup the profile file
        self.profile, self.profile_path = self.get_profile("profile.json")

        # Initialize the database according to config
        self.database = (
            db.Database(Path(f"{self.base_dir}/data.db"))
            if database is None
            else database
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
