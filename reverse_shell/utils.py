from pathlib import Path
from datetime import datetime
import binascii
import base64
import uuid
import json


def log(focus_message: str, description):
    print(f"[{focus_message.upper()}] {description}")


def get_formatted_time():
    """ Returns the current time using YYYY-MM-DD-HH-MM-SS"""
    current_time = str(datetime.now())
    current_time = current_time.replace(":", "-").replace(" ", "-")
    current_time = current_time.split(".")[0]
    return current_time


def write_blank_json(file_path: Path, bytes=False, encoding="utf-8"):
    """ Write a blank json text i.e `{}` into a json file
    returns None if there is a json.JSONDecodeError"""
    try:
        if bytes:
            file_path.write_bytes("{}".encode(encoding))
        else:
            file_path.write_text("{}", encoding=encoding)
    except json.JSONDecodeError:
        return None


def write_json(file_path: Path, data: dict, bytes=False, encoding="utf-8"):
    """ Write a stringified python dictionary to the file_path
    returns None if there is a json.JSONDecodeError"""
    try:
        if not bytes:
            file_path.write_text(json.dumps(data))
        else:
            file_path.write_bytes(json.dumps(data).encode(encoding))
    except json.JSONDecodeError:
        return None


def read_json(file_path: Path, bytes=False, encoding="utf-8"):
    """ Read from the `file_path` and return a python dictionary.
    returns None if there is a json.JSONDecodeError"""
    try:
        if not bytes:
            if not file_path.is_file():
                write_blank_json(file_path)
            return json.loads(file_path.read_text())
        else:
            if not file_path.is_file():
                write_blank_json(file_path, bytes=True, encoding=encoding)
            return json.loads(file_path.read_bytes().decode(encoding))
    except json.JSONDecodeError:
        return None


def encode_token(token: str):
    """ Encode a string to base64 then decode it to string."""
    random_encoded_bytes = token.encode("ascii")
    base64_encoded_bytes = base64.b64encode(random_encoded_bytes)
    return base64_encoded_bytes.decode("ascii")


def decode_token(token: str | bytes):
    """ Decode a base64 encoded byte that has been decoded to a string or 
    an original base64."""
    if isinstance(token, str):
        token = token.encode("ascii")
    b64_decoded_bytes = base64.b64decode(token)
    return b64_decoded_bytes.decode("ascii")


def generate_token():
    """ Generate a new token """
    random_uuid = uuid.uuid4()
    return str(random_uuid).replace("-", "")


def get_id(file_path: Path):
    """ Get an ID for the client(either victim or hacker) and generate a new one
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
