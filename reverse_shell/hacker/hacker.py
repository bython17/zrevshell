from http.client import HTTPConnection
from pathlib import Path


# TODO: Save server config to a file
class Hacker:
    def __init__(self, auth_token: str, hacker_token: str, server_address, port_number: int = 80, base_dir: Path = Path("hacker_data")):
        self.connection = HTTPConnection(server_address, port_number)
