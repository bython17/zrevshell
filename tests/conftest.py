from reverse_shell.server import config as c
from reverse_shell.server import server
from reverse_shell.utils import write_json
from configuration import configuration
from threading import Thread
from pathlib import Path
from http.client import HTTPConnection
import pytest
import shlex


def create_profile(profile_dict: dict[str, str]):
    """Create profile.json file using the given dictionary and return the path."""
    file_path = Path(".tmp/tmp_profile.json")
    write_json(file_path, profile_dict)
    return file_path


def generate_config_namespace(command: str):
    """Generate an argparse config namespace using the command given."""
    args = shlex.split(command)
    return c.get_argument_parser().parse_args(args)


@pytest.fixture(scope="function")
def modified_config(request):
    # We are given a profile.json as a python dictionary. Now, we need to change that into a real file and then pass it to the config.
    profile_path = create_profile(request.param)
    config_ns = generate_config_namespace(f"-fp {profile_path} -b {Path('.tmp')}")
    return c.Config(config_ns)


@pytest.fixture(autouse=True, scope="session")
def start_server():
    # let's run the server with another thread, and using the configuration
    server_thread = Thread(
        target=server.start_server, args=(configuration,), daemon=True
    )
    server_thread.start()


@pytest.fixture(scope="session")
def client():
    conn = HTTPConnection(configuration.ip, configuration.port)
    return conn
