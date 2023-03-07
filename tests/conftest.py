from http.client import HTTPConnection
from threading import Thread

import pytest
from configuration import configuration

from reverse_shell.server import server


@pytest.fixture(autouse=True, scope="session")
def start_server():
    # let's run the server with another thread, and using the configuration
    server_thread = Thread(target=server.run_server, args=(configuration,), daemon=True)
    server_thread.start()


@pytest.fixture(scope="session")
def client():
    conn = HTTPConnection(configuration.ip, configuration.port)
    yield conn
    # assuming that all tests are done let's close the connection
    conn.close()
