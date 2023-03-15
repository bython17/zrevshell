from http.client import HTTPConnection
from threading import Thread

import helper as hp
import pytest

from reverse_shell.server import server


@pytest.fixture(autouse=True, scope="session")
def start_server():
    # let's run the server with another thread, and using the configuration and live data
    server_thread = Thread(
        target=server.run_server, args=(hp.config, hp.live_data), daemon=True
    )
    server_thread.start()


@pytest.fixture(scope="session")
def client():
    conn = HTTPConnection(hp.config.ip, hp.config.port)
    yield conn
    # assuming that all tests are done let's close the connection
    conn.close()
