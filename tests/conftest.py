from http.client import HTTPConnection
from threading import Thread

import pytest

import reverse_shell.utils as ut
import tests.mock as mk
from reverse_shell.server import server


@pytest.fixture(autouse=True, scope="session")
def start_server():
    # let's run the server with another thread, and using the configuration and live data
    server_thread = Thread(
        target=server.run_server, args=(mk.config, mk.sessions), daemon=True
    )
    server_thread.start()
    yield
    mk.database.session_data.close()


@pytest.fixture(scope="session")
def client():
    conn = HTTPConnection(mk.config.ip, mk.config.port)
    yield conn
    # assuming that all tests are done let's close the connection
    conn.close()


@pytest.fixture
def verified_client_header():
    return {
        "Authorization": f"Basic {ut.encode_token(mk.config.auth_token)}",
        "client-id": ut.generate_token(),
    }


@pytest.fixture
def verified_hacker_header():
    return {
        "Authorization": f"Basic {ut.encode_token(mk.config.auth_token)}",
        "client-id": ut.generate_token(),
        "hacker-token": ut.encode_token(mk.config.hacker_token),
    }


@pytest.fixture(scope="function")
def db_cursor():
    # yields the database cursor and erases all data after the test finishes
    db_cursor = mk.database.session_data.cursor()
    yield db_cursor
    # ---------- The tear down
    # First get all the table names from the database
    db_cursor.execute("SELECT tbl_name FROM sqlite_master")
    tbl_names = list(set([tbl_name[0] for tbl_name in db_cursor.fetchall()]))
    # Let's remove the duplicates

    # Now delete all rows from each one of them
    for tbl_name in tbl_names:
        db_cursor.execute(f"DELETE FROM {tbl_name}")
