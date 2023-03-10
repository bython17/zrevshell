import json as js
from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import pytest
from configuration import configuration as config

import reverse_shell.utils as ut


@pytest.fixture(scope="function")
def db_cursor():
    # yields the database cursor and erases all data after the test finishes
    db_cursor = config.session_data_db.cursor()
    yield db_cursor
    # ---------- The tear down
    # First get all the table names from the database
    db_cursor.execute("SELECT tbl_name FROM sqlite_master")
    tbl_names = list(set([tbl_name[0] for tbl_name in db_cursor.fetchall()]))
    # Let's remove the duplicates

    # Now delete all rows from each one of them
    for tbl_name in tbl_names:
        db_cursor.execute(f"DELETE FROM {tbl_name}")


# Some helper functions
def create_hacker(hacker_id: str, db_cursor: Cursor):
    db_cursor.execute(
        "INSERT INTO clients VALUES(?, ?, 1)", (hacker_id, ut.ClientType.Hacker)
    )


def create_victim(
    victim_id: str,
    db_cursor: Cursor,
    victim_info: tuple[str | None, str | None, str | None, str | None, str | None] = (
        None,
        None,
        None,
        None,
        None,
    ),
):
    db_cursor.execute(
        "INSERT INTO clients VALUES(?, ?, 1)", (victim_id, ut.ClientType.Victim)
    )
    db_cursor.execute(
        "INSERT INTO victim_info VALUES(?, ?, ?, ?, ?, ?)",
        (victim_id, *victim_info),
    )


def get_cmd_id(command_name: str):
    """Make sure you know the command exists and is unique to get proper results."""
    return [key for key, value in config.server_cmds.items() if value == command_name][
        0
    ]


@pytest.mark.parametrize(
    "headers, res_code",
    [
        ({}, st.BAD_REQUEST),
        (
            {"Authorization": f"Basic {ut.encode_token(config.auth_token)}"},
            st.BAD_REQUEST,
        ),
        (
            {
                "Authorization": "Basic IMessedUpTheToken",
                "client-id": ut.generate_token(),
            },
            st.UNAUTHORIZED,
        ),
        ({"client-id": ut.generate_token()}, st.UNAUTHORIZED),
        (
            {
                "Authorization": f"Basic {ut.encode_token(config.auth_token)}",
                "client-id": ut.generate_token(),
            },
            st.OK,
        ),
    ],
)
def test_check_verified_request(
    client: HTTPConnection, headers: dict[str, str], res_code: st
):
    # Let's send our request to the server using the client fixture
    client.request("GET", "/", headers=headers)
    assert client.getresponse().status == res_code


@pytest.fixture
def verified_client_header():
    return {
        "Authorization": f"Basic {ut.encode_token(config.auth_token)}",
        "client-id": ut.generate_token(),
    }


# ---------- Testing command 'verify' ---------- #
# This command's path
verify_cmd_path = get_cmd_id("verify")


@pytest.mark.parametrize(
    "client_type",
    [(ut.ClientType.Admin), (ut.ClientType.Hacker), (ut.ClientType.Victim)],
)
def test_verify_basic(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_client_header: dict[str, str],
    client_type: int,
):
    # request the server for the verify command using our verified_client_header
    # before that store the client_id for further usage.
    client_id = verified_client_header["client-id"]
    client.request(
        "POST",
        f"/{verify_cmd_path}",
        headers={
            **verified_client_header,
            "client-type": client_type.__str__(),
            "hacker-token": f"{ut.encode_token(config.hacker_token)}",
            "admin-token": f"{ut.encode_token(config.admin_token)}",
        },
    )
    # First let's check for the response_code
    assert client.getresponse().status == st.OK

    # Now let's check if all the required data is written in
    # the database
    db_cursor.execute("SELECT * FROM clients WHERE client_id=?", (client_id,))
    # Now let's check if we have results returned since the database is brand new
    # the only row will be the one inserted when we requested the verify command
    # so we just need to check if there is something
    assert db_cursor.fetchone() is not None

    # if the client is a victim then we need to also check for the victim_info
    # table and make sure all fields are None there.
    if client_type == ut.ClientType.Victim:
        db_cursor.execute("SELECT * FROM victim_info WHERE id=?", (client_id,))
        # First check if we even correctly inserted data into the victim_info dictionary
        victim_info = db_cursor.fetchone()
        assert victim_info is not None
        # Now check for their values, mind you they must be all None
        # we sliced the victim_info because we know that the key(id) is not
        # and should not be None.
        assert all([True if val is None else False for val in victim_info[1:]])


@pytest.mark.parametrize(
    "req_body",
    [
        (
            {
                "host_name": "user123",
                "os": "Windows",
                "arch": "x86",
                "cpu": "AMD Ryzen 7",
                "ram": "16GB",
            }
        ),
        ({"os": "MacOS", "arch": "ARM"}),
        ({}),
    ],
)
def test_verify_victim_with_body(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_client_header: dict[str, str],
    req_body: dict[str, str],
):
    # Let's first encode and send the req_body to our server
    encoded_body = ut.encode_token(js.dumps(req_body))
    client_id = verified_client_header["client-id"]
    # Now let's request
    client.request(
        "POST",
        f"/{verify_cmd_path}",
        body=encoded_body,
        headers={
            **verified_client_header,
            "client-type": ut.ClientType.Victim.__str__(),
        },
    )
    # First check if the status code is correct
    assert client.getresponse().status == st.OK

    # Let's check for every key the req_body has to offer
    # we're gonna select it in SQL
    for key, val in req_body.items():
        # Now check for the data, so first check for it's existence
        db_cursor.execute(
            "SELECT ? FROM victim_info WHERE id=?",
            (
                key,
                client_id,
            ),
        )
        result = db_cursor.fetchone()
        assert result is not None
        assert req_body[result[0]] == val


def test_verify_when_victim_exists(
    client: HTTPConnection, verified_client_header, db_cursor: Cursor
):
    # Insert a client directly to the database and test if
    # request verify with the same client id yields a conflict status
    # we'll use client type victim cuz changing client types now doesn't
    # make a difference now.

    client_id = verified_client_header["client-id"]
    # Create sample victim
    create_victim(client_id, db_cursor)

    # Now let's check if the requests yield a conflict response
    client.request(
        "POST",
        f"/{verify_cmd_path}",
        headers={
            **verified_client_header,
            "client-type": ut.ClientType.Victim.__str__(),
        },
    )

    assert client.getresponse().status == st.CONFLICT


# ---------- Testing command 'create_session' ---------- #
create_session_path = get_cmd_id("create_session")


def test_create_session_without_body(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_client_header: dict[str, str],
):
    hacker_id = verified_client_header["client-id"]
    # Create a sample hacker because we need to use it.
    create_hacker(hacker_id, db_cursor)

    client.request("POST", f"/{create_session_path}", headers=verified_client_header)

    assert client.getresponse().status == st.BAD_REQUEST


def test_create_session_with_invalid_victim(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_client_header: dict[str, str],
):
    victim_id = ut.generate_token()

    hacker_id = verified_client_header["client-id"]
    # Create a sample hacker because we need to use it.
    create_hacker(hacker_id, db_cursor)

    client.request(
        "POST",
        f"/{create_session_path}",
        body=f"{ut.encode_token(victim_id)}",
        headers=verified_client_header,
    )

    assert client.getresponse().status == st.BAD_REQUEST


def test_create_session_with_victim_already_in_session(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_client_header: dict[str, str],
):
    # Create sample victim
    victim_id = ut.generate_token()
    create_victim(victim_id, db_cursor)

    hacker_id = verified_client_header["client-id"]
    # Create a sample hacker because we need to use it.
    create_hacker(hacker_id, db_cursor)

    # faking a session with a hacker for the victim
    config.hacking_sessions[victim_id] = ut.generate_token()

    client.request(
        "POST",
        f"/{create_session_path}",
        body=f"{ut.encode_token(victim_id)}",
        headers=verified_client_header,
    )

    assert client.getresponse().status == st.FORBIDDEN


def test_create_session_properly(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_client_header: dict[str, str],
):
    # Create sample victim
    victim_id = ut.generate_token()
    create_victim(victim_id, db_cursor)

    hacker_id = verified_client_header["client-id"]
    # Create a sample hacker because we need to use it.
    create_hacker(hacker_id, db_cursor)

    client.request(
        "POST",
        f"/{create_session_path}",
        body=f"{ut.encode_token(victim_id)}",
        headers=verified_client_header,
    )

    assert client.getresponse().status == st.OK

    # Also check in the hacking_sessions table
    assert config.hacking_sessions.get(victim_id, None) is not None
