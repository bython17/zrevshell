import json as js
from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import helper as hp
import pytest

import reverse_shell.utils as ut


@pytest.fixture(scope="function")
def db_cursor():
    # yields the database cursor and erases all data after the test finishes
    db_cursor = hp.database.session_data.cursor()
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
        "INSERT INTO clients VALUES(?, ?, 1)", (hacker_id, ut.ClientType.hacker)
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
        "INSERT INTO clients VALUES(?, ?, 1)", (victim_id, ut.ClientType.victim)
    )
    db_cursor.execute(
        "INSERT INTO victim_info VALUES(?, ?, ?, ?, ?, ?)",
        (victim_id, *victim_info),
    )


def get_cmd_id(command_name: str):
    """Make sure you know the command exists and is unique to get proper results."""
    return [
        key for key, value in hp.config.server_cmds.items() if value == command_name
    ][0]


@pytest.mark.parametrize(
    "headers, res_code",
    [
        ({}, st.BAD_REQUEST),
        (
            {"Authorization": f"Basic {ut.encode_token(hp.config.auth_token)}"},
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
                "Authorization": f"Basic {ut.encode_token(hp.config.auth_token)}",
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
        "Authorization": f"Basic {ut.encode_token(hp.config.auth_token)}",
        "client-id": ut.generate_token(),
    }


@pytest.fixture
def verified_hacker_header():
    return {
        "Authorization": f"Basic {ut.encode_token(hp.config.auth_token)}",
        "client-id": ut.generate_token(),
        "hacker-token": ut.encode_token(hp.config.hacker_token),
    }


# ---------- Testing command 'verify' ---------- #
# This command's path
register_cmd_path = get_cmd_id(ut.ServerCommands.register)


@pytest.mark.parametrize(
    "client_type",
    [(ut.ClientType.admin), (ut.ClientType.hacker), (ut.ClientType.victim)],
)
def test_register_basic(
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
        f"/{register_cmd_path}",
        headers={
            **verified_client_header,
            "client-type": client_type.__str__(),
            "hacker-token": ut.encode_token(hp.config.hacker_token),
            "admin-token": ut.encode_token(hp.config.admin_token),
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
    if client_type == ut.ClientType.victim:
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
def test_register_victim_with_body(
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
        f"/{register_cmd_path}",
        body=encoded_body,
        headers={
            **verified_client_header,
            "client-type": ut.ClientType.victim.__str__(),
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


def test_register_when_victim_exists(
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
        f"/{register_cmd_path}",
        headers={
            **verified_client_header,
            "client-type": ut.ClientType.victim.__str__(),
        },
    )

    assert client.getresponse().status == st.CONFLICT


# ---------- Testing command 'create_session' ---------- #
create_session_path = get_cmd_id(ut.ServerCommands.create_session)


def test_create_session_without_body(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_hacker_header: dict[str, str],
):
    hacker_id = verified_hacker_header["client-id"]
    # Create a sample hacker because we need to use it.
    create_hacker(hacker_id, db_cursor)

    client.request("POST", f"/{create_session_path}", headers=verified_hacker_header)

    assert client.getresponse().status == st.BAD_REQUEST


def test_create_session_with_invalid_victim(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_hacker_header: dict[str, str],
):
    victim_id = ut.generate_token()

    hacker_id = verified_hacker_header["client-id"]
    # Create a sample hacker because we need to use it.
    create_hacker(hacker_id, db_cursor)

    client.request(
        "POST",
        f"/{create_session_path}",
        body=ut.encode_token(victim_id),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.BAD_REQUEST


def test_create_session_with_victim_already_in_session(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_hacker_header: dict[str, str],
):
    # Create sample victim
    victim_id = ut.generate_token()
    create_victim(victim_id, db_cursor)

    hacker_id = verified_hacker_header["client-id"]
    # Create a sample hacker because we need to use it.
    create_hacker(hacker_id, db_cursor)

    # faking a session with a hacker for the victim
    hp.sessions.add_session(hacker_id, victim_id)

    client.request(
        "POST",
        f"/{create_session_path}",
        body=ut.encode_token(victim_id),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.FORBIDDEN


def test_create_session_for_session_id_in_body_as_hacker(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Create the hacker
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    # Now create a victim
    victim_id = ut.generate_token()
    create_victim(victim_id, db_cursor)

    # And finally make the request to establish the
    # session with the client
    client.request(
        "POST",
        f"/{create_session_path}",
        body=ut.encode_token(victim_id),
        headers=verified_hacker_header,
    )

    # Validating the result
    response = client.getresponse()

    content_size = response.getheader("content-length")

    if content_size is None:
        assert False

    # Decoding and reading the response body
    raw_response = response.read(int(content_size)).decode("utf8")
    session_id = ut.decode_token(raw_response)

    # Now let's compare our session ID with what's already there
    assert (
        hp.sessions.get_session(session_id)["hacker_id"] == hacker_id
        and hp.sessions.get_session(session_id)["victim_id"] == victim_id
    )


def test_create_session_properly(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_hacker_header: dict[str, str],
):
    # Create sample victim
    victim_id = ut.generate_token()
    create_victim(victim_id, db_cursor)

    hacker_id = verified_hacker_header["client-id"]
    # Create a sample hacker because we need to use it.
    create_hacker(hacker_id, db_cursor)

    client.request(
        "POST",
        f"/{create_session_path}",
        body=ut.encode_token(victim_id),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.OK

    # Also check in the hacking_sessions table
    assert hp.sessions.check_client_in_session(victim_id)


# ---------- Testing command 'post_cmd' ---------- #
post_cmd_path = get_cmd_id(ut.ServerCommands.post_cmd)


def test_post_cmd_with_dead_session(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # That generally means no victim was ever created
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    request_body = js.dumps(
        {
            "session_id": ut.generate_token(),  # A fake token(i.e the session isn't running)
            "command": "whoami",
        }
    )

    client.request(
        "POST",
        f"/{post_cmd_path}",
        body=ut.encode_token(request_body),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.FORBIDDEN


def test_post_cmd_with_victim_in_session(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Let's create a hacker and a victim
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    create_victim(victim_id, db_cursor)

    # Let's put the victim in session with supposedly another hacker
    session_id = hp.sessions.add_session(ut.generate_token(), victim_id)

    request_body = js.dumps({"session_id": session_id, "command": "whoami"})

    client.request(
        "POST",
        f"/{post_cmd_path}",
        body=ut.encode_token(request_body),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.FORBIDDEN


def test_post_cmd_without_body(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_hacker_header: dict[str, str],
):
    # Create victim and hacker
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    create_victim(victim_id, db_cursor)

    # Let's put the hacker in session with the victim
    hp.sessions.add_session(hacker_id, victim_id)

    client.request(
        "POST",
        f"/{post_cmd_path}",
        body="",
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.BAD_REQUEST


def test_post_cmd_properly(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Create the victim and the hacker
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    create_victim(victim_id, db_cursor)

    # putting the hacker in session with the victim
    session_id = hp.sessions.add_session(hacker_id, victim_id)

    request_body = js.dumps({"session_id": session_id, "command": "whoami"})

    client.request(
        "POST",
        f"/{post_cmd_path}",
        body=ut.encode_token(request_body),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.CREATED


# ---------- Testing command "get_session" ---------- #
get_session_path = get_cmd_id(ut.ServerCommands.get_session)


def test_get_session_without_a_session(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    client_id = verified_client_header["client-id"]
    create_victim(client_id, db_cursor)

    # Let's request to get a session even though we are not
    # in one
    client.request("GET", f"/{get_session_path}", headers=verified_client_header)

    assert client.getresponse().status == st.NOT_FOUND


def test_get_session_with_a_session(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    client_id = verified_client_header["client-id"]
    create_victim(client_id, db_cursor)

    # Let's put the victim in a session with the hacker(well a fake one)
    session_id = hp.sessions.add_session(client_id, ut.generate_token())

    client.request("GET", f"/{get_session_path}", headers=verified_client_header)

    response = client.getresponse()

    # Check if the status code was right
    assert response.status == st.OK

    # And now if the session_id is correct
    content_length = response.getheader("content-length")

    # Check it false if the content length doesn't even exist
    if content_length is None:
        assert False

    server_sent_session_id = response.read(int(content_length)).decode()
    server_sent_session_id = ut.decode_token(server_sent_session_id)

    assert session_id == server_sent_session_id
