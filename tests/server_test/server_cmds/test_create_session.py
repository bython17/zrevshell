from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import reverse_shell.utils as ut
import tests.mock as mk
import tests.server_test.helper as hp

# Command ID
create_session_path = hp.get_cmd_id(ut.ServerCommands.create_session)


def test_create_session_without_body(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_hacker_header: dict[str, str],
):
    hacker_id = verified_hacker_header["client-id"]
    # Create a sample hacker because we need to use it.
    hp.create_hacker(hacker_id, db_cursor)

    client.request("POST", f"{create_session_path}", headers=verified_hacker_header)

    assert client.getresponse().status == st.BAD_REQUEST


def test_create_session_with_invalid_victim(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_hacker_header: dict[str, str],
):
    victim_id = ut.generate_token()

    hacker_id = verified_hacker_header["client-id"]
    # Create a sample hacker because we need to use it.
    hp.create_hacker(hacker_id, db_cursor)

    client.request(
        "POST",
        f"{create_session_path}",
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
    hp.create_victim(victim_id, db_cursor)

    hacker_id = verified_hacker_header["client-id"]
    # Create a sample hacker because we need to use it.
    hp.create_hacker(hacker_id, db_cursor)

    # faking a session with a hacker for the victim
    mk.session_manager.add_session(hacker_id, victim_id)

    client.request(
        "POST",
        f"{create_session_path}",
        body=ut.encode_token(victim_id),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.FORBIDDEN


def test_create_session_for_session_id_in_body_as_hacker(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Create the hacker
    hacker_id = verified_hacker_header["client-id"]
    hp.create_hacker(hacker_id, db_cursor)

    # Now create a victim
    victim_id = ut.generate_token()
    hp.create_victim(victim_id, db_cursor)

    # And finally make the request to establish the
    # session with the client
    client.request(
        "POST",
        f"{create_session_path}",
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
        mk.session_manager.get_session(session_id)["hacker_id"] == hacker_id
        and mk.session_manager.get_session(session_id)["victim_id"] == victim_id
    )


def test_create_session_when_hacker_in_multiple_valid_sessions(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    hp.create_hacker(hacker_id, db_cursor)

    victim1_id, victim2_id = ut.generate_token(), ut.generate_token()
    hp.create_victim(victim1_id, db_cursor)
    hp.create_victim(victim2_id, db_cursor)

    # Now let's create session between the one hacker and
    # the multiple sessions
    client.request(
        "POST",
        f"{create_session_path}",
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
        mk.session_manager.get_session(session_id)["hacker_id"] == hacker_id
        and mk.session_manager.get_session(session_id)["victim_id"] == victim1_id
    )

    client.request(
        "POST",
        f"{create_session_path}",
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
    hp.create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    hp.create_victim(victim_id, db_cursor)

    session_id = mk.session_manager.add_session(hacker_id, victim_id)
    # Now kill the session, remove it from the client_list and the sessions map
    # this emulates the condition when the hacker exits a session.
    mk.session_manager.kill_session(session_id)

    # And now let's try to create a session with another
    # victim
    victim2_id = ut.generate_token()
    hp.create_victim(victim2_id, db_cursor)

    client.request(
        "POST",
        f"{create_session_path}",
        body=ut.encode_token(victim2_id),
        headers=verified_hacker_header,
    )

    response = client.getresponse()
    assert response.status == st.OK

    content_length = response.getheader("content-length")
    if content_length is None:
        assert False

    session_id = ut.decode_token(response.read(int(content_length)).decode())

    assert mk.session_manager.get_session_id(hacker_id) == session_id


def test_create_session_properly(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_hacker_header: dict[str, str],
):
    # Create sample victim
    victim_id = ut.generate_token()
    hp.create_victim(victim_id, db_cursor)

    hacker_id = verified_hacker_header["client-id"]
    # Create a sample hacker because we need to use it.
    hp.create_hacker(hacker_id, db_cursor)

    client.request(
        "POST",
        f"{create_session_path}",
        body=ut.encode_token(victim_id),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.OK

    # Also check in the hacking_sessions table
    assert mk.session_manager.check_client_in_session(victim_id)
