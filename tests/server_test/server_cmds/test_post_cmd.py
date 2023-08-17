import json as js
from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import reverse_shell.utils as ut
import tests.mock as mk
import tests.server_test.helper as hp

# Command ID
post_cmd_path = hp.get_cmd_id(ut.ServerCommands.post_cmd)


def test_post_cmd_with_dead_session(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # That generally means no victim was ever created
    hacker_id = verified_hacker_header["client-id"]
    hp.create_hacker(hacker_id, db_cursor)

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
    hp.create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    hp.create_victim(victim_id, db_cursor)

    # Let's put the victim in session with supposedly another hacker
    session_id = mk.sessions.add_session(ut.generate_token(), victim_id)

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
    hp.create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    hp.create_victim(victim_id, db_cursor)

    # And let's put the hacker inside another session
    mk.sessions.add_session(hacker_id, ut.generate_token())
    # Let's put the victim in session with supposedly another hacker
    session_id = mk.sessions.add_session(ut.generate_token(), victim_id)

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
    hp.create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    hp.create_victim(victim_id, db_cursor)

    # Let's put the hacker in session with the victim
    mk.sessions.add_session(hacker_id, victim_id)

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
    hp.create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    hp.create_victim(victim_id, db_cursor)

    # putting the hacker in session with the victim
    session_id = mk.sessions.add_session(hacker_id, victim_id)

    request_body = js.dumps({"session_id": session_id, "command": "", "empty": True})

    client.request(
        "POST",
        f"/{post_cmd_path}",
        body=ut.encode_token(request_body),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.CREATED

    # Check if the session comm is modified accordingly
    assert mk.sessions.get_command(session_id) is None


def test_post_cmd_properly(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Create the victim and the hacker
    hacker_id = verified_hacker_header["client-id"]
    hp.create_hacker(hacker_id, db_cursor)

    victim_id = ut.generate_token()
    hp.create_victim(victim_id, db_cursor)

    # putting the hacker in session with the victim
    session_id = mk.sessions.add_session(hacker_id, victim_id)

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
    assert mk.sessions.get_command(session_id) == cmd
