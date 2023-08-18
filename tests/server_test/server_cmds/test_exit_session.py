from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import reverse_shell.utils as ut
import tests.mock as mk
import tests.server_test.helper as hp

# Command ID
exit_session_path = hp.get_cmd_id(ut.ServerCommands.exit_session)


def test_exit_session_while_not_in_one(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    hp.create_hacker(hacker_id, db_cursor)

    # Now try to exit without providing a session_id
    client.request("DELETE", f"{exit_session_path}", headers=verified_hacker_header)

    assert client.getresponse().status == st.BAD_REQUEST


def test_exit_session_when_in_session_but_with_fake_session(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    hp.create_hacker(hacker_id, db_cursor)

    # Ok let's put ourselves in session
    mk.session_manager.add_session(hacker_id, ut.generate_token())
    fake_session_id = ut.encode_token(ut.generate_token())

    client.request(
        "DELETE",
        f"{exit_session_path}",
        body=fake_session_id,
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


def test_exit_session_in_valid_session(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    hp.create_hacker(hacker_id, db_cursor)

    # Insert our selves in session
    session_id = mk.session_manager.add_session(hacker_id, ut.generate_token())

    # Now request the server with the correct session
    client.request(
        "DELETE",
        f"{exit_session_path}",
        body=ut.encode_token(session_id),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.OK

    # And now check if the same thing is reflected in the
    # sessions
    session = mk.session_manager.get_session(session_id)

    assert not session["alive"]
