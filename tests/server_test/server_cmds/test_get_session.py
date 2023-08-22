from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import reverse_shell.utils as ut
import tests.mock as mk
import tests.server_test.helper as hp

# Command ID
get_session_path = hp.get_cmd_endpoint(ut.ServerCommand.get_session)


def test_get_session_without_a_session(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    client_id = verified_client_header["client-id"]
    hp.create_victim(client_id, db_cursor)

    # Let's request to get a session even though we are not
    # in one
    client.request("GET", f"{get_session_path}", headers=verified_client_header)

    assert client.getresponse().status == st.NOT_FOUND


def test_get_session_with_a_session(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    client_id = verified_client_header["client-id"]
    hp.create_victim(client_id, db_cursor)

    # Let's put the victim in a session with the hacker(well a fake one)
    session_id = mk.session_manager.add_session(client_id, ut.generate_token())

    client.request("GET", f"{get_session_path}", headers=verified_client_header)

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
