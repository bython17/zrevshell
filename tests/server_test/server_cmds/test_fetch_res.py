import json as js
from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import pytest

import reverse_shell.utils as ut
import tests.mock as mk
import tests.server_test.helper as hp
from reverse_shell.server.sessions import Response

# Command ID
fetch_res_path = hp.get_cmd_endpoint(ut.ServerCommand.fetch_res)


def test_fetch_res_without_providing_session_id(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Ok first create the hacker and then request the server
    # for fetching a response which should respond as bad_request since
    # we don't even provide the body needed

    hacker_id = verified_hacker_header["client-id"]
    hp.create_hacker(hacker_id, db_cursor)

    client.request("GET", f"{fetch_res_path}", headers=verified_hacker_header)

    assert client.getresponse().status == st.BAD_REQUEST


def test_fetch_res_with_invalid_sessions(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    # Now we need to request the server with a session_id that doesn't
    # exist.

    hacker_id = verified_hacker_header["client-id"]
    hp.create_hacker(hacker_id, db_cursor)

    fake_session_id = ut.generate_token()

    client.request(
        "GET",
        f"{fetch_res_path}",
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
    hp.create_hacker(hacker_id, db_cursor)

    other_session = mk.session_manager.add_session(
        ut.generate_token(), ut.generate_token()
    )
    # putting our selves in session to bypass the session check
    mk.session_manager.add_session(hacker_id, ut.generate_token())

    client.request(
        "GET",
        f"{fetch_res_path}",
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
    hp.create_hacker(hacker_id, db_cursor)

    other_session = mk.session_manager.add_session(
        ut.generate_token(), ut.generate_token()
    )

    client.request(
        "GET",
        f"{fetch_res_path}",
        body=ut.encode_token(other_session),
        headers=verified_hacker_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


@pytest.mark.parametrize(
    "response",
    [
        (
            {
                "response": {"stdout": "just about to finish", "stderr": ""},
                "command_status_code": None,
                "failed_to_execute": False,
            }
        ),
        (
            {
                "response": {"stdout": "finished", "stderr": ""},
                "command_status_code": 0,
                "failed_to_execute": False,
            }
        ),
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
    hp.create_hacker(hacker_id, db_cursor)

    # Put a hacker and victim in session
    session_id = mk.session_manager.add_session(hacker_id, ut.generate_token())

    # Now emulate the case where we send the finished response
    mk.session_manager.insert_response(
        session_id,
        response["response"]["stdout"],
        response["response"]["stderr"],
        response["command_status_code"],
        response["failed_to_execute"],
    )

    # Now try to fetch_res
    client.request(
        "GET",
        f"{fetch_res_path}",
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
