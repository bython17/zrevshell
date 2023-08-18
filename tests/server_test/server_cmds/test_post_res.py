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
post_res_path = hp.get_cmd_id(ut.ServerCommands.post_res)


def test_post_res_with_dead_session(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # First create the victim
    victim_id = verified_client_header["client-id"]
    hp.create_victim(victim_id, db_cursor)

    # Now let's prepare the request body
    req_body = js.dumps(
        {
            "session_id": ut.generate_token(),  # This supposed to be the non-existing session_id
            "response": {"stdout": "Some random response", "stderr": ""},
            "empty": False,
            "command_status_code": None,
            "failed_to_execute": False,
        }
    )

    # Now send this data to the server
    client.request(
        "POST",
        f"{post_res_path}",
        body=ut.encode_token(req_body),
        headers=verified_client_header,
    )

    assert client.getresponse().status == st.NOT_ACCEPTABLE


def test_post_res_using_a_session_id_belonging_to_another_session(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Let's start by creating the victim and the hacker
    victim_id = verified_client_header["client-id"]
    hp.create_victim(victim_id, db_cursor)

    hacker_id = ut.generate_token()
    hp.create_hacker(hacker_id, db_cursor)

    # and now let's put the victim and the hacker in different sessions
    # with different people
    session_id = mk.session_manager.add_session(hacker_id, ut.generate_token())
    mk.session_manager.add_session(ut.generate_token(), victim_id)

    # build the request_body
    req_body = js.dumps(
        {
            "session_id": session_id,
            "response": {"stdout": "Just a simple response", "stderr": ""},
            "empty": False,
            "command_status_code": None,
            "failed_to_execute": False,
        }
    )

    # Now try requesting the server
    client.request(
        "POST",
        f"{post_res_path}",
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
    hp.create_victim(victim_id, db_cursor)

    # Now let's just send the request
    client.request("POST", f"{post_res_path}", headers=verified_client_header)

    assert client.getresponse().status == st.BAD_REQUEST


def test_post_res_with_invalid_body(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Same with the above this differs because it is an invalid body
    # rather no body at all like the before
    victim_id = verified_client_header["client-id"]
    hp.create_victim(victim_id, db_cursor)

    req_body = js.dumps({"response": "Something I can help?"})

    # Now let's just send the request
    client.request(
        "POST",
        f"{post_res_path}",
        body=ut.encode_token(req_body),
        headers=verified_client_header,
    )

    assert client.getresponse().status == st.BAD_REQUEST


def test_post_res_with_with_empty_flag(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Now let's do everything as expected and try it
    victim_id = verified_client_header["client-id"]
    hp.create_victim(victim_id, db_cursor)

    hacker_id = ut.generate_token()
    hp.create_hacker(hacker_id, db_cursor)

    # Putting the hacker and victim inside a session
    session_id = mk.session_manager.add_session(hacker_id, victim_id)

    req_body = js.dumps(
        {
            "session_id": session_id,
            "response": {"stdout": "", "stderr": ""},
            "empty": True,
            "command_status_code": None,
            "failed_to_execute": False,
        }
    )

    client.request(
        "POST",
        f"{post_res_path}",
        body=ut.encode_token(req_body),
        headers=verified_client_header,
    )

    # Now check both the status code and the session communications if the needed
    # response is added in the correct place.
    response = client.getresponse()

    assert response.status == st.OK

    remote_res = mk.session_manager.get_response(session_id)

    assert remote_res == []


def test_post_res_properly(
    client: HTTPConnection, db_cursor: Cursor, verified_client_header: dict[str, str]
):
    # Now let's do everything as expected and try it
    victim_id = verified_client_header["client-id"]
    hp.create_victim(victim_id, db_cursor)

    hacker_id = ut.generate_token()
    hp.create_hacker(hacker_id, db_cursor)

    # Putting the hacker and victim inside a session
    session_id = mk.session_manager.add_session(hacker_id, victim_id)
    res = {"stdout": "testing", "stderr": ""}

    req_body = js.dumps(
        {
            "session_id": session_id,
            "response": res,
            "empty": False,
            "command_status_code": None,
            "failed_to_execute": False,
        }
    )

    client.request(
        "POST",
        f"{post_res_path}",
        body=ut.encode_token(req_body),
        headers=verified_client_header,
    )

    # Now check both the status code and the session communications if the needed
    # response is added in the correct place.
    response = client.getresponse()

    assert response.status == st.OK

    remote_res = mk.session_manager.get_response(session_id)[0]["response"]

    assert remote_res == res


@pytest.mark.parametrize(
    "body",
    [
        (
            {
                "response": "hello",  # should be a dict
                "empty": False,
                "command_status_code": None,
                "failed_to_execute": False,
            }
        ),
        (
            {
                "response": {"stdout": "finished", "stderr": ""},
                "empty": [],  # should be a bool
                "command_status_code": 0,
                "failed_to_execute": False,
            }
        ),
        (
            {
                "response": {"stdout": "finished", "stderr": ""},
                "empty": False,
                "command_status_code": "hey",  # should be an int or None
                "failed_to_execute": False,
            }
        ),
        (
            {
                "response": {"stdout": "finished", "stderr": ""},
                "empty": False,
                "command_status_code": 0,
                "failed_to_execute": [],  # should be a bool
            }
        ),
    ],
)
def test_post_res_with_invalid_types(
    client: HTTPConnection,
    db_cursor: Cursor,
    verified_client_header: dict[str, str],
    body: Response,
):
    # Now let's do everything as expected and try it
    victim_id = verified_client_header["client-id"]
    hp.create_victim(victim_id, db_cursor)

    hacker_id = ut.generate_token()
    hp.create_hacker(hacker_id, db_cursor)

    # Put em in a session
    session_id = mk.session_manager.add_session(hacker_id, victim_id)
    json_string = js.dumps({"session_id": session_id, **body})

    client.request(
        "POST",
        f"{post_res_path}",
        body=ut.encode_token(json_string),
        headers=verified_client_header,
    )

    response = client.getresponse()
    assert response.status == st.BAD_REQUEST
