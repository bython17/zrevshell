import json as js
from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import reverse_shell.utils as ut
import tests.mock as mk
from reverse_shell.server.sessions import Response
from tests.server_test.server_cmds.test_create_session import create_session_path
from tests.server_test.server_cmds.test_exit_session import exit_session_path
from tests.server_test.server_cmds.test_fetch_cmd import fetch_cmd_path
from tests.server_test.server_cmds.test_fetch_res import fetch_res_path
from tests.server_test.server_cmds.test_get_session import get_session_path
from tests.server_test.server_cmds.test_post_cmd import post_cmd_path
from tests.server_test.server_cmds.test_post_res import post_res_path
from tests.server_test.server_cmds.test_register import register_cmd_path


def test_normal_flow(
    db_cursor: Cursor,
    verified_client_header: dict[str, str],
    verified_hacker_header: dict[str, str],
):
    # We need to be using our own clients not the ones defined
    # as fixtures.
    hacker_client = HTTPConnection(mk.config.ip, mk.config.port)
    victim_client = HTTPConnection(mk.config.ip, mk.config.port)

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
        "response": {"stdout": "something", "stderr": ""},
        "empty": False,
        "command_status_code": None,
        "failed_to_execute": False,
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
    assert not mk.sessions.check_session_exists(session_id)
