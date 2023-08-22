import json as js
from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import reverse_shell.utils as ut
import tests.server_test.helper as hp

# Command ID
list_victims_path = hp.get_cmd_endpoint(ut.ServerCommand.list_victims)


def test_list_victims_with_no_victims(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    hp.create_hacker(hacker_id, db_cursor)

    # Now let's request the server to list the victims, but it should
    # produce no victims i.e an empty array since there are no in the server
    client.request("GET", f"{list_victims_path}", headers=verified_hacker_header)

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
    hp.create_hacker(hacker_id, db_cursor)

    # Now let's insert some victims in the database
    client1_id = ut.generate_token()
    client2_id = ut.generate_token()
    client3_id = ut.generate_token()

    client1_info = ("someone", "Windows", "x86", "5th Gen Intel", "8GB")
    client2_info = ("somebody", "MacOS", "ARM", "M2 PRO", "32GB")
    client3_info = ("something", "Debian Linux", "x64", "Ryzen 7 5800", "16GB")

    hp.create_victim(client1_id, db_cursor, client1_info)
    hp.create_victim(client2_id, db_cursor, client2_info)
    hp.create_victim(client3_id, db_cursor, client3_info)

    client.request("GET", f"{list_victims_path}", headers=verified_hacker_header)
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
