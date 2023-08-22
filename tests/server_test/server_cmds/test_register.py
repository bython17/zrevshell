import json as js
from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import pytest

import reverse_shell.utils as ut
import tests.mock as mk
import tests.server_test.helper as hp

# Command ID
register_cmd_path = hp.get_cmd_endpoint(ut.ServerCommand.register)


@pytest.mark.parametrize(
    "client_type",
    [(ut.ClientType.hacker.value), (ut.ClientType.victim.value)],
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
        f"{register_cmd_path}",
        headers={
            **verified_client_header,
            "client-type": client_type.__str__(),
            "hacker-token": ut.encode_token(mk.config.hacker_token),
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
        f"{register_cmd_path}",
        body=encoded_body,
        headers={
            **verified_client_header,
            "client-type": ut.ClientType.victim.value.__str__(),
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
    hp.create_victim(client_id, db_cursor)

    # Now let's check if the requests yield a conflict response
    client.request(
        "POST",
        f"{register_cmd_path}",
        headers={
            **verified_client_header,
            "client-type": ut.ClientType.victim.value.__str__(),
        },
    )

    assert client.getresponse().status == st.CONFLICT
