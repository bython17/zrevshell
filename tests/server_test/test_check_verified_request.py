"""Test the check_verified_request method of the server"""
from http import HTTPStatus as st
from http.client import HTTPConnection

import pytest

import reverse_shell.utils as ut
import tests.mock as mk


@pytest.mark.parametrize(
    "headers, res_code",
    [
        ({}, st.BAD_REQUEST),
        (
            {"Authorization": f"Basic {ut.encode_token(mk.config.auth_token)}"},
            st.BAD_REQUEST,
        ),
        (
            {
                "Authorization": "Basic IMessedUpTheToken",
                "client-id": ut.generate_token(),
            },
            st.UNAUTHORIZED,
        ),
        ({"client-id": ut.generate_token()}, st.UNAUTHORIZED),
        (
            {
                "Authorization": f"Basic {ut.encode_token(mk.config.auth_token)}",
                "client-id": ut.generate_token(),
            },
            st.OK,
        ),
    ],
)
def test_check_verified_request(
    client: HTTPConnection, headers: dict[str, str], res_code: st
):
    # Let's send our request to the server using the client fixture
    # let's update the signature because now / is open to everyone.
    client.request("GET", "/verify", headers=headers)
    assert client.getresponse().status == res_code
