import reverse_shell.utils as ut
from configuration import configuration as config
from http import HTTPStatus as st
from http.client import HTTPConnection
import pytest


@pytest.mark.parametrize(
    "token, res_code",
    [
        ("ThisIsAFakeToken", st.UNAUTHORIZED),
        (config.auth_token, st.OK),
    ],
)
def test_authorization(client: HTTPConnection, token, res_code: st):
    # Let's check if authorization works by testing it with the real and
    # fake token.
    client.request(
        "GET",
        "/",
        headers={
            "Authorization": f"Basic {ut.encode_token(token)}",
            "client-id": "random-client-id",
        },
    )
    assert client.getresponse().status == res_code
