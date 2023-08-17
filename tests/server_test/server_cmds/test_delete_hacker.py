from http import HTTPStatus as st
from http.client import HTTPConnection
from sqlite3 import Cursor

import reverse_shell.utils as ut
import tests.server_test.helper as hp

# Command ID
delete_hacker_path = hp.get_cmd_id(ut.ServerCommands.delete_hacker)


def test_delete_hacker(
    client: HTTPConnection, db_cursor: Cursor, verified_hacker_header: dict[str, str]
):
    hacker_id = verified_hacker_header["client-id"]
    hp.create_hacker(hacker_id, db_cursor)

    # Now request a deletion of the hacker
    client.request(
        "DELETE", f"/{delete_hacker_path}", body=None, headers=verified_hacker_header
    )

    assert client.getresponse().status == st.OK

    # Now check if the database still contains the hacker
    db_cursor.execute("SELECT client_id FROM clients WHERE client_id=?", [hacker_id])
    assert db_cursor.fetchall() == []
