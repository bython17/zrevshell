from sqlite3 import Cursor

import reverse_shell.utils as ut
import tests.mock as mk


# Some helper functions
def create_hacker(hacker_id: str, db_cursor: Cursor):
    db_cursor.execute(
        "INSERT INTO clients VALUES(?, ?, 0.0, 1)", (hacker_id, ut.ClientType.hacker)
    )


def create_victim(
    victim_id: str,
    db_cursor: Cursor,
    victim_info: tuple[str | None, str | None, str | None, str | None, str | None] = (
        None,
        None,
        None,
        None,
        None,
    ),
):
    """Create a victim using the parameters, the order of the victim_info param is as follows:
    host_name, OS, ARCH, CPU and RAM"""
    db_cursor.execute(
        "INSERT INTO clients VALUES(?, ?, 0.0, 1)", (victim_id, ut.ClientType.victim)
    )
    db_cursor.execute(
        "INSERT INTO victim_info VALUES(?, ?, ?, ?, ?, ?)",
        (victim_id, *victim_info),
    )


def get_cmd_endpoint(command: ut.ServerCommand):
    """Get an endpoint of a command"""
    return [
        value for key, value in mk.config.server_cmd_endpoints.items() if key == command
    ][0]
