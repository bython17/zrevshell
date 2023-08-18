from functools import cached_property
from pathlib import Path

from reverse_shell.server.config import Config, get_argument_parser
from reverse_shell.server.database import Database
from reverse_shell.server.dependency_container import ServerContainer
from reverse_shell.server.sessions import InMemorySessionManager, SessionManager

# ---- ServerContainer implementation


class MockContainer(ServerContainer):
    @cached_property
    def base_dir(self) -> Path:
        base_dir = Path(".tmp/server_data/")

        if not base_dir.resolve().is_dir():
            base_dir.mkdir(parents=True)

        return base_dir

    @cached_property
    def config(self) -> Config:
        return Config(
            get_argument_parser().parse_args(
                [
                    "-sd",
                    f"{self.base_dir}",
                    "--connect-ip",
                    "127.0.0.1",
                    "-cid",
                    "60",
                    "-d",
                ]
            )
        )

    @cached_property
    def database(self) -> Database:
        return Database(self.config.database_path, allow_multithreaded_db=True)

    @cached_property
    def session_manager(self) -> SessionManager:
        return InMemorySessionManager()


# Shared container between all tests
container = MockContainer()
config = container.config
database = container.database
session_manager = container.session_manager
