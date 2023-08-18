from abc import ABC, abstractmethod
from argparse import ArgumentParser
from functools import cached_property
import reverse_shell.server.config as cfg
import reverse_shell.server.database as db
import reverse_shell.server.sessions as ss


class ServerContainer(ABC):
    @property
    @abstractmethod
    def database(self) -> db.Database:
        pass

    @property
    @abstractmethod
    def config(self) -> cfg.Config:
        pass

    @property
    @abstractmethod
    def session_manager(self) -> ss.SessionManager:
        pass


# ---- Default implementation
class DefaultServerContainer(ServerContainer):
    @cached_property
    def parser(self) -> ArgumentParser:
        return cfg.get_argument_parser()

    @cached_property
    def config(self) -> cfg.Config:
        return cfg.Config(self.parser.parse_args())

    @cached_property
    def database(self) -> db.Database:
        return db.Database(self.config.database_path)

    @cached_property
    def session_manager(self) -> ss.SessionManager:
        return ss.InMemorySessionManager()
