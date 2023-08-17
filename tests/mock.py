from pathlib import Path

from reverse_shell.server.database import Database
from reverse_shell.server.sessions import InMemorySessions
from reverse_shell.server.config import Config, get_argument_parser

# Let's check if our base directory exists and if it doesn't
# we'll create it.

base_dir = Path(".tmp/server_data/")

if not base_dir.resolve().is_dir():
    base_dir.mkdir(parents=True)

# First initiate the database alone since we need to add another config
database = Database(base_dir / "data.db", allow_multithreaded_db=True)

# Session data
sessions = InMemorySessions()

config = Config(
    get_argument_parser().parse_args(
        ["-sd", f"{base_dir}", "--connect-ip", "127.0.0.1"]
    ),
    database,
)
