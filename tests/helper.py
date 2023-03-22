from pathlib import Path

from reverse_shell.server import server_helper

# Let's check if our base directory exists and if it doesn't
# we'll create it.

base_dir = Path(".tmp/server_data/")

if not base_dir.resolve().is_dir():
    base_dir.mkdir(parents=True)

# First initiate the database alone since we need to add another config
database = server_helper.Database(None, base_dir, allow_multithreaded_db=True)

# Session data
sessions = server_helper.Sessions()

config = server_helper.Config(
    server_helper.get_argument_parser().parse_args(["-b", f"{base_dir}"]), database
)
