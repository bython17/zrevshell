from pathlib import Path

from reverse_shell.server import config

# Let's check if our base directory exists and if it doesn't
# we'll create it.

base_dir = Path(".tmp/server_data/")

if not base_dir.resolve().is_dir():
    base_dir.mkdir(parents=True)

configuration = config.Config(
    config.get_argument_parser().parse_args(["-b", f"{base_dir}"]),
    allow_multi_thread_db_access=True,
)
