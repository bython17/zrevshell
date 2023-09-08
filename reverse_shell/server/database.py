# --- the imports
import sqlite3 as sq

# from http.client import HTTPMessage
from pathlib import Path

import reverse_shell.utils as ut
from reverse_shell.server import ErrorCodes as ec


class Database(ut.DatabaseUtils):
    def __init__(
        self,
        db_path: Path,
        allow_multithreaded_db: bool = True,
    ):
        # ---- Required database schemas
        self.session_data_schema = [
            """
        CREATE TABLE IF NOT EXISTS victim_info(
            id TEXT PRIMARY KEY,
            host_name TEXT,
            os TEXT,
            arch TEXT,
            clock_speed INT,
            ram TEXT,
            FOREIGN KEY(id) REFERENCES clients(client_id)
        )
        """,
            """
        CREATE TABLE IF NOT EXISTS clients(
            client_id TEXT PRIMARY KEY,
            client_type TEXT,
            last_requested REAL,
            status INT
        )
        """,
        ]

        # ---- Creating instances of the parameters
        self.allow_multithreaded_db = allow_multithreaded_db

        # ---- DB initialization
        self.session_data = self.get_database(db_path, self.session_data_schema)
        super().__init__(self.session_data)

    def get_database(self, db_path: Path, db_schema: list[str]) -> sq.Connection:
        """Return a sqlite3 database connection using the user_config_option parameter and validate it using the db_schema option if the database is not provided by the user needed tables will be created using the db_schema list"""

        already_existing_db = True
        if not db_path.resolve().is_file():
            # Inform the user that a new data.db is created
            ut.log("info", "Generated session database.")
            already_existing_db = False

        db = sq.connect(db_path, check_same_thread=not self.allow_multithreaded_db)
        cur = db.cursor()

        # Let's now validate the database based on the db_schema argument
        # if the is_user_given var is True.

        # First we are going to get the SQL command
        # that is created for each of the table created
        # found in the sqlite_master table
        cur.execute("SELECT sql FROM sqlite_master")
        schemas = cur.fetchall()

        # If the database is brand new and doesn't have anything on it and it's
        # user provided then we will treat it like a not user given file. if it makes sense
        if already_existing_db and schemas != []:
            # Unpack the inner tuples in the list
            schemas = [self.strip_schema(i[0]) for i in schemas if i[0] is not None]

            # We need to strip_schema the database schema given to remove
            # spaces and stuff
            stripped_db_schema = [self.strip_schema(i) for i in db_schema]

            # validate the elements
            is_valid = all(
                self.strip_schema(item) in stripped_db_schema for item in schemas
            )
            if not is_valid:
                ut.error_exit(
                    "Invalid SQL database please use one generated by the server.",
                    ec.invalid_file,
                )

        else:
            # Create the tables needed using the db_schema arg
            # we're just going to execute the commands we get from
            # the db_schema
            for schema_cmd in db_schema:
                cur.execute(schema_cmd)

            db.commit()

        return db

    def close_db(self):
        """Close the database connection."""
        self.session_data.close()
