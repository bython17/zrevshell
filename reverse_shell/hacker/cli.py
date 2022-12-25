import platform
import reverse_shell.utils as ut
import sys
import subprocess
from reverse_shell import __app_name__, __version__


def get_command_and_args(user_input):
    command_and_args = [i for i in user_input.split() if i]  # Splitting the user_input by a space and removing unwanted spaces

    if command_and_args:
        # Checking if there are args and assigning an empty
        # list if there are no args
        if len(command_and_args) == 1:
            command, args = command_and_args[0], ()
        else:
            # if there are args then they are stored in a list
            command, args = command_and_args[0], tuple(command_and_args[1:])

        return (command, args)
    else:
        return None


def command_line(commands_with_funcs):
    command = ""
    while command != "exit":
        user_input = input(f"hacker@{platform.uname().node}# ").lower()
        command_and_args = get_command_and_args(user_input)

        # Check if the we didn't get any command
        if command_and_args is not None:
            command, args = command_and_args
        else:
            continue

        if command in commands_with_funcs:
            func, required_len_args, default_args = commands_with_funcs[command]
            if required_len_args == len(args):
                func(*args, *default_args)
            else:
                ut.log("error", f"expected {'None' if required_len_args == 0 else required_len_args} arguments, but got {len(args)} arguments")
        else:
            ut.log("error", f"command '{command}' was not found, type 'help' to see the available commands")


def help_hacker(help_message):
    print(help_message)


def clear():
    if sys.platform[:3] == "win":
        subprocess.run("cls")
    else:
        subprocess.run("clear")


def initiate(additional_commands: dict = {}):
    help_message = f"""
    This is the {__app_name__} v{__version__}

    Here are the commands to play with:

        help => dislplay this message
        clear => clear the screen
        list-victims => list all online victims
        attack[victim_id] => attack the victim online with their id
        exit => quit the app
    """

    commands_with_funcs = {
        "help": (help_hacker, 0, [help_message]),
        "exit": (sys.exit, 0, []),
        "clear": (clear, 0, [])
    }

    for key in additional_commands:
        commands_with_funcs[key] = additional_commands[key]

    # Running the command line
    command_line(commands_with_funcs)


if __name__ == "__main__":
    initiate()
