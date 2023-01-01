import platform
import reverse_shell.utils as ut
import sys
import subprocess
import shlex
from reverse_shell import __app_name__, __version__


def csplit(string: str, splitter=" ") -> list[str]:
    return [i for i in string.split(splitter) if i != '']


def get_command_and_args(user_input):
    command_and_args = shlex.split(user_input)  # Splitting the user_input into a list

    if command_and_args:
        # Checking if there are args and assigning an empty
        # list if there are no args
        if len(command_and_args) == 1:
            command, args = command_and_args[0], [(), {}]
        else:
            arguments = command_and_args[1:]
            positional_arguments = []
            optional_arguments = {}

            for argument in arguments:
                if "=" in argument and len(csplit(argument, '=')) == 2 and csplit(argument, '=')[0].startswith("--"):
                    key_value = csplit(argument, "=")
                    optional_arguments[key_value[0][2:]] = key_value[1]
                else:
                    positional_arguments.append(argument)

            # if there are args then they are stored in a tuple
            command, args = command_and_args[0], [tuple(positional_arguments), optional_arguments]

        return (command, args)
    else:
        return None


def command_line(commands_with_funcs: dict):
    command = ""
    while command != "exit":
        user_input = input(f"hacker@{platform.uname().node}# ")
        command_and_args = get_command_and_args(user_input)

        # Check if the we didn't get any command
        if command_and_args is not None:
            command, args = command_and_args
            postional_args, optional_args = args
        else:
            continue

        if command in commands_with_funcs:
            func, required_len_args, available_optional_args, default_args = commands_with_funcs[command]

            positional_argument_check = required_len_args == len(postional_args)
            optional_argument_check = all([True if arg in available_optional_args else False for arg in optional_args])

            if positional_argument_check and optional_argument_check:
                func(*postional_args, *default_args, **optional_args)
            elif not positional_argument_check:
                ut.log("error", f"expected {'None' if required_len_args == 0 else required_len_args} arguments, but got {len(postional_args)} arguments")
            elif not optional_argument_check:
                # Filter the optional argument that is not described
                false_optional_arg = [f"'{arg}'" for arg in optional_args if arg not in available_optional_args]
                ut.log("error", f"optional arguments: {' and '.join(false_optional_arg)} are not valid.")

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
    help_message = f"""This is the {__app_name__} v{__version__}

    Here are the commands to play with:

        help => dislplay this message
        clear => clear the screen
        list-victims => list all online victims
        attack[victim_id] => attack the victim online with their id
        exit => quit the app"""

    commands_with_funcs = {
        # command: (function, required_positional_arguments, available_optional_arguments,  default_arguments)
        "help": (help_hacker, 0, [], [help_message]),
        "exit": (sys.exit, 0, [], []),
        "clear": (clear, 0, [], [])
    }

    for key in additional_commands:
        commands_with_funcs[key] = additional_commands[key]

    # Running the command line
    command_line(commands_with_funcs)


if __name__ == "__main__":
    initiate()
