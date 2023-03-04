from reverse_shell.server import config

configuration = config.Config(config.get_argument_parser().parse_args())
