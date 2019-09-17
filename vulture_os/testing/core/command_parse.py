import argparse


def command_parse():
    """
    Parse the command
    :return: The parsed command
    """

    parser = argparse.ArgumentParser(description="The standalone testing framework for Vulture")

    parser.add_argument(
        '--output',
        dest='output_level',
        nargs='?',
        default='no',
        choices=['overview', 'global', 'detailed', 'no'],
        help="Output detail level (default: no)"
    )

    parser.add_argument(
        '--no-log',
        dest='save',
        action='store_false',
        default=True,
        help="Disable the diagnostic logging in Vulture"
    )

    return parser.parse_args()
