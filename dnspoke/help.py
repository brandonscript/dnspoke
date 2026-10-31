"""Consistent command help, including help paths and bare command groups."""

from __future__ import annotations

import argparse
import sys


def format_help(parser: argparse.ArgumentParser, description: str, examples: str = "") -> None:
    parser.description = description
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser._positionals.title = "Arguments"
    parser._optionals.title = "Options"
    parser._option_string_actions["--help"].help = "Show this help and exit"
    parser.epilog = (
        "Examples:\n" + examples + "\n\n" if examples else ""
    ) + "Use dnspoke help COMMAND for more information."


def add_command(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    summary: str,
    description: str = "",
    examples: str = "",
    aliases: tuple[str, ...] = (),
) -> argparse.ArgumentParser:
    parser = commands.add_parser(name, aliases=list(aliases), help=summary)
    format_help(parser, description or summary, examples)
    return parser


def subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return {
                name: child
                for name, child in action.choices.items()
                if isinstance(child, argparse.ArgumentParser)
            }
    return {}


def parse_arguments(
    parser: argparse.ArgumentParser, argv: list[str] | None = None
) -> argparse.Namespace | None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    current = parser
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "help":
            for topic in arguments[index + 1 :]:
                choices = subcommands(current)
                if topic not in choices or topic == "help":
                    current.error(
                        f"Unknown help topic: {topic}. "
                        f"Run {current.prog} --help for available commands."
                    )
                current = choices[topic]
            current.print_help()
            return None
        if token in ("-h", "--help", "--version"):
            break
        option, separator, _ = token.partition("=")
        action = current._option_string_actions.get(option)
        if action is not None:
            if action.nargs == 0:
                index += 1
                continue
            if action.nargs is None:
                index += 1 if separator else 2
                continue
            break
        choices = subcommands(current)
        if token not in choices:
            break
        current = choices[token]
        index += 1
    if index == len(arguments) and subcommands(current):
        current.print_help()
        return None
    return parser.parse_args(arguments)


def add_help_command(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    help_parser = add_command(
        commands, "help", "Show help for a command", examples="  dnspoke help admin invite"
    )
    help_parser.add_argument(
        "command", nargs="*", metavar="COMMAND", help="Command path, for example: admin invite"
    )
