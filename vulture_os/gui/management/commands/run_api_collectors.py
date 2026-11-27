#!/home/vlt-os/env/bin/python
"""This file is part of Vulture OS.

Vulture OS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture OS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture OS.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Théo Bertin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Run API collectors, each in its own forked process'

import json
import logging
import multiprocessing
import sys

from django.core.management.base import BaseCommand, CommandError

from gui.crontab.api_collector_worker import (ForkUnsafeError, check_fork_safe, run_collector,
                                              set_process_title, wait_processes)


def echo_logs_to_stdout(logger):
    """ Duplicate the records of `logger` to stdout, with the formatter of its file handler """
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logger.level)
    formatter = next((h.formatter for h in logger.handlers if h.formatter is not None), None)
    if formatter:
        handler.setFormatter(formatter)
    logger.addHandler(handler)


class Command(BaseCommand):
    help = ("Run the API collectors of the given frontends, each in a forked child process.\n"
            "By hand: manage.py run_api_collectors 'Frontend name' ['Other frontend' ...]\n"
            "         manage.py run_api_collectors --ids 12 [13 ...]\n"
            "The api_clients_parser cron job uses --stdin to pass the ids of the frontends to run.")

    # No system checks here: they import the URL conf, hence forms that query the database at
    # import time, which would open a MongoClient in this process and make it unsafe to fork.
    requires_system_checks = []

    def add_arguments(self, parser):
        parser.add_argument("frontends", nargs="*", metavar="FRONTEND",
                            help="names of the frontends to run (ids with --ids)")
        parser.add_argument("--ids", action="store_true",
                            help="interpret FRONTEND arguments as frontend ids instead of names")
        parser.add_argument("--stdin", action="store_true",
                            help="read a JSON list of frontend ids from stdin (used by the cron job)")

    def handle(self, *args, **options):
        set_process_title("api_collector spawner")

        # Import the cron module here rather than in the children: importing it configures
        # logging (dictConfig), which would reset the handlers of the api_parser logger and
        # drop the stdout handler added below. Forked children inherit the configured logger.
        from gui.crontab.api_clients_parser import logger
        # Manual run (frontends given on the command line) or interactive terminal: show the
        # collectors' logs on stdout as well as in the api_parser log file.
        if not options["stdin"] or sys.stdout.isatty():
            echo_logs_to_stdout(logger)

        # This process must be a clean one to fork from: refuse to run rather than risk hanging
        # the collectors (see api_collector_worker.check_fork_safe).
        try:
            check_fork_safe()
        except ForkUnsafeError as e:
            raise CommandError(str(e))

        if options["stdin"]:
            try:
                selectors = json.load(sys.stdin)
            except ValueError as e:
                raise CommandError(f"invalid JSON on stdin: {e}")
            if not isinstance(selectors, list) or not all(isinstance(s, int) for s in selectors):
                raise CommandError("stdin must hold a JSON list of frontend ids")
        elif options["ids"]:
            try:
                selectors = [int(f) for f in options["frontends"]]
            except ValueError as e:
                raise CommandError(f"invalid frontend id: {e}")
        else:
            selectors = options["frontends"]

        if not selectors:
            self.stdout.write("No frontend to run")
            return

        # The collectors (and whatever they fork themselves) use a plain fork() of this process,
        # which has no thread and no MongoClient: each child opens its own connection.
        ctx = multiprocessing.get_context("fork")
        processes = []
        for selector in selectors:
            p = ctx.Process(target=run_collector, name=f"api_collector_{selector}", args=(selector,))
            p.start()
            processes.append(p)
        wait_processes(processes)
