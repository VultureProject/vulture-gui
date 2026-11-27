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
__doc__ = 'Helpers of the run_api_collectors command: fork-safety check and collector child entry point'

# The collectors are forked by the run_api_collectors management command, which the
# api_clients_parser cron job starts as a separate manage.py process (see api_clients_parser.py):
# the cron process already holds an open MongoClient when the job starts, and forking from a
# process whose monitor threads may be inside OpenSSL can leave a native lock locked forever in
# the child. The command process loads Django, never opens a database connection nor starts a
# thread (no system checks), and forks the collectors with a plain fork().

import ctypes
import threading
from time import sleep


class ForkUnsafeError(RuntimeError):
    """ Raised when the current process cannot fork the collectors safely """


def _load_setproctitle():
    """ Resolve FreeBSD's setproctitle(3) once, from the libc already loaded in this process.

    Returns None where libc does not provide it (Linux): titles are then silently skipped.
    Resolved at import time so that forked collectors inherit it and never need to look it up.
    """
    for library in (None, "libc.so.7"):
        try:
            func = ctypes.CDLL(library).setproctitle
        except (OSError, AttributeError):
            continue
        func.restype = None
        return func
    return None


_setproctitle = _load_setproctitle()

# The kernel rejects (silently) a title longer than kern.ps_arg_cache_limit, 256 bytes by
# default: keep a margin for the struct the kernel stores it in.
_TITLE_MAX_BYTES = 200


def set_process_title(title):
    """Show `title` as this process' command line in ps/top/procstat output."""
    if _setproctitle is None:
        return
    try:
        # A leading '-' makes setproctitle(3) replace the whole command line
        # instead of prefixing the title with the program name.
        _setproctitle(b"-%s", title.encode("utf-8", "replace")[:_TITLE_MAX_BYTES])
    except (OSError, TypeError, ctypes.ArgumentError):
        pass


def check_fork_safe():
    """ Raise ForkUnsafeError unless this process can fork() safely: a single thread and no
    database connection.

    Collectors must never be forked from a process holding an open MongoClient: its monitor
    threads run TLS handshakes, and a native (OpenSSL/libc) lock held by one of them at fork()
    time stays locked forever in the child, which then hangs before doing anything.
    """
    from django.db import connections

    threads = [t.name for t in threading.enumerate()]
    open_connections = [conn.alias for conn in connections.all(initialized_only=True)
                        if conn.connection is not None]
    if len(threads) != 1 or open_connections:
        raise ForkUnsafeError(f"process is not fork-safe: threads={threads}, "
                              f"open database connection(s): {open_connections or 'none'}. "
                              "Something opened a database connection or started a thread at import time.")


def wait_processes(processes):
    """ Block until every process of the list has exited """
    processes = list(processes)
    while processes:
        sleep(1)
        for p in list(processes):
            p.join(0)
            if not p.is_alive():
                processes.remove(p)


def run_collector(frontend):
    """Entry point of a collector child process.

    `frontend` is a frontend id (int) or name (str): it is resolved here, with a MongoClient
    that belongs to this process only, never reused from the parent.
    """
    set_process_title(f"api_collector [frontend={frontend!r}]")
    from services.frontend.models import Frontend

    from gui.crontab.api_clients_parser import execute_parser, logger

    lookup = {"pk": frontend} if isinstance(frontend, int) else {"name": frontend}
    try:
        frontend = Frontend.objects.get(**lookup)
    except Frontend.DoesNotExist:
        logger.warning(f"API Collector: frontend {lookup} does not exist, skipping",
                       extra={'frontend': str(frontend)})
        return
    collector_id = frontend.api_collector.pk if frontend.api_collector else None
    set_process_title(f"api_collector [frontend={frontend.pk} collector={collector_id}] {frontend.name} ({frontend.api_parser_type})")
    execute_parser(frontend)
