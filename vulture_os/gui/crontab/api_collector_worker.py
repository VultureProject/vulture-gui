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
__doc__ = 'Forkserver preload and child entry point for the API collectors'

# This module is imported by the multiprocessing forkserver helper process (see
# api_clients_parser.py) and by the collector children forked from it. It must stay free of
# Django model imports at module level, and it must never open a database connection or start
# a thread: the whole point of the helper is to fork collectors from a process that has no
# MongoClient and no native lock in flight.

import os

import django
from django.apps import apps


def ensure_django():
    """Make the Django app registry ready in this process (no-op when already done)."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulture_os.settings")
    if not apps.ready:
        django.setup()


def run_collector(frontend_id):
    """Entry point of a collector child process.

    The frontend is fetched again here, with a MongoClient that belongs to this process only.
    """
    ensure_django()
    from services.frontend.models import Frontend
    from gui.crontab.api_clients_parser import execute_parser, logger

    try:
        frontend = Frontend.objects.get(pk=frontend_id)
    except Frontend.DoesNotExist:
        logger.warning(f"API Collector: frontend {frontend_id} does not exist anymore, skipping",
                       extra={'frontend': str(frontend_id)})
        return
    execute_parser(frontend)


# Preload: load Django once in the forkserver helper so that every collector forked from it
# starts with the app registry ready.
ensure_django()
