#!/home/vlt-os/env/bin/python3
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
__author__ = "Théo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Python script used to generate Rsyslog-compatible timezone offset lookup tables'

import json
import os
import sys
from datetime import datetime, timezone
from toolkit.datetime.timezone import (
    get_local_boundaries,
    get_offset_string,
    get_timezone_transitions,
    get_transient_timezones,
)
from zoneinfo import ZoneInfo
from system.config.models import write_conf
from system.exceptions import VultureSystemConfigError
from services.exceptions import ServiceExit

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')

TZFILES_FOLDER = os.path.join(settings.LOCALETC_PATH, "rsyslog.d/_lookup_tables/timezones/")


def _get_rsyslog_sparse_arrays(tz: ZoneInfo, start_date: datetime, end_date: datetime):
    timestamps = get_timezone_transitions(tz, start_date, end_date)
    localized_array = set()
    utc_array = set()
    for index, timestamp in enumerate(timestamps):
        if index == 0:
            localized_array.add((int(timestamp['local_timestamp'].timestamp()), get_offset_string(timestamp['offset_seconds'])))
        elif index + 1 < len(timestamps):
            prev_timestamp = timestamps[index-1]
            next_timestamp = timestamps[index+1]
            localized_array.update(set(get_local_boundaries(timestamp, prev_timestamp, next_timestamp)))
        utc_array.add((int(timestamp['utc_timestamp'].timestamp()), get_offset_string(timestamp['offset_seconds'])))

    return utc_array, localized_array


def _generate_rsyslog_lookup_db(data):
    database = {
        "version": 1,
        "nomatch": "",
        "type": "sparseArray",
        "table": []
    }
    for index, transition in data:
        entry = {
            "index": index,
            "value": transition,
        }
        try:
            # Add a n additional entry (not read by rsyslog) for debugging and human file reading
            entry["dbgtime"] = datetime.fromtimestamp(index).isoformat() + "Z"
        except ValueError:
            pass
        database['table'].append(entry)

    return database


def generate_timezone_dbs():
    now = datetime.now()
    start_date = datetime(now.year - 1, 1, 1, tzinfo=timezone.utc)
    end_date = datetime(now.year +10, 1, 1, tzinfo=timezone.utc)
    logger.info(f"[generate_timezone_dbs] Beggining generation from {start_date} to {end_date}...")

    for tz in get_transient_timezones():
        timezone_name = str(tz)
        logger.info(f"[generate_timezone_dbs] (Re)generating lookup databases for timezone '{timezone_name}'...")
        utc_array, localized_array = _get_rsyslog_sparse_arrays(tz, start_date, end_date)
        filename_local = f"{timezone_name.lower().replace('/', '_')}_local.lookup"
        data_local = _generate_rsyslog_lookup_db(localized_array)
        try:
            write_conf(logger, [
                f"{TZFILES_FOLDER}{filename_local}",
                json.dumps(data_local),
                "vlt-os:wheel", "640",
                ])
        except (VultureSystemConfigError, ServiceExit) as e:
            logger.warning(f"[generate_timezone_dbs] Could not write the updated '{filename_local}' file: {e}")

        filename_utc = f"{timezone_name.lower().replace('/', '_')}_utc.lookup"
        data_utc = _generate_rsyslog_lookup_db(utc_array)
        try:
            write_conf(logger, [
                f"{TZFILES_FOLDER}{filename_utc}",
                json.dumps(data_utc),
                "vlt-os:wheel", "640",
                ])
        except (VultureSystemConfigError, ServiceExit) as e:
            logger.warning(f"[generate_timezone_dbs] Could not write the updated '{filename_utc}' file: {e}")

    logger.info("[generate_timezone_dbs] Generations complete.")
