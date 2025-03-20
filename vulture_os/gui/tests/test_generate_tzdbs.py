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

__author__ = "Théo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Tests for timezone databases generation crontab'

from datetime import datetime, timezone
from django.test import SimpleTestCase
from gui.crontab.generate_tzdbs import _get_rsyslog_sparse_arrays
from zoneinfo import ZoneInfo

class GenerateTZDBsCrontabTestCase(SimpleTestCase):
    TEST_CASE_NAME=f"{__name__}"

    def test_get_rsyslog_sparse_arrays_simplified_europe_paris(self):
        tz_europe_paris = ZoneInfo("Europe/Paris")
        # List of the real Europe/Paris timezone (UTC) transitions between 2024 and 2026
        # 2024-03-31T01:00:00Z (1711846800)    ->    +02:00
        # 2024-10-27T01:00:00Z (1729990800)    ->    +01:00
        # 2025-03-30T01:00:00Z (1743296400)    ->    +02:00
        # 2025-10-26T01:00:00Z (1761440400)    ->    +01:00
        #
        # Which give the following ranges in local timestamps
        # from 2024-03-31T03:00:00 (1711854000)   is    +02:00
        # from 2024-10-27T02:00:00 (1729994400)   is    OVERLAP
        # from 2024-10-27T03:00:00 (1729998000)   is    +01:00
        # from 2025-03-30T02:00:00 (1743300000)   is    IMPOSSIBLE
        # from 2025-03-30T03:00:00 (1743303600)   is    +02:00
        # from 2025-10-26T02:00:00 (1761444000)   is    OVERLAP
        # from 2025-10-26T03:00:00 (1761447600)   is    +01:00
        start_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end_date = datetime(2026, 1, 1, tzinfo=timezone.utc)
        # Getting the list of transitions between 01/01/2024 and 31/12/2025
        utc_array, localized_array = _get_rsyslog_sparse_arrays(tz_europe_paris, start_date, end_date)
        self.assertSetEqual(
            utc_array,
            {
                (1711846800, "+02:00"),
                (1729990800, "+01:00"),
                (1743296400, "+02:00"),
                (1761440400, "+01:00"),
            },
        )
        self.assertSetEqual(
            localized_array,
            {
                (1711854000, "+02:00"),
                (1729994400, "OVERLAP"),
                (1729998000, "+01:00"),
                (1743300000, "IMPOSSIBLE"),
                (1743303600, "+02:00"),
                (1761444000, "OVERLAP"),
                (1761447600, "+01:00"),
            },
        )
