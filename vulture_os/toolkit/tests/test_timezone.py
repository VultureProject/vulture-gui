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
__doc__ = 'Tests for datetime/timezone.py'

from datetime import timedelta, datetime, tzinfo, timezone as dt_timezone
from django.test import SimpleTestCase
from django.utils import timezone
from toolkit.datetime.timezone import (
    get_offset_string,
    get_timezone_transitions,
    get_local_boundaries,
    get_transient_timezones,
    get_safe_tz_name,
)
from zoneinfo import ZoneInfo

class TimezoneTestCase(SimpleTestCase):
    TEST_CASE_NAME=f"{__name__}"

###########################
# get_transient_timezones #
###########################
    def test_get_transient_timezones(self):
        result = get_transient_timezones()
        self.assertIsInstance(result, set)
        self.assertNotEqual(len(result), 0)
        for tz in result:
            self.assertIsInstance(tz, tzinfo)

    def test_get_transient_timezones_no_gmt(self):
        #Deprecated/misleading timezones
        result = get_transient_timezones()
        for tz in result:
            self.assertFalse("GMT" in str(tz))

    def test_get_transient_timezones_utcs(self):
        #Deprecated/misleading timezones
        result = get_transient_timezones()
        for offset in range(-12,15):
            self.assertIn(dt_timezone(timedelta(seconds=offset*3600), f"UTC{offset}"), result)

####################
# get_safe_tz_name #
####################
    def test_get_safe_tz_name(self):
        result = get_transient_timezones()
        for tz in result:
            self.assertRegex(get_safe_tz_name(tz), r"^[a-z0-9_]+$")

#####################
# get_offset_string #
#####################
    def test_offset_string_positive_int(self):
        self.assertEqual(get_offset_string(4200), "+01:10")

    def test_offset_string_positive_timedelta(self):
        self.assertEqual(get_offset_string(timedelta(hours=2, minutes=3)), "+02:03")

    def test_offset_string_negative_int(self):
        self.assertEqual(get_offset_string(-14400), "-04:00")

    def test_offset_string_negative_timedelta(self):
        self.assertEqual(get_offset_string(timedelta(hours=-3, minutes=-25)), "-03:25")

    def test_offset_string_zero_int(self):
        self.assertEqual(get_offset_string(0), "+00:00")

############################
# get_timezone_transitions #
############################
    def test_get_timezone_transitions_europe_paris(self):
        tz = ZoneInfo("Europe/Paris")
        start_date = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)
        end_date = datetime(2100, 1, 1, tzinfo=dt_timezone.utc)
        timestamps = get_timezone_transitions(tz, start_date, end_date)
        self.assertIsNotNone(timestamps)
        self.assertIsNot(len(timestamps), 0)

    def test_get_timezone_transitions_never_empty(self):
        for tz in get_transient_timezones():
            start_date = datetime(2024, 1, 1, tzinfo=dt_timezone.utc)
            end_date = datetime(2025, 1, 1, tzinfo=dt_timezone.utc)
            timestamps = get_timezone_transitions(tz, start_date, end_date)
            self.assertIsNotNone(timestamps, f"{tz} is None")
            self.assertIsNot(len(timestamps), 0, f"{tz} returns no timezone transition")

    def test_get_timezone_transitions_contents(self):
        tz = ZoneInfo("Europe/Paris")
        start_date = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)
        end_date = datetime(2100, 1, 1, tzinfo=dt_timezone.utc)
        timestamps = get_timezone_transitions(tz, start_date, end_date)
        for timestamp in timestamps:
            self.assertListEqual(
                list(timestamp.keys()),
                ['utc_timestamp', 'local_timestamp', 'offset_seconds'])
            self.assertListEqual(
                [type(value) for value in timestamp.values()],
                [datetime, datetime, int]
            )

    def test_get_timezone_transitions_ensure_tz_aware(self):
        tz = ZoneInfo("Europe/Paris")
        start_date = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)
        end_date = datetime(2100, 1, 1, tzinfo=dt_timezone.utc)
        timestamps = get_timezone_transitions(tz, start_date, end_date)
        for timestamp in timestamps:
            self.assertTrue(timezone.is_aware(timestamp['utc_timestamp']))
            self.assertTrue(timezone.is_aware(timestamp['local_timestamp']))

    def test_get_timezone_transitions_ensure_tz_utc(self):
        tz = ZoneInfo("Europe/Paris")
        start_date = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)
        end_date = datetime(2100, 1, 1, tzinfo=dt_timezone.utc)
        timestamps = get_timezone_transitions(tz, start_date, end_date)
        for timestamp in timestamps:
            self.assertEqual(timestamp['utc_timestamp'].tzinfo, dt_timezone.utc)
            self.assertEqual(timestamp['local_timestamp'].tzinfo, dt_timezone.utc)

    def test_get_timezone_transitions_local_value(self):
        tz = ZoneInfo("Europe/Paris")
        start_date = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)
        end_date = datetime(2100, 1, 1, tzinfo=dt_timezone.utc)
        timestamps = get_timezone_transitions(tz, start_date, end_date)
        for timestamp in timestamps:
            self.assertEqual(
                timestamp['local_timestamp'],
                timestamp['utc_timestamp'] + timedelta(seconds=timestamp['offset_seconds'])
            )

########################
# get_local_boundaries #
########################
    def test_get_local_boundaries_no_change(self):
        timestamp_utc = datetime(year=2025, month=3, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc = datetime(year=2025, month=3, day=5, hour=12, minute=45, second=57, tzinfo=dt_timezone.utc)
        transition = {
            "utc_timestamp": timestamp_utc,
            "local_timestamp": timestamp_loc,
            "offset_seconds": 3600,
        }

        self.assertEqual(
            get_local_boundaries(transition, transition, transition),
            set()
        )

    def test_get_local_boundaries_decreased_offset_after(self):
        """This condition shows a local timestamp jumping back 1 hour,
        so there will be a 1-hour OVERLAP condition for local timestamps.
        This OVERLAP will begin at the latest local timestamp
        and will last for the difference in offset between the old and new local timestamps.
        Then, the new offset will apply
        """
        timestamp_utc1 = datetime(year=2025, month=3, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc1 = datetime(year=2025, month=3, day=5, hour=13, minute=45, second=57, tzinfo=dt_timezone.utc)
        offset1 = 7200
        timestamp_utc2 = datetime(year=2025, month=4, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc2 = datetime(year=2025, month=4, day=5, hour=12, minute=45, second=57, tzinfo=dt_timezone.utc)
        offset2 = 3600
        diff_offset = abs(offset2 - offset1)
        transition1 = {
            "utc_timestamp": timestamp_utc1,
            "local_timestamp": timestamp_loc1,
            "offset_seconds": offset1,
        }
        transition2 = transition1
        transition3 = {
            "utc_timestamp": timestamp_utc2,
            "local_timestamp": timestamp_loc2,
            "offset_seconds": offset2,
        }

        self.assertSetEqual(
            get_local_boundaries(transition2, transition1, transition3),
            set([
                (timestamp_loc2.timestamp(), "OVERLAP"),
                (timestamp_loc2.timestamp() + diff_offset, "+01:00"),
            ])
        )

    def test_get_local_boundaries_increased_offset_after(self):
        """This condition shows a local timestamp jumping forth 1 hour,
        so there will be a 1-hour IMPOSSIBLE condition for local timestamps.
        This IMPOSSIBLE range will begin at the new local timestamp - the difference in offset,
        and will end at the latest local timestamp.
        Then, the new offset will apply
        """
        timestamp_utc1 = datetime(year=2025, month=3, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc1 = datetime(year=2025, month=3, day=5, hour=12, minute=45, second=57, tzinfo=dt_timezone.utc)
        offset1 = 3600
        timestamp_utc2 = datetime(year=2025, month=4, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc2 = datetime(year=2025, month=4, day=5, hour=13, minute=45, second=57, tzinfo=dt_timezone.utc)
        offset2 = 7200
        diff_offset = abs(offset2 - offset1)
        transition1 = {
            "utc_timestamp": timestamp_utc1,
            "local_timestamp": timestamp_loc1,
            "offset_seconds": offset1,
        }
        transition2 = transition1
        transition3 = {
            "utc_timestamp": timestamp_utc2,
            "local_timestamp": timestamp_loc2,
            "offset_seconds": offset2,
        }

        self.assertSetEqual(
            get_local_boundaries(transition2, transition1, transition3),
            set([
                (timestamp_loc2.timestamp() - diff_offset, "IMPOSSIBLE"),
                (timestamp_loc2.timestamp(), "+02:00"),
            ])
        )

    def test_get_local_boundaries_decreased_offset_before(self):
        """This condition shows a local timestamp jumping forth 1 hour,
        so there will be a 1-hour IMPOSSIBLE condition for local timestamps.
        This IMPOSSIBLE range will begin at the current timestamp - the difference in offset,
        and will end at the current timestamp.
        Then, the new offset will apply
        """
        timestamp_utc1 = datetime(year=2025, month=3, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc1 = datetime(year=2025, month=3, day=5, hour=12, minute=45, second=57, tzinfo=dt_timezone.utc)
        offset1 = 3600
        timestamp_utc2 = datetime(year=2025, month=4, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc2 = datetime(year=2025, month=4, day=5, hour=13, minute=45, second=57, tzinfo=dt_timezone.utc)
        offset2 = 7200
        diff_offset = abs(offset2 - offset1)
        transition1 = {
            "utc_timestamp": timestamp_utc1,
            "local_timestamp": timestamp_loc1,
            "offset_seconds": offset1,
        }
        transition2 = {
            "utc_timestamp": timestamp_utc2,
            "local_timestamp": timestamp_loc2,
            "offset_seconds": offset2,
        }
        transition3 = transition2

        self.assertSetEqual(
            get_local_boundaries(transition2, transition1, transition3),
            set([
                (timestamp_loc2.timestamp() - diff_offset, "IMPOSSIBLE"),
                (timestamp_loc2.timestamp(), "+02:00"),
            ])
        )

    def test_get_local_boundaries_increased_offset_before(self):
        """This condition shows a local timestamp jumping back 1 hour,
        so there will be a 1-hour OVERLAP condition for local timestamps.
        This OVERLAP will begin at the latest local timestamp
        and will last for the difference in offset between the old and new local timestamps.
        Then, the new offset will apply
        """
        timestamp_utc1 = datetime(year=2025, month=3, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc1 = datetime(year=2025, month=3, day=5, hour=13, minute=45, second=57, tzinfo=dt_timezone.utc)
        offset1 = 7200
        timestamp_utc2 = datetime(year=2025, month=4, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc2 = datetime(year=2025, month=4, day=5, hour=12, minute=45, second=57, tzinfo=dt_timezone.utc)
        offset2 = 3600
        diff_offset = abs(offset2 - offset1)
        transition1 = {
            "utc_timestamp": timestamp_utc1,
            "local_timestamp": timestamp_loc1,
            "offset_seconds": offset1,
        }
        transition2 = {
            "utc_timestamp": timestamp_utc2,
            "local_timestamp": timestamp_loc2,
            "offset_seconds": offset2,
        }
        transition3 = transition2

        self.assertSetEqual(
            get_local_boundaries(transition2, transition1, transition3),
            set([
                (timestamp_loc2.timestamp(), "OVERLAP"),
                (timestamp_loc2.timestamp() + diff_offset, "+01:00"),
            ])
        )

    def test_get_local_boundaries_decreased_offset_after_neg(self):
        """This condition shows a local timestamp jumping back 1 hour,
        so there will be a 1-hour OVERLAP condition for local timestamps.
        This OVERLAP will begin at the latest local timestamp
        and will last for the difference in offset between the old and new local timestamps.
        Then, the new offset will apply
        """
        timestamp_utc1 = datetime(year=2025, month=3, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc1 = datetime(year=2025, month=3, day=5, hour=10, minute=15, second=57, tzinfo=dt_timezone.utc)
        offset1 = -5400
        timestamp_utc2 = datetime(year=2025, month=4, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc2 = datetime(year=2025, month=4, day=5, hour=9, minute=45, second=57, tzinfo=dt_timezone.utc)
        offset2 = -7200
        diff_offset = abs(offset2 - offset1)
        transition1 = {
            "utc_timestamp": timestamp_utc1,
            "local_timestamp": timestamp_loc1,
            "offset_seconds": offset1,
        }
        transition2 = transition1
        transition3 = {
            "utc_timestamp": timestamp_utc2,
            "local_timestamp": timestamp_loc2,
            "offset_seconds": offset2,
        }

        self.assertSetEqual(
            get_local_boundaries(transition2, transition1, transition3),
            set([
                (timestamp_loc2.timestamp(), "OVERLAP"),
                (timestamp_loc2.timestamp() + diff_offset, "-02:00"),
            ])
        )

    def test_get_local_boundaries_increased_offset_after_neg(self):
        """This condition shows a local timestamp jumping forth 1 hour,
        so there will be a 1-hour IMPOSSIBLE condition for local timestamps.
        This IMPOSSIBLE range will begin at the new local timestamp - the difference in offset,
        and will end at the latest local timestamp.
        Then, the new offset will apply
        """
        timestamp_utc1 = datetime(year=2025, month=3, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc1 = datetime(year=2025, month=3, day=5, hour=10, minute=44, second=57, tzinfo=dt_timezone.utc)
        offset1 = -3660
        timestamp_utc2 = datetime(year=2025, month=4, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc2 = datetime(year=2025, month=4, day=5, hour=11, minute=30, second=57, tzinfo=dt_timezone.utc)
        offset2 = -900
        diff_offset = abs(offset2 - offset1)
        transition1 = {
            "utc_timestamp": timestamp_utc1,
            "local_timestamp": timestamp_loc1,
            "offset_seconds": offset1,
        }
        transition2 = transition1
        transition3 = {
            "utc_timestamp": timestamp_utc2,
            "local_timestamp": timestamp_loc2,
            "offset_seconds": offset2,
        }

        self.assertSetEqual(
            get_local_boundaries(transition2, transition1, transition3),
            set([
                (timestamp_loc2.timestamp() - diff_offset, "IMPOSSIBLE"),
                (timestamp_loc2.timestamp(), "-00:15"),
            ])
        )

    def test_get_local_boundaries_decreased_offset_before_neg(self):
        """This condition shows a local timestamp jumping forth 1 hour,
        so there will be a 1-hour IMPOSSIBLE condition for local timestamps.
        This IMPOSSIBLE range will begin at the current timestamp - the difference in offset,
        and will end at the current timestamp.
        Then, the new offset will apply
        """
        timestamp_utc1 = datetime(year=2025, month=3, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc1 = datetime(year=2025, month=3, day=5, hour=7, minute=45, second=57, tzinfo=dt_timezone.utc)
        offset1 = -14400
        timestamp_utc2 = datetime(year=2025, month=4, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc2 = datetime(year=2025, month=4, day=5, hour=9, minute=15, second=57, tzinfo=dt_timezone.utc)
        offset2 = -9000
        diff_offset = abs(offset2 - offset1)
        transition1 = {
            "utc_timestamp": timestamp_utc1,
            "local_timestamp": timestamp_loc1,
            "offset_seconds": offset1,
        }
        transition2 = {
            "utc_timestamp": timestamp_utc2,
            "local_timestamp": timestamp_loc2,
            "offset_seconds": offset2,
        }
        transition3 = transition2

        self.assertSetEqual(
            get_local_boundaries(transition2, transition1, transition3),
            set([
                (timestamp_loc2.timestamp() - diff_offset, "IMPOSSIBLE"),
                (timestamp_loc2.timestamp(), "-02:30"),
            ])
        )

    def test_get_local_boundaries_increased_offset_before_neg(self):
        """This condition shows a local timestamp jumping back 1 hour,
        so there will be a 1-hour OVERLAP condition for local timestamps.
        This OVERLAP will begin at the latest local timestamp
        and will last for the difference in offset between the old and new local timestamps.
        Then, the new offset will apply
        """
        timestamp_utc1 = datetime(year=2025, month=3, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc1 = datetime(year=2025, month=3, day=5, hour=9, minute=15, second=57, tzinfo=dt_timezone.utc)
        offset1 = -9000
        timestamp_utc2 = datetime(year=2025, month=4, day=5, hour=11, minute=45, second=57, tzinfo=dt_timezone.utc)
        timestamp_loc2 = datetime(year=2025, month=4, day=5, hour=8, minute=15, second=57, tzinfo=dt_timezone.utc)
        offset2 = -12600
        diff_offset = abs(offset2 - offset1)
        transition1 = {
            "utc_timestamp": timestamp_utc1,
            "local_timestamp": timestamp_loc1,
            "offset_seconds": offset1,
        }
        transition2 = {
            "utc_timestamp": timestamp_utc2,
            "local_timestamp": timestamp_loc2,
            "offset_seconds": offset2,
        }
        transition3 = transition2

        self.assertSetEqual(
            get_local_boundaries(transition2, transition1, transition3),
            set([
                (timestamp_loc2.timestamp(), "OVERLAP"),
                (timestamp_loc2.timestamp() + diff_offset, "-03:30"),
            ])
        )
