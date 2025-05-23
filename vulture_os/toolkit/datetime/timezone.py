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
__author__ = "Theo Bertin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Timezone generation and conversion tools'

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, available_timezones


def get_transient_timezones():
    result = set()
    for tz_name in available_timezones():
        try:
            # Handle legacy GMT timezones specifically,
            # as the offset in the name represents an OPPOSITE (and constant) offset from UTC now!
            if "GMT" in tz_name:
                if "+" in tz_name:
                    offset = int(tz_name.split("+")[-1])
                    result.add(timezone(timedelta(seconds=-offset*3600), name=f"UTC-{offset}"))
                if "-" in tz_name:
                    offset = int(tz_name.split("-")[-1])
                    result.add(timezone(timedelta(seconds=offset*3600), name=f"UTC+{offset}"))
            else:
                result.add(ZoneInfo(tz_name))
        except ValueError:
            continue
    return result


def get_safe_tz_name(tz) -> str:
    return str(tz).replace(
        '/', '_'
        ).replace(
            '+', '_plus_'
        ).replace(
            '-', '_minus_'
        ).lower()


def get_offset_string(offset_seconds: int | timedelta) -> str:
    """Returns a string representation of the offset in seconds, in the form '[+-]XX:YY'

    Args:
        offset_seconds (int | timedelta): the offset in seconds, either positive or negative

    Returns:
        str: the offset in the format '[+-]XX:YY'
    """    """"""
    tz_string = ""
    if isinstance(offset_seconds, timedelta):
        offset_seconds = int(offset_seconds.total_seconds())
    if offset_seconds < 0:
        tz_string += '-'
    else:
        tz_string += '+'
    tz_string += f"{int(abs(offset_seconds)/3600):02d}:{int((abs(offset_seconds)/60)%60):02d}"
    return tz_string


def get_timezone_transitions(local_tz: ZoneInfo, start_date: datetime, end_date: datetime) -> list[dict] | None:
    """Returns the utc, local and corresponding offsets of known timezone transitions for a specific timezone name

    Args:
        local_tz (ZoneInfo): the local timezone to get transitions from
        start_date (datetime): the (UTC) timezone to begin the list from
        end_date (datetime): the (UTC) timezone to end the list with

    Returns:
        result (list[dict] | None): *None* if the provided timezone name wasn't found, else a list of dictionaries containing:
            - utc_timestamp: a UTC-aware datetime object of the UTC time of transition
            - local_timestamp : a UTC-aware datetime object of the local time of transition (offseted by offset_seconds)
            - offset_seconds: an int representing the new offset between UTC and local times
    """
    timestamps = list()
    increment_td = timedelta(days=1)

    # Ensure research is done using UTC datetimes...
    dt = start_date.astimezone(timezone.utc)
    end_dt = end_date.astimezone(timezone.utc)

    # ...but get offsets as local timezones
    prev_offset = dt.astimezone(local_tz).utcoffset()
    timestamps.append({
        "utc_timestamp": dt.replace(microsecond=0),
        "local_timestamp": dt.astimezone(local_tz).replace(microsecond=0, tzinfo=timezone.utc),
        "offset_seconds": int(prev_offset.total_seconds()),
    })
    dt += increment_td

    while dt < end_dt:
        new_offset = dt.astimezone(local_tz).utcoffset()
        if new_offset != prev_offset:
            # Dichotomic search of exact (UTC) time change
            low, high = dt - increment_td, dt
            while (high - low).total_seconds() > 1:
                # Cut in half...
                mid = low + (high - low) / 2
                # ...remove the half that doesn't contain the change
                if mid.astimezone(local_tz).utcoffset() == prev_offset:
                    low = mid
                else:
                    high = mid
            # Search converged to the exact time of change
            timestamps.append({
                    "utc_timestamp": high.replace(microsecond=0),
                    "local_timestamp": high.astimezone(local_tz).replace(microsecond=0, tzinfo=timezone.utc),
                    "offset_seconds": int(new_offset.total_seconds()),
                })
            prev_offset = new_offset
        dt += increment_td

    return timestamps


def get_local_boundaries(current: dict, prev: dict, next: dict) -> set[tuple]:
    """Generate a list of linear local timestamps, corresponding to the offset change,
    along with the new offset for the new range.

    Args:
        current (dict): an object returned by the **get_timezone_transitions()** function, representing a transition
        prev (dict): an object returned by the **get_timezone_transitions()** function, representing the previous transition
        next (dict): an object returned by the **get_timezone_transitions()** function, representing the next transition

    Returns:
        set[tuple]: a unique set of tuples with
            - the unix timestamp of the begining of the computed range for a specific offset
            - the offset in seconds, or **OVERLAP** if the timestamp can correspond to more than 1 offset, or **IMPOSSIBLE** if the timestamp cannot appear for this timezone
    """
    data = list()
    if current['offset_seconds'] > next['offset_seconds']:
        # There will be an overlap on timestamps, as the hour will go BACK
        diff_offset = current['offset_seconds'] - next['offset_seconds']
        # This overlap begins at the next timestamp, and lasts for diff_offset, then the next offset finally applies
        data.append((int(next['local_timestamp'].timestamp()), "OVERLAP"))
        data.append((int((next['local_timestamp'] + timedelta(seconds=diff_offset)).timestamp()), get_offset_string(next['offset_seconds'])))
    elif current['offset_seconds'] < next['offset_seconds']:
        # There will be a hole on timestamps, as the hour will jump FORTH
        diff_offset = next['offset_seconds'] - current['offset_seconds']
        # The gap begins diff_offset BEFORE the new offset time, then the new offset finally applies
        data.append((int((next['local_timestamp'] - timedelta(seconds=diff_offset)).timestamp()), "IMPOSSIBLE"))
        data.append((int(next['local_timestamp'].timestamp()), get_offset_string(next['offset_seconds'])))
    if current['offset_seconds'] > prev['offset_seconds']:
        # There has been a hole on timestamps, as the hour previously jumped FORTH
        diff_offset = current['offset_seconds'] - prev['offset_seconds']
        # The gap began diff_offset BEFORE the current offset time, then finally applied at the current timestamp
        data.append((int((current['local_timestamp'] - timedelta(seconds=diff_offset)).timestamp()), "IMPOSSIBLE"))
        data.append((int(current['local_timestamp'].timestamp()), get_offset_string(current['offset_seconds'])))
    elif current['offset_seconds'] < prev['offset_seconds']:
        # There has been an overlap on timestamps, as the hour did go BACK
        diff_offset = prev['offset_seconds'] - current['offset_seconds']
        # This overlap begins at the current timestamp, and will last during diff_offset, then the current offset will finally apply
        data.append((int(current['local_timestamp'].timestamp()), "OVERLAP"))
        data.append((int((current['local_timestamp'] + timedelta(seconds=diff_offset)).timestamp()), get_offset_string(current['offset_seconds'])))
    return set(data)
