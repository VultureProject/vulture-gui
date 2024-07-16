#!/home/vlt-os/env/bin/python
"""This file is part of Vulture 4.

Vulture 4 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 4 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 4.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Théo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'System network routing configuration and management'

from subprocess import run as sub_run

from toolkit.network.network import is_valid_hostname, is_valid_ip

def _call_route_cmd(command: str, options: list[str], resolve: bool = False, ip6: bool = False, timeout: int = 5) -> str:
    cmd_parts = ["route"]
    if not resolve:
        cmd_parts += ["-n"]
    if ip6:
        cmd_parts += ["-6"]
    cmd_parts += [command]
    cmd_parts += options
    answer = sub_run(cmd_parts, check=True, capture_output=True, timeout=timeout)
    return answer.stdout.decode()

def _parse_route_output(input: str) -> dict:
    output = dict()
    for line in input.split("\n"):
        split_line = line.strip().split(':', 1)
        if len(split_line) == 2:
            key, value = split_line
            output[key.strip()] = value.strip()
    return output

def get_route_interface(destination: str, ip6=False) -> tuple[bool, str]:
    if len(destination) == 0:
        return False, "No destination given"
    if not is_valid_ip(destination) and not is_valid_hostname(destination):
        return False, "Destination doesn't seem to represent an IP or a hostname"

    try:
        answer = _call_route_cmd("get", [destination], ip6=ip6)
    except Exception as e:
        return False, str(e)

    parsed = _parse_route_output(answer)
    if "interface" not in parsed.keys():
        return False, "Could not get a valid interface for the route"


    return True, parsed['interface']
