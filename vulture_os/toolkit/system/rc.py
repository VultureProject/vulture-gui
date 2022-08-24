#!/home/vlt-os/env/bin/python
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "William DARKWA"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'System rc configuration manipulation'

import os
from ast import literal_eval

# External modules imports
import subprocess

RC_PATH ="/etc/rc.conf.d/"

def get_rc_config(logger, rc_args):
    """Retrieve the value of a variable in rc configuration. If no file
    is specified, /etc/rc.conf is checked.

    :param logger:      API logger (to be called by an API request)
    :param rc_args:     A tuple containing filename, variable

    :return: The value of the variable in rc configuration. If the
    file specified or the variable does not exist, an empty string is returned.

    Note: If used over node API request, use await_result function
    on the instance return in the API response to get the response
    """
    if isinstance(rc_args, str):
        filename, variable = literal_eval(rc_args)
    else:
        filename, variable = rc_args

    try:
        command = ['/usr/local/bin/sudo', '/usr/sbin/sysrc']
        if filename:
          file_path = os.path.join(RC_PATH, filename)
          command.extend(['-f', file_path])
        command.extend(['-n', variable])
        result = subprocess.run(command, capture_output=True)
        return result.stdout.decode("utf8").strip()

    except Exception as e:
        logger.error("set_rc_config: {}".format(e))
        return False

def set_rc_config(logger, rc_args):
    """Set or update value of a variable in rc configuration. If no file
    is specified, it is put in /etc/rc.conf. If the file specified does not
    exist, it is created by sysrc.
    :param logger:      API logger (to be called by an API request)
    :param rc_args:     A tuple containing file name, variable and value
    :return: True for success and False for a fail
    """
    if isinstance(rc_args, str):
        filename, variable, value = literal_eval(rc_args)
    else:
        filename, variable, value = rc_args

    try:
        command = ['/usr/local/bin/sudo', '/usr/sbin/sysrc']
        if filename:
          file_path = os.path.join(RC_PATH, filename)
          command.extend(['-f', file_path])
        command.extend(['{}={}'.format(variable, value)])
        proc = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        res, errors = proc.communicate()
        if not errors:
            return True
        else:
            logger.error("set_rc_config: Failed to call script {} : {}".format(command, errors))
            return False

    except Exception as e:
        logger.error("set_rc_config: {}".format(e))
        return False
