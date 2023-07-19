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
import re
from ast import literal_eval

# External modules imports
import subprocess

RC_PATH ="/etc/rc.conf.d/"

def get_rc_config(variable=None, filename=None, flags=[]):
    """Retrieve the value of a variable in rc configuration. If no file
    is specified, /etc/rc.conf is checked.

    :param  variable:       The name of the variable to get from sysrc
                            If none is specified (default), the command will return all non-default values
            filename:       The file to fetch with sysrc in the /etc/rc.conf.d/ directory (don't specify path)
                            by default, sysrc fetches in /etc/rc.conf
            flags:          an optional set of flags and instructions to pass to sysrc
                            by default, '-n' is set to only return value
                            see 'man sysrc' to get details on availabe flags and modifiers

    :return:    a Tuple with
                    - The status of the query (True if successful, False otherwise)
                    - a string representing the direct result of sysrc's stdout

    Note: If used over node API request, use await_result function
    on the instance return in the API response to get the response
    """

    command = ['/usr/local/bin/sudo', '/usr/sbin/sysrc']
    if filename:
        command.extend(['-f', os.path.join(RC_PATH, filename)])

    if flags:
        command.extend(flags)
    else:
        command.append('-n')

    if variable:
        command.append(variable)

    try:
        result = subprocess.run(command, capture_output=True)
        result = result.stdout.decode('utf8')
        return True, result.strip()
    except Exception as e:
        return False, str(e)


def set_rc_config(variable, value, filename=None, operation="="):
    """Set or update value of a variable in rc configuration. If no file
    is specified, it is put in /etc/rc.conf. If the file specified does not
    exist, it is created by sysrc.

    :param  variable:       The name of the variable to set
            value:          The value to give to the variable
            filename:       The file to use with sysrc in the /etc/rc.conf.d/ directory (don't specify path)
                            by default, sysrc writes in /etc/rc.conf
            operation:      Defines the operation to use
                            Can be either "=" (default), "+=" (add words) or "-=" (remove words)


    :return: a tuple with
                - True for success and False on failure
                - an empty string on success, the error string on failure
    """

    if operation not in ['=', '+=', '-=']:
        return False, "operation can only be one of '=', '+=' or '-='!"


    try:
        command = ['/usr/local/bin/sudo', '/usr/sbin/sysrc']
        if filename:
            file_path = os.path.join(RC_PATH, filename)
            command.extend(['-f', file_path])
        command.extend(['{}{}{}'.format(variable, operation, value)])
        proc = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        res, errors = proc.communicate()
        if not errors:
            return True, ""
        else:
            return False, "Failed to call script {} : {}".format(command, errors)

    except Exception as e:
        return False, str(e)


def remove_rc_config(variable_regexp, filename=None):
    """Remove variable(s) in an rc configuration. the parameter is a regex that will be used to filter
            existing variables in the pointed file. Default file used is /etc/rc.conf

    :param  variable_regexp:    The regexp of the variable(s) to remove/unset from the file
            filename:       The file to use with sysrc in the /etc/rc.conf.d/ directory (don't specify path)
                            by default, sysrc uses in /etc/rc.conf

    :return: a Tuple with the results of the operation
                - True and a list of removed parameters in case of success
                - False and an error string in case of error
    """

    pattern = re.compile(variable_regexp)

    if filename:
        fullpath = os.path.join(RC_PATH, filename)
    else:
        fullpath = "/etc/rc.conf"
    list_command = ['/usr/local/bin/sudo', '/usr/sbin/sysrc', '-aN', '-f', fullpath]

    try:
        result = subprocess.run(list_command, capture_output=True)
        result = result.stdout.decode('utf8')
        # Get a clean list of set parameters in the file
        params = result.strip().split()
    except Exception as e:
        return False, f"Failed to list existing variables in file {fullpath}: {str(e)}"

    # Filter raw data to get only variables matching regexp
    filtered_params = list(filter(lambda param: pattern.match(param), params))

    if filtered_params:
        remove_command = ['/usr/local/bin/sudo', '/usr/sbin/sysrc', '-f', fullpath, '-ix']
        remove_command.extend(filtered_params)
        try:
            result = subprocess.check_output(remove_command)
        except Exception as e:
            return False, f"Failed to remove existing variables in file {fullpath}: {str(e)}"

    return True, filtered_params


def call_set_rc_config(logger, rc_args):
    """Made to be called by a Cluster/Node api_request()
        Will call set_rc_config

    :param logger:      API logger
    :param rc_args:     A dictionary containing set_rc_config() parameters
    :return: True for success and False for a fail
    """
    if isinstance(rc_args, str):
        rc_args = literal_eval(rc_args)

    logger.debug(f"call_set_rc_config: calling with parameters {rc_args}")

    status, result = set_rc_config(**rc_args)
    if status:
        return True
    else:
        logger.error(f"call_set_rc_config: Failed to call script: {result}")
        return False


def call_remove_rc_config(logger, rc_args):
    """Made to be called by a Cluster/Node api_request()
        Will call remove_rc_config

    :param logger:      API logger
    :param rc_args:     A tuple containing file name, variable and value
    :return: True for success and False for a fail
    """
    if isinstance(rc_args, str):
        rc_args = literal_eval(rc_args)

    logger.debug(f"call_remove_rc_config: calling with parameters {rc_args}")

    status, result = remove_rc_config(**rc_args)
    if status:
        return True
    else:
        logger.error(f"call_remove_rc_config: Failed to call script: {result}")
        return False
