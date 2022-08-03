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
    file specified or the varible does not exist, an empty string is returned.

    Note: If used over node API request, use await_result function
    on the instance return in the API response to get the response
    """
    if isinstance(rc_args, str):
        filename, variable = literal_eval(rc_args)
    else:
        filename, variable = rc_args

    try:
        file_path = os.path.join(RC_PATH, filename)

        command = ['/usr/local/bin/sudo', '/usr/sbin/sysrc', '-f', file_path, '-n', variable]
        # If there is not file specified, remove the '-f' option and the empty string(filename)
        if not filename:
            del command[2:4]
        result = subprocess.run(command, capture_output=True)
        return result.stdout.decode("utf8").strip()

    except Exception as e:
        logger.error("Error set_rc_config: {}".format(e))
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
        file_path = os.path.join(RC_PATH, filename)

        command = ['/usr/local/bin/sudo', '/usr/sbin/sysrc', '-f', file_path, '{}={}'.format(variable, value)]
        if not filename:
            del command[2:4]
        proc = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        res, errors = proc.communicate()
        if not errors:
            return True
        else:
            logger.error("Failed to call script {} : {}".format(command, errors))
            return False

    except Exception as e:
        logger.error("Error set_rc_config: {}".format(e))
        return False