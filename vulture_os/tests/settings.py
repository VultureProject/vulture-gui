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

from vulture_os.settings import *

LOG_LEVEL = "DEBUG"
DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': 'djongo',
        'NAME': 'vulture',
        "CLIENT": {
            'host': 'mongodb',
            'port': 9091,
            'serverSelectionTimeoutMS': 5000,
            'REPLICASET': 'Vulture',
            'READPREFERENCE': "primaryPreferred"
        },
    }
}

LOG_SETTINGS = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(asctime)s %(module)s:%(lineno)d [%(levelname)s] %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
        'api_parser': {
            'format': '%(asctime)s %(module)s:%(lineno)d [%(levelname)s][%(frontend)s][PID:%(process)d] %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': LOG_LEVEL,
        },
        'database': {
            'level': LOG_LEVEL,
            'class': 'toolkit.log.log_utils.DatabaseHandler',
            'type_logs': 'vulture',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'ERROR',
    },
    'loggers': {
        'debug': {
            'handlers': ('console',),
            'level': LOG_LEVEL,
            'propagate': True,
        },
        'auth': {
            'handlers': ('console',),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'api': {
            'handlers': ('console',),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'gui': {
            'handlers': ('console',),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'services': {
            'handlers': ('console',),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'daemon': {
            'handlers': ('console',),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'crontab': {
            'handlers': ('console',),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'api_parser': {
            'handlers': ('console',),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'authentication': {
            'handlers': ('console',),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'system': {
            'handlers': ('console',),
            'level': LOG_LEVEL,
            'propagate': True
        },
    },
}
