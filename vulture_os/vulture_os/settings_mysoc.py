#!/usr/bin/env python
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

import environ
from os import path as os_path


BASE_DIR = os_path.dirname(os_path.dirname(os_path.abspath(__file__)))
SETTINGS_DIR = os_path.abspath(os_path.dirname(__file__))

env = environ.Env()
env.prefix = 'VULTURE_'
environ.Env.read_env(os_path.join(SETTINGS_DIR, '.env'))
LOG_LEVEL = env.str("LOG_LEVEL", "INFO")

SYSTEM_ROOT_PATH = env.str("SYSTEM_ROOT_PATH", "/")
LOGS_PATH = os_path.join(SYSTEM_ROOT_PATH, env.str("LOGS_PATH", "var/log"))
API_PARSER_LOGS_PATH = os_path.join(LOGS_PATH, env.str("API_PARSER_LOGS_PATH", "vulture/os/api_parser.log"))

AVAILABLE_APPS = [
    'api_collector.apps.ApiCollectorConfig',
]

CRONJOBS = [
    ("0 * * * 0", "api_collector.models.base.test_crontab"),
]

TEMPLATES = [
    {
        'DIRS': [
            BASE_DIR + "/api_collector/templates/",
        ],
    }
]

LOG_SETTINGS = {
    'formatters': {
        'api_parser': {
            'format': '%(asctime)s %(module)s:%(lineno)d [%(levelname)s][%(frontend)s][PID:%(process)d] %(message)s'
        }
    },
    'handlers': {
        'api_parser': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'api_parser',
            'filename': API_PARSER_LOGS_PATH,
            'mode': 'a'
        },
    },
    'loggers': {
        'api_parser': {
            'handlers': ('api_parser', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
    }
}