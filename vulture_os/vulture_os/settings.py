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

import environ
import importlib.util
import sys
from glob import glob
from os import path as os_path
from toolkit.network.network import get_hostname
from toolkit.system.secret_key import set_key

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os_path.dirname(os_path.dirname(os_path.abspath(__file__)))
SETTINGS_DIR = os_path.abspath(os_path.dirname(__file__))

env = environ.Env()
env.prefix = 'VULTURE_'
environ.Env.read_env(os_path.join(SETTINGS_DIR, '.env'))

# Project folders
SYSTEM_ROOT_PATH = env.str("SYSTEM_ROOT_PATH", "/")
DBS_PATH = os_path.join(SYSTEM_ROOT_PATH, env.str("DBS_PATH", "var/db"))
TMP_PATH = os_path.join(SYSTEM_ROOT_PATH, env.str("TMP_PATH", "var/tmp"))
LOGS_PATH = os_path.join(SYSTEM_ROOT_PATH, env.str("LOGS_PATH", "var/log"))
SOCKETS_PATH = os_path.join(SYSTEM_ROOT_PATH, env.str("SOCKETS_PATH", "var/sockets"))
HOMES_PATH = os_path.join(SYSTEM_ROOT_PATH, env.str("HOMES_PATH", "home"))
LOCALETC_PATH = os_path.join(SYSTEM_ROOT_PATH, env.str("LOCALETC_PATH", "usr/local/etc"))

# Logging
DEBUG_LOGS_PATH = os_path.join(LOGS_PATH, env.str("DEBUG_LOGS_PATH", "vulture/os/debug.log"))
API_LOGS_PATH = os_path.join(LOGS_PATH, env.str("API_LOGS_PATH", "vulture/os/api.log"))
GUI_LOGS_PATH = os_path.join(LOGS_PATH, env.str("GUI_LOGS_PATH", "vulture/os/gui.log"))
SERVICES_LOGS_PATH = os_path.join(LOGS_PATH, env.str("SERVICES_LOGS_PATH", "vulture/os/services.log"))
DAEMON_LOGS_PATH = os_path.join(LOGS_PATH, env.str("DAEMON_LOGS_PATH", "vulture/os/cluster.log"))
CRONTAB_LOGS_PATH = os_path.join(LOGS_PATH, env.str("CRONTAB_LOGS_PATH", "vulture/os/crontab.log"))
API_PARSER_LOGS_PATH = os_path.join(LOGS_PATH, env.str("API_PARSER_LOGS_PATH", "vulture/os/api_parser.log"))
AUTHENTICATION_LOGS_PATH = os_path.join(LOGS_PATH, env.str("AUTHENTICATION_LOGS_PATH", "vulture/os/authentication.log"))
SYSTEM_LOGS_PATH = os_path.join(LOGS_PATH, env.str("SYSTEM_LOGS_PATH", "vulture/os/system.log"))

HOSTNAME = env.str("HOSTNAME", get_hostname())

SERVICE_RESTART_DELAY = env.int("SERVICE_RESTART_DELAY", 10)

# Retrieving Django SECRET_KEY
try:
    from vulture_os.secret_key import SECRET_KEY
# File doesn't exist, we need to create it
except ImportError:
    # Generate a key in the settings' folder
    SECRET_KEY = set_key(SETTINGS_DIR)

# Applying custom patches to code
try:
    from toolkit.patches import *
except ImportError:
    pass

LOG_LEVEL = env.str("LOG_LEVEL", "INFO")

DEBUG = env.bool("DEBUG", False)
DEV_MODE = env.bool("DEV_MODE", False)

ALLOWED_HOSTS = ["*"]

CSRF_COOKIE_SECURE = True
CSRF_TRUSTED_ORIGINS = ["https://vulture-nginx:8000"]

# Application definition
INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_crontab'
]

AVAILABLE_APPS = [
    'gui',
    'services',
    'system',
    'authentication',
    'applications',
    'darwin',
    'toolkit',
    'workflow'
]


INSTALLED_APPS.extend(AVAILABLE_APPS)

CRONJOBS = [
    ("* * * * *", "gui.crontab.api_clients_parser.api_clients_parser"),  # Every minute
    ("8 22 * * *", "gui.crontab.pki.update_crl"),  # Every day at 22:08
    ("7 22 * * *", "gui.crontab.pki.update_acme"),  # Every day at 22:07
    ("0 23 * * *", "gui.crontab.feed.security_update"),  # Every day at 23:00
    ("25 19 * * wed,sat", "gui.crontab.feed.update_reputation_ctx"),  # Every wednesday and saturday at 06:00
    ("0 1 * * *", "gui.crontab.check_internal_tasks.check_internal_tasks"),  # Every day at 01:00
    ("15 10 1 * *", "gui.crontab.generate_tzdbs.generate_timezone_dbs"),  # Every first day of the month at 10:15
]

CRONTAB_COMMAND_PREFIX = "LANG=en_US.UTF-8"

# Extend cronjobs with custom cronjobs
if os_path.exists(os_path.dirname(os_path.abspath(__file__)) + "/custom_cronjobs.py"):
    try:
        from vulture_os.custom_cronjobs import CUSTOM_CRONJOBS
        CRONJOBS.extend(CUSTOM_CRONJOBS)
    except Exception:
        pass


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'gui.middlewares.api_middleware.JSONParsingMiddleware',
    'gui.middlewares.api_middleware.PutParsingMiddleware',
    'gui.middlewares.os.OsMiddleware'
]

ROOT_URLCONF = 'vulture_os.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR + "/templates/",
            BASE_DIR + "/gui/templates/gui/",
            BASE_DIR + "/services/templates/services/",
            BASE_DIR + "/system/templates/system/",
            BASE_DIR + "/darwin/access_control/config"
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'gui.context_processors.admin_media',
            ],
        },
    },
]

WSGI_APPLICATION = 'vulture_os.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'djongo',
        'NAME': 'vulture',
        "CLIENT": {
            'host': env.str('MONGODB_HOST', HOSTNAME),
            'port': env.int('MONGODB_PORT', 9091),
            'serverSelectionTimeoutMS': 5000,
            'REPLICASET': 'Vulture',
            'SSL': env.bool('MONGODB_SSL', True),
            'tlsCertificateKeyFile': None if not env.bool('MONGODB_SSL', True) else os_path.join(DBS_PATH, env.str('MONGODB_CERT_FILE', 'pki/node.pem')),
            'tlsCAFile': None if not env.bool('MONGODB_SSL', True) else os_path.join(DBS_PATH, env.str('MONGODB_CA_FILE', 'pki/ca.pem')),
            'tlsAllowInvalidHostnames': True,
            'READPREFERENCE': "primaryPreferred"
        },
    }
}

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

REDISIP = env.str('REDIS_HOST', '127.0.0.5')
REDISPORT = env.int('REDIS_PORT', 6379)

LOGIN_URL = "/login/"

SESSION_IDLE_TIMEOUT = 180
SESSION_COOKIE_AGE = 3600
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_NAME = "vltsessid"
SESSION_SAVE_EVERY_REQUEST = True

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/
MEDIA_PATH = 'gui/static/img/'
STATIC_ROOT = os_path.join(BASE_DIR, "static")
STATIC_URL = 'static/'

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
    'filters': {
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
    'handlers': {
        # By default, only output ERROR+ logs to stdout/stderr
        'console-errors': {
            'class': 'logging.StreamHandler',
            'level': 'ERROR',
            'filters': ['require_debug_false']
        },
        # When DEBUG is True, log level to stdout/stderr is chosen through LOG_LEVEL
        'console': {
            'class': 'logging.StreamHandler',
            'level': LOG_LEVEL,
            'filters': ['require_debug_true']
        },
        'debug': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': DEBUG_LOGS_PATH,
            'formatter': 'verbose',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'api': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.WatchedFileHandler',
            'filename': API_LOGS_PATH,
            'formatter': 'verbose',
            'mode': 'a'
        },
        'gui': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.WatchedFileHandler',
            'filename': GUI_LOGS_PATH,
            'formatter': 'verbose',
            'mode': 'a'
        },
        'services': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.WatchedFileHandler',
            'filename': SERVICES_LOGS_PATH,
            'formatter': 'verbose',
            'mode': 'a'
        },
        'daemon': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': DAEMON_LOGS_PATH,
            'mode': 'a'
        },
        'crontab': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': CRONTAB_LOGS_PATH,
            'mode': 'a'
        },
        'api_parser': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'api_parser',
            'filename': API_PARSER_LOGS_PATH,
            'mode': 'a'
        },
        'authentication': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': AUTHENTICATION_LOGS_PATH,
            'mode': 'a'
        },
        'system': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': SYSTEM_LOGS_PATH,
            'mode': 'a'
        }
    },
    'root': {
        'handlers': ['console-errors'],
        'level': 'ERROR',
    },
    'loggers': {
        'debug': {
            'handlers': ('debug', 'console'),
            'level': LOG_LEVEL,
            'propagate': True,
        },
        'auth': {
            'handlers': ('debug', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'api': {
            'handlers': ('api', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'gui': {
            'handlers': ('gui', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'services': {
            'handlers': ('services', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'daemon': {
            'handlers': ('daemon', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'crontab': {
            'handlers': ('crontab', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'api_parser': {
            'handlers': ('api_parser', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'authentication': {
            'handlers': ('authentication', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'system': {
            'handlers': ('system', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
    },
}

# Handle optional modules
for file in glob(f"{SETTINGS_DIR}/settings_*.py"):
    module_name = os_path.basename(file).split('.')[0]
    # Load python code from file
    spec = importlib.util.spec_from_file_location(module_name, file)
    if spec and spec.loader:
        # Load python module from loaded spec in runtime
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        # Check selected settings presence to merge into global Django settings

        if hasattr(module, "AVAILABLE_APPS"):
            INSTALLED_APPS.extend(module.AVAILABLE_APPS)

        if hasattr(module, "CRONJOBS"):
            CRONJOBS.extend(module.CRONJOBS)

        if hasattr(module, "TEMPLATES"):
            for template in module.TEMPLATES:
                if backend := template.get('BACKEND'):
                    for main_template in TEMPLATES:
                        if backend == main_template.get('BACKEND'):
                            for k,v in template.items():
                                if isinstance(v, dict):
                                    try:
                                        main_template[k].update(v)
                                    except KeyError:
                                        main_template[k] = v
                                if isinstance(v, list):
                                    main_template[k].extend(v)

        if hasattr(module, "LOG_SETTINGS"):
            for k,v in module.LOG_SETTINGS.items():
                try:
                    LOG_SETTINGS[k].update(v)
                except KeyError:
                    LOG_SETTINGS[k] = v

TITLE = "VULTURE OS"
VERSION = "0.1"
WEBSITE = 'https://www.vultureproject.org'
COMPANY = 'Vulture Project'
LOGO_SM = 'img/vulture-logo-small.png'
LOGO = 'img/vulture-logo.png'
LOGO_LG = 'img/vulture_logo.png'
WALLPAPER = 'img/VultureOS_wallpaper.png'
