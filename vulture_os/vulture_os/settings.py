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

import os
from pymongo import ReadPreference
from toolkit.network.network import get_hostname
from toolkit.system.secret_key import set_key

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_DIR = os.path.abspath(os.path.dirname(__file__))

# Retrieving Django SECRET_KEY
try:
    from vulture_os.secret_key import SECRET_KEY
# File doesn't exist, we need to create it
except ImportError:
    # Generate a key in the settings' folder
    SECRET_KEY = set_key(SETTINGS_DIR)

LOG_LEVEL = "INFO"

DEBUG = False
DEV_MODE = False
TEMPLATE_DEBUG = DEBUG

ALLOWED_HOSTS = ["*"]

CSRF_COOKIE_SECURE = True

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
    ("1 * * * *", "gui.crontab.feed.security_update"),  # Every hour
    ("0 1 * * *", "gui.crontab.check_internal_tasks.check_internal_tasks")  # Every day at 01:00
]

CRONTAB_COMMAND_PREFIX = "LANG=en_US.UTF-8"

# Extend cronjobs with custom cronjobs
if os.path.exists(os.path.dirname(os.path.abspath(__file__)) + "/custom_cronjobs.py"):
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
            'host': get_hostname(),
            'port': 9091,
            'serverSelectionTimeoutMS': 5000,
            'REPLICASET': 'Vulture',
            'SSL': True,
            'SSL_CERTFILE': '/var/db/pki/node.pem',
            'SSL_CA_CERTS': '/var/db/pki/ca.pem',
            'READPREFERENCE': "primaryPreferred"
        },
    }
}


LOGIN_URL = "/login/"

SESSION_IDLE_TIMEOUT = 180
SESSION_COOKIE_AGE = 3600
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_NAME = "vltsessid"
SESSION_SAVE_EVERY_REQUEST = True

# Password validation
# https://docs.djangoproject.com/en/2.0/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/2.0/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.0/howto/static-files/
MEDIA_PATH = '/gui/static/img/'
STATIC_ROOT = os.path.join(BASE_DIR, "static")
STATIC_URL = '/static/'

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
            'format': '%(asctime)s %(module)s:%(lineno)d [%(levelname)s][%(frontend)s] %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
        'debug': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/vulture/os/debug.log',
            'formatter': 'verbose',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'database': {
            'level': LOG_LEVEL,
            'class': 'toolkit.log.log_utils.DatabaseHandler',
            'type_logs': 'vulture',
        },
        'api': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.WatchedFileHandler',
            'filename': '/var/log/vulture/os/api.log',
            'formatter': 'verbose',
            'mode': 'a'
        },
        'gui': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.WatchedFileHandler',
            'filename': '/var/log/vulture/os/gui.log',
            'formatter': 'verbose',
            'mode': 'a'
        },
        'services': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.WatchedFileHandler',
            'filename': '/var/log/vulture/os/services.log',
            'formatter': 'verbose',
            'mode': 'a'
        },
        'daemon': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': '/var/log/vulture/os/cluster.log',
            'mode': 'a'
        },
        'crontab': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': '/var/log/vulture/os/crontab.log',
            'mode': 'a'
        },
        'api_parser': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'api_parser',
            'filename': '/var/log/vulture/os/api_parser.log',
            'mode': 'a'
        },
        'authentication': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': '/var/log/vulture/os/authentication.log',
            'mode': 'a'
        },
        'system': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': '/var/log/vulture/os/system.log',
            'mode': 'a'
        }
    },
    'loggers': {
        'debug': {
            'handlers': ('debug', 'database', 'console'),
            'level': LOG_LEVEL,
            'propagate': True,
        },
        'auth': {
            'handlers': ('debug', 'database', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'api': {
            'handlers': ('api', 'database', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'gui': {
            'handlers': ('gui', 'database', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'services': {
            'handlers': ('services', 'database', 'console'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'daemon': {
            'handlers': ('daemon', 'database'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'crontab': {
            'handlers': ('crontab', 'database'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'api_parser': {
            'handlers': ('api_parser', 'database'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'authentication': {
            'handlers': ('authentication', 'database'),
            'level': LOG_LEVEL,
            'propagate': True
        },
        'system': {
            'handlers': ['system'],
            'level': LOG_LEVEL,
            'propagate': True
        },
    },
}

TITLE = "VULTURE OS"
VERSION = "0.1"
WEBSITE = 'https://www.vultureproject.org'
COMPANY = 'Vulture Project'
LOGO_SM = 'img/vulture-logo-small.png'
LOGO = 'img/vulture-logo.png'
LOGO_LG = 'img/vulture_logo.png'
WALLPAPER = 'img/VultureOS_wallpaper.png'
