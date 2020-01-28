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

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Retrieving Django SECRET_KEY
try:
    from vulture_os.secret_key import SECRET_KEY
# File doesn't exist, we need to create it
except ImportError:
    from django.utils.crypto import get_random_string
    SETTINGS_DIR = os.path.abspath(os.path.dirname(__file__))
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
    secret_key = get_random_string(64, chars)

    with open(os.path.join(SETTINGS_DIR, 'secret_key.py'), 'w') as f:
        f.write("SECRET_KEY = '{}'\n".format(secret_key))

    SECRET_KEY = secret_key


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
    'documentation',
    'toolkit',
    'workflow'
]


INSTALLED_APPS.extend(AVAILABLE_APPS)


CRONJOBS = [
    ("* * * * *", "gui.crontab.rss.rss_fetch"),  # Every minute
    ("8 22 * * *", "gui.crontab.pki.update_crl"),  # Every day at 22:08
    ("7 22 * * *", "gui.crontab.pki.update_acme"),  # Every day at 22:07
    ("1 * * * *", "gui.crontab.feed.security_update"),  # Every hour
    ("1 * * * *", "gui.crontab.documentation.doc_update"),  # Every hour
    ("0 1 * * *", "gui.crontab.check_internal_tasks.check_internal_tasks")  # Every day at 01:00
]

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
            BASE_DIR + "/documentation/templates/documentation/",
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
        'HOST': get_hostname(),
        'REPLICASET': 'Vulture',
        'PORT': 9091,
        'SSL': True,
        'SSL_CERTFILE': '/var/db/pki/node.pem',
        'SSL_CA_CERTS': '/var/db/pki/ca.pem',
        'READPREFERENCE': ReadPreference.PRIMARY_PREFERRED
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
STATICFILES_DIRS = [
    # os.path.join(BASE_DIR, "static"),
    ('documentation', os.path.join(BASE_DIR, "documentation", "static"))
]

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
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/vulture/os/api.log',
            'formatter': 'verbose',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'gui': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/vulture/os/gui.log',
            'formatter': 'verbose',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'services': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/vulture/os/services.log',
            'formatter': 'verbose',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'daemon': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': '/var/log/vulture/os/cluster.log',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'crontab': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': '/var/log/vulture/os/crontab.log',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'authentication': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': '/var/log/vulture/os/authentication.log',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'system': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': '/var/log/vulture/os/system.log',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
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

DOCUMENTATION_PATH = "/var/db/documentation"

PREDATOR_HOST = "https://predator.vultureproject.org/"
PREDATOR_VERSION = "v1"
