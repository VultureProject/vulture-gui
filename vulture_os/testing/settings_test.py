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

# Applying custom patches to code
try:
    from toolkit.patches import *
except ImportError:
    pass

LOG_LEVEL = "INFO"

DEBUG = False
DEV_MODE = False
TEMPLATE_DEBUG = DEBUG

ALLOWED_HOSTS = ["*"]

CSRF_COOKIE_SECURE = True
CSRF_TRUSTED_ORIGINS = ["https://vulture-nginx:8000"]

# Application definition
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_crontab",
]

AVAILABLE_APPS = [
    "gui",
    "services",
    "system",
    "authentication",
    "applications",
    "darwin",
    "toolkit",
    "workflow",
]


INSTALLED_APPS.extend(AVAILABLE_APPS)

CRONJOBS = [
    ("* * * * *", "gui.crontab.api_clients_parser.api_clients_parser"),  # Every minute
    ("8 22 * * *", "gui.crontab.pki.update_crl"),  # Every day at 22:08
    ("7 22 * * *", "gui.crontab.pki.update_acme"),  # Every day at 22:07
    ("0 23 * * *", "gui.crontab.feed.security_update"),  # Every day at 23:00
    (
        "0 6 * * wed,sat",
        "gui.crontab.feed.update_reputation_ctx",
    ),  # Every wednesday and saturday at 06:00
    (
        "0 1 * * *",
        "gui.crontab.check_internal_tasks.check_internal_tasks",
    ),  # Every day at 01:00
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
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "gui.middlewares.api_middleware.JSONParsingMiddleware",
    "gui.middlewares.api_middleware.PutParsingMiddleware",
    "gui.middlewares.os.OsMiddleware",
]

ROOT_URLCONF = "vulture_os.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            BASE_DIR + "/templates/",
            BASE_DIR + "/gui/templates/gui/",
            BASE_DIR + "/services/templates/services/",
            BASE_DIR + "/system/templates/system/",
            BASE_DIR + "/darwin/access_control/config",
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "gui.context_processors.admin_media",
            ],
        },
    },
]

WSGI_APPLICATION = "vulture_os.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "vulture",
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

REDISIP = "127.0.0.1"
REDISPORT = "6379"

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
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/
MEDIA_PATH = "gui/static/img/"
STATIC_ROOT = os.path.join(BASE_DIR, "static")
STATIC_URL = "static/"

LOG_SETTINGS = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "(%(name)s) %(asctime)s %(module)s:%(lineno)d [%(levelname)s] %(message)s"
        }
    },
    "handlers": {
        # By default, only output ERROR+ logs to stdout/stderr
        "console-errors": {
            "class": "logging.StreamHandler",
            "level": "ERROR",
        },
        "debug-test": {
            "class": "logging.StreamHandler",
            "level": LOG_LEVEL,
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console-errors"],
        "level": "ERROR",
    },
    "loggers": {
        "debug": {
            "handlers": ("debug-test",),
            "level": LOG_LEVEL,
            "propagate": True,
        },
        "auth": {"handlers": ("debug-test",), "level": LOG_LEVEL, "propagate": True},
        "api": {"handlers": ("debug-test",), "level": LOG_LEVEL, "propagate": True},
        "gui": {"handlers": ("debug-test",), "level": LOG_LEVEL, "propagate": True},
        "services": {
            "handlers": ("debug-test",),
            "level": LOG_LEVEL,
            "propagate": True,
        },
        "daemon": {"handlers": ("debug-test",), "level": LOG_LEVEL, "propagate": True},
        "crontab": {"handlers": ("debug-test",), "level": LOG_LEVEL, "propagate": True},
        "api_parser": {
            "handlers": ("debug-test",),
            "level": LOG_LEVEL,
            "propagate": True,
        },
        "authentication": {
            "handlers": ("debug-test",),
            "level": LOG_LEVEL,
            "propagate": True,
        },
        "system": {"handlers": ("debug-test",), "level": LOG_LEVEL, "propagate": True},
    },
}

TITLE = "VULTURE OS"
VERSION = "0.1"
WEBSITE = "https://www.vultureproject.org"
COMPANY = "Vulture Project"
LOGO_SM = "img/vulture-logo-small.png"
LOGO = "img/vulture-logo.png"
LOGO_LG = "img/vulture_logo.png"
WALLPAPER = "img/VultureOS_wallpaper.png"
