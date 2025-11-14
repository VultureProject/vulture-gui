"""
Django settings for vulture project.
"""

import environ
from os import path as os_path
from toolkit.network.network import get_hostname
from toolkit.system.secret_key import set_key

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
PORTAL_AUTHENTICATION_LOGS_PATH = os_path.join(LOGS_PATH, env.str("PORTAL_AUTHENTICATION_LOGS_PATH", 'vulture/portal/portal_authentication.log'))
REDIS_EVENTS_LOGS_PATH = os_path.join(LOGS_PATH, env.str("REDIS_EVENTS_LOGS_PATH", 'vulture/portal/redis_events.log'))
AUTHENTICATION_LOGS_PATH = os_path.join(LOGS_PATH, env.str("AUTHENTICATION_LOGS_PATH", 'vulture/portal/authentication.log'))
DEBUG_LOGS_PATH = os_path.join(LOGS_PATH, env.str("DEBUG_LOGS_PATH", 'vulture/portal/debug.log'))

HOSTNAME = env.str("HOSTNAME", get_hostname())

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
TEMPLATE_DEBUG = DEBUG

ALLOWED_HOSTS = ["*"]

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_NAME = "csrftk"

CONN_MAX_AGE = None

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
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

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'portal.middleware.VultureCSRFMiddleWare'
)

TEMPLATE_DIRS = (
    os_path.join(HOMES_PATH, 'vlt-gui/vulture/portal/templates'),
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.core.context_processors.request',
)

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR + "/portal/templates/",
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
            'autoescape': False,
        },
    },
]

ROOT_URLCONF = 'portal.urls'

WSGI_APPLICATION = 'portal.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'vulture',
        'USER': 'postgres',
        'PASSWORD': '',
        'HOST': env.str('POSTGRES_HOST', HOSTNAME),
        'PORT': env.int('POSTGRES_PORT', 5432),
    }
}


LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'

CACERT_DIR = os_path.join(DBS_PATH, 'mongodb/')
REDISIP = env.str('REDIS_HOST', '127.0.0.1')
REDISPORT = env.int('REDIS_PORT', 6379)
OS = "FreeBSD"

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
        'file_portal_authentication': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': PORTAL_AUTHENTICATION_LOGS_PATH,
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'file_redis_events': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': REDIS_EVENTS_LOGS_PATH,
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'authentication': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': AUTHENTICATION_LOGS_PATH,
            'mode': 'a'
        },
        'debug': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': DEBUG_LOGS_PATH,
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
    },
    'root': {
        'handlers': ['console-errors'],
        'level': 'ERROR',
    },
    'loggers': {
        'portal_authentication': {
            'handlers': ['file_portal_authentication', 'console'],
            'propagate': True,
            'level': LOG_LEVEL,
        },
        'redis_events': {
            'handlers': ['file_redis_events', 'console'],
            'propagate': True,
            'level': LOG_LEVEL,
        },
        'authentication': {
            'handlers': ('authentication', 'console'),
            'propagate': True,
            'level': LOG_LEVEL,
        },
        'debug': {
            'handlers': ['debug', 'console'],
            'propagate': True,
            'level': LOG_LEVEL,
        },
    }
}

LOG_SETTINGS_FALLBACK = {
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
        'file_portal_authentication': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'verbose',
            'filename': os_path.join(LOGS_PATH, 'vulture/portal/portal_authentication.log'),
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'file_redis_events': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'verbose',
            'filename': os_path.join(LOGS_PATH, 'vulture/portal/redis_events.log'),
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'debug': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'verbose',
            'filename': os_path.join(LOGS_PATH, 'vulture/portal/debug.log'),
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
    },
    'loggers': {
        'portal_authentication': {
            'handlers': ['file_portal_authentication'],
            'propagate': True,
            'level': 'INFO',
        },
        'redis_events': {
            'handlers': ['file_redis_events'],
            'propagate': True,
            'level': 'DEBUG',
        },
        'debug': {
            'handlers': ['debug'],
            'propagate': True,
            'level': 'INFO',
        },
    }
}
