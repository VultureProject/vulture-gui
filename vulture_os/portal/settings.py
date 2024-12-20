"""
Django settings for vulture project.
"""

from os import path as os_path
from toolkit.network.network import get_hostname
from toolkit.system.secret_key import set_key

BASE_DIR = os_path.dirname(os_path.dirname(os_path.abspath(__file__)))
SETTINGS_DIR = os_path.abspath(os_path.dirname(__file__))

# Project folders
ROOT_PATH = "/"
DBS_PATH = os_path.join(ROOT_PATH, "var/db")
TMP_PATH = os_path.join(ROOT_PATH, "var/tmp")
LOGS_PATH = os_path.join(ROOT_PATH, "var/log")
SOCKETS_PATH = os_path.join(ROOT_PATH, "var/sockets")
HOMES_PATH = os_path.join(ROOT_PATH, "home")
LOCALETC_PATH = os_path.join(ROOT_PATH, "usr/local/etc")

HOSTNAME = get_hostname()

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

LOG_LEVEL = 'INFO'

DEBUG = False
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
        'ENGINE': 'djongo',
        'NAME': 'vulture',
        "CLIENT": {
            'host': HOSTNAME,
            'port': 9091,
            'serverSelectionTimeoutMS': 5000,
            'REPLICASET': 'Vulture',
            'SSL': True,
            'tlsCertificateKeyFile': os_path.join(DBS_PATH, 'pki/node.pem'),
            'tlsCAFile': os_path.join(DBS_PATH, 'pki/ca.pem'),
            'READPREFERENCE': "primaryPreferred"
        },
    }
}


LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'

CACERT_DIR = os_path.join(DBS_PATH, 'mongodb/')
MONGODBPORT = 9091
MONGODBARBPORT = 9092
REDISIP = '127.0.0.1'
REDISPORT = '6379'
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
        'database': {
            'level': LOG_LEVEL,
            'class': 'toolkit.log.log_utils.DatabaseHandler',
            'type_logs': 'vulture',
        },
        'file_portal_authentication': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': os_path.join(LOGS_PATH, 'vulture/portal/portal_authentication.log'),
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'file_redis_events': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': os_path.join(LOGS_PATH, 'vulture/portal/redis_events.log'),
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'authentication': {
            'class': 'logging.handlers.WatchedFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': os_path.join(LOGS_PATH, 'vulture/portal/authentication.log'),
            'mode': 'a'
        },
        'debug': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'verbose',
            'filename': os_path.join(LOGS_PATH, 'vulture/portal/debug.log'),
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
            'handlers': ['file_portal_authentication', 'database', 'console'],
            'propagate': True,
            'level': LOG_LEVEL,
        },
        'redis_events': {
            'handlers': ['file_redis_events', 'database', 'console'],
            'propagate': True,
            'level': LOG_LEVEL,
        },
        'authentication': {
            'handlers': ('authentication', 'database', 'console'),
            'propagate': True,
            'level': LOG_LEVEL,
        },
        'debug': {
            'handlers': ['debug', 'database', 'console'],
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
