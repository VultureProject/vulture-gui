"""
Django settings for vulture project.
"""

import os
from pymongo import ReadPreference
from toolkit.network.network import get_hostname

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

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
    'documentation',
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
    '/home/vlt-gui/vulture/portal/templates',
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
        'HOST': get_hostname(),
        'REPLICASET': 'Vulture',
        'PORT': 9091,
        'SSL': True,
        'SSL_CERTFILE': '/var/db/pki/node.pem',
        'SSL_CA_CERTS': '/var/db/pki/ca.pem',
        'READPREFERENCE': ReadPreference.PRIMARY_PREFERRED
    }
}


LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

STATIC_URL = '/static/'

CACERT_DIR = '/var/db/mongodb/'
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
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
        'database': {
            'level': 'DEBUG',
            'class': 'toolkit.log.log_utils.DatabaseHandler',
            'type_logs': 'vulture',
        },
        'file_portal_authentication': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'verbose',
            'filename': '/var/log/vulture/portal/portal_authentication.log',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'file_redis_events': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'verbose',
            'filename': '/var/log/vulture/portal/redis_events.log',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'debug': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'verbose',
            'filename': '/var/log/vulture/portal/debug.log',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
    },
    'loggers': {
        'portal_authentication': {
            'handlers': ['file_portal_authentication', 'database'],
            'propagate': True,
            'level': 'INFO',
        },
        'redis_events': {
            'handlers': ['file_redis_events', 'database'],
            'propagate': True,
            'level': 'DEBUG',
        },
        'debug': {
            'handlers': ['debug', 'database'],
            'propagate': True,
            'level': 'INFO',
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
            'filename': '/var/log/vulture/portal/portal_authentication.log',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'file_redis_events': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'verbose',
            'filename': '/var/log/vulture/portal/redis_events.log',
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
        'debug': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'INFO',
            'formatter': 'verbose',
            'filename': '/var/log/vulture/portal/debug.log',
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
