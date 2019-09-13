"""vulture_os URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path, re_path, include
from django.conf.urls.i18n import i18n_patterns
from django.views.i18n import JavaScriptCatalog
from django.conf import settings

import glob
import logging
import logging.config

logging.config.dictConfig(settings.LOG_SETTINGS)

logger = logging.getLogger('debug')


def get_urls(path):
    urls = []
    for file in glob.glob(path):
        urls.append(file)

    return urls


urlpatterns = []


urls_files = {}
for app in settings.AVAILABLE_APPS:
    urls_files[app] = []
    urls_files[app].extend(get_urls(settings.BASE_DIR + '/{}/urls.py'.format(app)))
    urls_files[app].extend(get_urls(settings.BASE_DIR + '/{}/*/urls.py'.format(app)))


for app, urls in urls_files.items():
    for url in urls:
        url = url.replace(settings.BASE_DIR + "/", '').replace('/', '.').replace('.py', '')
        urlpatterns.append(re_path(r"^", include(url)))


urlpatterns += i18n_patterns(
    path("jsi18n/", JavaScriptCatalog.as_view(), name="javascript-catalog"),
)