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

from django.urls import path, include
from django.conf.urls.i18n import i18n_patterns
from django.views.defaults import bad_request as default_bad_request
from django.views.defaults import permission_denied as default_permission_denied
from django.views.defaults import page_not_found as default_page_not_found
from django.views.defaults import server_error as default_server_error
from django.http import JsonResponse
from django.utils.translation import gettext_lazy as _
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


def custom400(request, exception=None):
    api_url = request.get_full_path().startswith("/api/")
    if api_url:
        return JsonResponse({
            "error": _("Bad request")
        }, status= 400)
    else:
        return default_bad_request(request, exception)

def custom403(request, exception=None):
    api_url = request.get_full_path().startswith("/api/")
    if api_url:
        return JsonResponse({
            "error": _("Permission denied")
        }, status= 403)
    else:
        return default_permission_denied(request, exception)

def custom404(request, exception=None):
    api_url = request.get_full_path().startswith("/api/")
    if api_url:
        return JsonResponse({
            "error": _("Resource not found")
        }, status= 404)
    else:
        return default_page_not_found(request, exception)

def custom500(request):
    api_url = request.get_full_path().startswith("/api/")
    if api_url:
        return JsonResponse({
            "error": _("Server error")
        }, status= 500)
    else:
        return default_server_error(request)

handler400 = custom400
handler403 = custom403
handler404 = custom404
handler500 = custom500

urlpatterns = []


urls_files = {}
for app in settings.AVAILABLE_APPS:
    urls_files[app] = []
    urls_files[app].extend(get_urls(settings.BASE_DIR + '/{}/urls.py'.format(app)))
    urls_files[app].extend(get_urls(settings.BASE_DIR + '/{}/*/urls.py'.format(app)))


for app, urls in urls_files.items():
    for url in urls:
        url = url.replace(settings.BASE_DIR + "/", '').replace('/', '.').replace('.py', '')
        urlpatterns.append(path("", include(url)))


urlpatterns += i18n_patterns(
    path("jsi18n/", JavaScriptCatalog.as_view(), name="javascript-catalog"),
)