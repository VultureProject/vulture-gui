#!/home/vlt-os/env/bin/python
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
__author__ = "Theo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "3.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'IDP API AUTHENTICATION'

import logging

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, JsonResponse
from functools import wraps
from portal.system.redis_sessions import REDISOauth2Session, REDISBase

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')

class JsonResponseUnauthorized(JsonResponse):
    def __init__(self):
        super().__init__({'error': 'Unauthorized'}, status=401)
        # if not hasattr(self, 'headers'):
        #     self.headers = {}
        self["WWW-Authenticate"] = "Please provide an 'Authorization' header with a valid token"

def api_check_authorization():
    """ Decorator used to check if the given API Key is correct
    passed in
    :param group_names: List of groups
    :return:
    """

    def decorator(func):
        @wraps(func)
        def inner(cls_or_request, *args, **kwargs):
            request = None

            if not isinstance(cls_or_request, HttpRequest):
                if not isinstance(args[0], HttpRequest):
                    logger.error("API Call without request object : {} and {}".format(cls_or_request, request))
                    return JsonResponseUnauthorized()
                else:
                    request = args[0]
            else:
                request = cls_or_request

            api_key = request.headers.get("authorization")
            if not api_key:
                logger.error(
                    "API Call without valid 'Authorization' header. Method (%s): %s", request.method, request.path,
                    extra={'status_code': 401, 'request': request}
                )
                return JsonResponseUnauthorized()

            api_key = api_key.replace("Bearer ", "")

            token = REDISOauth2Session(REDISBase(), f"oauth2_{api_key}")
            if not token.exists():
                logger.warning(f"Invalid token in API call: {api_key}")
                raise PermissionDenied()

            request.auth_token = token

            return func(request, *args, **kwargs)

        return inner
    return decorator
