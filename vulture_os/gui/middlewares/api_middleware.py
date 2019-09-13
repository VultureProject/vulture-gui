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
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Middleware for PUT and DELETE methods'

from django.utils.deprecation import MiddlewareMixin
from django.utils.translation import ugettext_lazy as _
from django.http import HttpResponseBadRequest, JsonResponse
import json


class PutParsingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.method in ("PUT", "DELETE") and not hasattr(request, "JSON"):
            return JsonResponse({
                'error': _("Method is PUT and content-type is not JSON."),
            }, status=400)

        if request.method == "PUT" and request.content_type != "application/json":
            if hasattr(request, "_post"):
                del request._post
                del request._files

            try:
                request.method = "POST"
                request._load_post_and_files()
                request.method = "PUT"

            except AttributeError:
                request.META["REQUEST_METHOD"] = "POST"
                request._load_post_and_files()
                request.META["REQUEST_METHOD"] = "PUT"

            request.PUT = request.POST


class JSONParsingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.method in ("PATCH", "PUT", "POST", "DELETE") and request.content_type == "application/json":
            try:
                request.JSON = json.loads(request.body)

            except ValueError as error:
                return HttpResponseBadRequest(
                    "Unable to parse JSON data: {error}".format(error=error)
                )
