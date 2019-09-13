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
__author__ = "Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Parser URLS'

# Django system imports
from django.urls import path, re_path

# Django project imports
from applications.parser import views, api
from applications.generic_list import ListParser


urlpatterns = [
    path('apps/parser/', ListParser.as_view(), name="applications.parser.list"),

    re_path('^apps/parser/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            views.parser_delete,
            name="applications.parser.delete"),

    re_path('^apps/parser/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.parser_edit,
            name="applications.parser.edit"),

    re_path('^apps/parser/clone/(?P<object_id>[A-Fa-f0-9]+)$',
            views.parser_clone,
            name="applications.parser.clone"),

    path('apps/parser/test/',
         api.parser_test,
         name="applications.parser.test_conf"),

    path('api/v1/apps/parser/',
         api.ParserAPIv1.as_view(),
         name="applications.parser.api"),

    path('api/v1/apps/parser/<int:object_id>/',
         api.ParserAPIv1.as_view(),
         name="applications.parser.api")
]
