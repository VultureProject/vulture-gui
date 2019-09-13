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
__doc__ = 'Listeners URLS'

# Django system imports
from django.urls import path, re_path

# Django project imports
from applications.logfwd import views, api
from applications.generic_list import ListLogfwd

# Required exceptions imports


urlpatterns = [
    path('apps/logfwd/', ListLogfwd.as_view(), name="applications.logfwd.list"),

    re_path('^apps/logfwd/edit/(?P<fw_type>[A-Za-z]+)/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.logfwd_edit,
            name="applications.logfwd.edit"),

    re_path('^apps/logfwd/clone/(?P<fw_type>[A-Za-z]+)/(?P<object_id>[A-Fa-f0-9]+)$',
            views.logfwd_clone,
            name="applications.logfwd.clone"),

    re_path('^apps/logfwd/delete/(?P<fw_type>[A-Za-z]+)/(?P<object_id>[A-Fa-f0-9]+)$',
            views.logfwd_delete,
            name="applications.logfwd.delete"),

    # All objects
    path("api/v1/apps/logfwd/", api.LogOMAPIv1.as_view(), name="applications.logfwd.api"),

    # Object with id object_id - get or modify
    path("api/v1/apps/logfwd/<int:object_id>/", api.LogOMAPIv1.as_view(), name="applications.logfwd.api"),

    # Object(s) of type fw_type - Get or create new
    path("api/v1/apps/logfwd/<str:fw_type>/", api.LogOMAPIv1.as_view(), name="applications.logfwd.api"),

    # Object of type fw_type with id object_id - Get or modify
    path("api/v1/apps/logfwd/<str:fw_type>/<int:object_id>/", api.LogOMAPIv1.as_view(), name="applications.logfwd.api"),

    # Do action on object with id object_id
    path("api/v1/apps/logfwd/<int:object_id>/<str:action>/", api.LogOMAPIv1.as_view(), name="applications.logfwd.api"),
]
