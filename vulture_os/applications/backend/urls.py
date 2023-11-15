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
from applications.backend import views, api
from applications.generic_list import ListBackend


urlpatterns = [
    path('apps/backend/', ListBackend.as_view(), name="applications.backend.list"),

    path('apps/backend/delete/<int:object_id>',
            views.backend_delete,
            name="applications.backend.delete"),

    re_path('^apps/backend/edit/(?P<object_id>[0-9]+)?$',
            views.backend_edit,
            name="applications.backend.edit"),

    path('apps/backend/clone/<int:object_id>',
            views.backend_clone,
            name="applications.backend.clone"),

    path('apps/backend/start/<int:object_id>',
            views.backend_start,
            name="applications.backend.start"),

    path('apps/backend/pause/<int:object_id>',
            views.backend_pause,
            name="applications.backend.pause"),

    path('api/apps/backend/test_conf/', api.backend_test_conf, name="applications.backend.test_conf"),

    path('api/apps/backend/test/', api.test, name="applications.backend.test"),

    re_path('^api/v1/apps/backend/(?P<object_id>[0-9]+)?/?$', api.BackendAPIv1.as_view(), name="applications.backend.api"),

    path('api/v1/apps/backend/<int:object_id>/<str:action>/',
         api.BackendAPIv1.as_view(),
         name="applications.backend.api"),
]
