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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Listeners URLS'

# Django system imports
from django.urls import path, re_path

# Django project imports
from services.strongswan import api
from services.strongswan import views
from services.generic_list import ListStrongswan


urlpatterns = [
    path('api/v1/services/strongswan/',
        api.StrongswanAPIv1.as_view(),
        name="services.strongswan.api"
    ),

    path('api/v1/services/strongswan/<int:object_id>',
        api.StrongswanAPIv1.as_view(),
        name="services.strongswan.api"
    ),

    path('api/v1/services/strongswan/<int:object_id>/<str:action>/',
        api.StrongswanAPIv1.as_view(),
        name="services.strongswan.api"
    ),

    re_path('^services/strongswan/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            views.strongswan_delete,
            name="services.strongswan.delete"
    ),

    re_path('^services/strongswan/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.strongswan_edit,
            name="services.strongswan.edit"
    ),

    re_path('^services/strongswan/clone/(?P<object_id>[A-Fa-f0-9]+)$',
            views.strongswan_clone,
            name="services.strongswan.clone"
    ),

    re_path('^services/strongswan/start/(?P<object_id>[A-Fa-f0-9]+)$',
            views.strongswan_start,
            name="services.strongswan.start"
    ),

    re_path('^services/strongswan/restart/(?P<object_id>[A-Fa-f0-9]+)$',
            views.strongswan_restart,
            name="services.strongswan.restart"
    ),

    re_path('^services/strongswan/reload/(?P<object_id>[A-Fa-f0-9]+)$',
            views.strongswan_reload,
            name="services.strongswan.reload"
    ),

    re_path('^services/strongswan/stop/(?P<object_id>[A-Fa-f0-9]+)$',
            views.strongswan_stop,
            name="services.strongswan.stop"
    ),

    path('services/strongswan/', ListStrongswan.as_view(), name="services.strongswan.list"),
]
