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
__doc__ = 'Openvpn URLs'

# Django system imports
from django.urls import path, re_path

# Django project imports
from services.openvpn import api
from services.openvpn import views
from services.generic_list import ListOpenvpn


urlpatterns = [
    path('api/v1/services/openvpn/',
        api.OpenvpnAPIv1.as_view(),
        name="services.openvpn.api"
    ),

    path('api/v1/services/openvpn/<int:object_id>',
        api.OpenvpnAPIv1.as_view(),
        name="services.openvpn.api"
    ),

    path('api/v1/services/openvpn/<int:object_id>/<str:action>/',
        api.OpenvpnAPIv1.as_view(),
        name="services.openvpn.api"
    ),

    re_path('^services/openvpn/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            views.openvpn_delete,
            name="services.openvpn.delete"
    ),

    re_path('^services/openvpn/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.openvpn_edit,
            name="services.openvpn.edit"
    ),

    re_path('^services/openvpn/clone/(?P<object_id>[A-Fa-f0-9]+)$',
            views.openvpn_clone,
            name="services.openvpn.clone"
    ),

    re_path('^services/openvpn/start/(?P<object_id>[A-Fa-f0-9]+)$',
            views.openvpn_start,
            name="services.openvpn.start"
    ),

    re_path('^services/openvpn/restart/(?P<object_id>[A-Fa-f0-9]+)$',
            views.openvpn_restart,
            name="services.openvpn.restart"
    ),

    re_path('^services/openvpn/reload/(?P<object_id>[A-Fa-f0-9]+)$',
            views.openvpn_reload,
            name="services.openvpn.reload"
    ),

    re_path('^services/openvpn/stop/(?P<object_id>[A-Fa-f0-9]+)$',
            views.openvpn_stop,
            name="services.openvpn.stop"
    ),

    path('services/openvpn/', ListOpenvpn.as_view(), name="services.openvpn.list"),
]
