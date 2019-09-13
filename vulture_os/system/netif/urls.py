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
__doc__ = 'Netif URLS'


from system.netif import views, api
from django.urls import path, re_path
from system.generic_list import ListNetworkAddress


urlpatterns = [
    re_path('^system/netif/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            views.netif_delete,
            name="system.netif.delete"),

    re_path('^system/netif/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.netif_edit,
            name="system.netif.edit"),

    path('system/netif/', ListNetworkAddress.as_view(), name="system.netif.list"),

    path('system/netif/refresh', views.netif_refresh, name="system.netif.refresh"),

    path('api/v1/system/netaddr/', api.NetworkAddressAPIv1.as_view(), name="api.system.netaddr"),

    path('api/v1/system/netaddr/<int:object_id>', api.NetworkAddressAPIv1.as_view(), name="api.system.netaddr"),

    path('api/v1/system/netif/', api.NetworkInterfaceCardAPIv1.as_view(), name="api.system.netif"),

    path('api/v1/system/netif/refresh/', api.netif_refresh, name="api.system.netif.refresh")

]
