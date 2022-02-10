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
__author__ = "Kévin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Tenants URLS'


from django.urls import path, re_path
from system.tenants import views, api
from system.generic_list import ListTenants

urlpatterns = [

    path('system/tenants/', ListTenants.as_view(), name="system.tenants.list"),

    re_path('^system/tenants/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            views.tenants_delete,
            name="system.tenants.delete"),

    re_path('^system/tenants/clone/(?P<object_id>[A-Fa-f0-9]+)$',
            views.tenants_clone,
            name="system.tenants.clone"),

    re_path('^system/tenants/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.tenants_edit,
            name="system.tenants.edit"),

    path('api/v1/system/tenants/', api.TenantsAPIv1.as_view(), name="system.tenants.api"),
    path('api/v1/system/tenants/<str:object_id>/', api.TenantsAPIv1.as_view(), name="system.tenants.api"),

]
