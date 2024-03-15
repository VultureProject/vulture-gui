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
__doc__ = 'Access Control URLS'

from security.generic_delete import DeleteAccessControl
from security.generic_list import ListAccessControl
from security.access_control import views, api
from django.urls import path, re_path


urlpatterns = [
    path('security/acl/get', views.access_control_get, name="security.access_control.get"),
    path('security/acl/clone', views.access_control_clone, name="security.access_control.clone"),
    path('security/acl/', ListAccessControl.as_view(), name="security.access_control.list"),
    re_path('^security/acl/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.access_control_edit, name="security.access_control.edit"),
    path('security/acl/delete/<int:object_id>',
            DeleteAccessControl.as_view(), name="security.access_control.delete"),

    path('api/v1/security/acl/', api.ACLAPIv1.as_view(), name="api.security.access_control.get"),
    path('api/v1/security/acl/<int:object_id>/',
            api.ACLAPIv1.as_view(), name="api.security.access_control.get"),
    re_path('^api/v1/security/acl/edit/(?P<object_id>[A-Fa-f0-9]+)?/?$',
            api.ACLAPIv1.as_view(), name="api.security.access_control.edit"),

]
