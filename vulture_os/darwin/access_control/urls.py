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

from darwin.generic_delete import DeleteAccessControl
from darwin.generic_list import ListAccessControl
from darwin.access_control import views, api
from django.urls import path, re_path


urlpatterns = [
    path('darwin/acl/get', views.access_control_get, name="darwin.access_control.get"),
    path('darwin/acl/clone', views.access_control_clone, name="darwin.access_control.clone"),
    path('darwin/acl/', ListAccessControl.as_view(), name="darwin.access_control.list"),
    re_path('^darwin/acl/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.access_control_edit, name="darwin.access_control.edit"),
    path('darwin/acl/delete/<int:object_id>',
            DeleteAccessControl.as_view(), name="darwin.access_control.delete"),

    path('api/v1/darwin/acl/', api.ACLAPIv1.as_view(), name="api.darwin.access_control.get"),
    re_path('^api/v1/darwin/acl/(?P<object_id>[A-Fa-f0-9]+)?/?$',
            api.ACLAPIv1.as_view(), name="api.darwin.access_control.get"),
    re_path('^api/v1/darwin/acl/edit/(?P<object_id>[A-Fa-f0-9]+)?/?$',
            api.ACLAPIv1.as_view(), name="api.darwin.access_control.edit"),
]
