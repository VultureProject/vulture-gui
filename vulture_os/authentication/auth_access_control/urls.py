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
__doc__ = 'Authentication Access Control URLS'

from authentication.auth_access_control import api
from authentication.auth_access_control import views
from authentication.generic_list import ListAuthenticationAccessControl
from authentication.generic_delete import DeleteAuthAccessControl
from django.urls import path, re_path

urlpatterns = [
    path('portal/authentication/acl/', ListAuthenticationAccessControl.as_view(), name="portal.authentication_access_control"),
    re_path('^portal/authentication/acl/edit/(?P<object_id>[A-Fa-f0-9]+)?$', views.auth_access_control_edit, name="portal.authentication_access_control.edit"),
    path('api/v1/portal/authentication/acl/clone/', api.auth_access_control_clone, name="portal.authentication_access_control.clone"),
    path('api/v1/portal/authentication/acl/', api.AuthenticationAccessControlAPIv1.as_view(), name="api.portal.authentication_access_control"),

    path('api/v1/portal/authentication/acl/<str:object_id>/', api.AuthenticationAccessControlAPIv1.as_view(), name="api.portal.authentication_access_control"),
    re_path('^portal/authentication/acl/delete/(?P<object_id>[A-Fa-f0-9]+)?$', DeleteAuthAccessControl.as_view(), name="portal.authentication_access_control.delete"),
]