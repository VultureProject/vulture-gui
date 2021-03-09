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
__doc__ = 'UserAuthentication and UserSSO Repository URLS'

# Django system imports
from django.urls import path, re_path

# Django project imports
from authentication.generic_list import ListUserAuthentication
from authentication.generic_delete import DeleteUserAuthentication
from authentication.user_portal import views
from authentication.user_portal import api



urlpatterns = [
    # List view
    path('portal/user_authentication/',
         ListUserAuthentication.as_view(),
         name="portal.user_authentication.list"),
    # Edit view
    re_path('^portal/user_authentication/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.user_authentication_edit,
            name="portal.user_authentication.edit"),
    # Clone view
    re_path('^portal/user_authentication/clone/(?P<object_id>[A-Fa-f0-9]+)$',
            views.user_authentication_clone,
            name="portal.user_authentication.clone"),
    # Delete view
    re_path('^portal/user_authentication/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            DeleteUserAuthentication.as_view(),
            name="portal.user_authentication.delete"),

    path('portal/user_authentication/sso_wizard/',
          views.sso_wizard,
          name="portal.user_authentication.sso_wizard"),
    # path('authentication/ldap/group_search_test/',
    #      views.group_search_test,
    #      name="authentication.ldap.group_search_test"),

    path('api/v1/portal/user_authentication/',
        api.UserPortalApi.as_view(),
        name="api.portal.user_authentication"
    ),

    path('api/v1/portal/user_authentication/<str:object_id>/',
        api.UserPortalApi.as_view(),
        name="api.portal.user_authentication"
    ),
]
