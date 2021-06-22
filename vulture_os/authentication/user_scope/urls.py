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
__doc__ = 'UserScope URLS'

# Django system imports
from django.urls import path, re_path

# Django project imports
from authentication.generic_list import ListUserScope
from authentication.generic_delete import DeleteUserScope
from authentication.user_scope import views, api



urlpatterns = [
    # List view
    path('authentication/user_scope/',
         ListUserScope.as_view(),
         name="portal.user_scope.list"),
    # Edit view
    re_path('^authentication/user_scope/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.user_scope_edit,
            name="portal.user_scope.edit"),
    # Clone view
    re_path('^authentication/user_scope/clone/(?P<object_id>[A-Fa-f0-9]+)$',
            views.user_scope_clone,
            name="portal.user_scope.clone"),
    # Delete view
    re_path('^authentication/user_scope/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            DeleteUserScope.as_view(),
            name="portal.user_scope.delete"),


    path('api/v1/authentication/user_scope/',
        api.UserScopeApi.as_view(),
        name="api.portal.user_scope"
    ),

    path('api/v1/authentication/user_scope/<str:object_id>/',
        api.UserScopeApi.as_view(),
        name="api.portal.user_scope"
    )
]
