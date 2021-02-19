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
__doc__ = 'LDAP Repository URLS'

# Django system imports
from django.urls import path, re_path

# Django project imports
from authentication.generic_list import ListLDAPRepository
from authentication.generic_delete import DeleteLDAPRepository
from authentication.ldap import views
from authentication.ldap import api


# Required exceptions imports


urlpatterns = [
        # List view
    path('authentication/ldap/', ListLDAPRepository.as_view(), name="authentication.ldap.list"),

    re_path('^authentication/ldap/view/(?P<object_id>[A-Fa-f0-9]+)$', views.ldap_view, name="authentication.ldap.view"),

    # Edit view
    re_path('^authentication/ldap/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.ldap_edit,
            name="authentication.ldap.edit"),
    # Clone view
    re_path('^authentication/ldap/clone/(?P<object_id>[A-Fa-f0-9]+)$',
            views.ldap_clone,
            name="authentication.ldap.clone"),
    # Delete view
    re_path('^authentication/ldap/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            DeleteLDAPRepository.as_view(),
            name="authentication.ldap.delete"),

    # Authentication test views
    path('authentication/ldap/user_search_test/',
            views.user_search_test,
            name="authentication.ldap.user_search_test"),
    path('authentication/ldap/group_search_test/',
            views.group_search_test,
            name="authentication.ldap.group_search_test"),
    
    # API
    path('api/v1/authentication/ldap/view/<int:object_id>/',
        api.LDAPViewApi.as_view(),
        name="authentication.api.ldap.view"
    ),

    path('api/v1/authentication/ldap/<int:object_id>/',
        api.LDAPApi.as_view(),
        name="authentication.api.ldap"
    )
]
