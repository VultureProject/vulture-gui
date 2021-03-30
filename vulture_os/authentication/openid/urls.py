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
__doc__ = 'OpenID Repository URLS'

# Django system imports
from django.urls import path, re_path

# Django project imports
from authentication.generic_list import ListOpenIDRepository
from authentication.generic_delete import DeleteOpenIDRepository
from authentication.openid import views
from authentication.openid import api


# Required exceptions imports


urlpatterns = [
    # List view
        path('authentication/openid/', ListOpenIDRepository.as_view(), name="authentication.openid.list"),
        # Edit view
        re_path('^authentication/openid/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
                views.edit,
                name="authentication.openid.edit"),
        # Clone view
        re_path('^authentication/openid/clone/(?P<object_id>[A-Fa-f0-9]+)$',
                views.clone,
                name="authentication.openid.clone"),
        # Delete view
        re_path('^authentication/openid/delete/(?P<object_id>[A-Fa-f0-9]+)$',
                DeleteOpenIDRepository.as_view(),
                name="authentication.openid.delete"),
        # Authentication test views
        path('authentication/openid/test_provider/',
                views.test_provider,
                name="authentication.openid.test_provider"),

        path('api/v1/authentication/openid/',
        api.OPENIDApi.as_view(),
        name="authentication.openid.api"
    ),

    path('api/v1/authentication/openid/<int:object_id>/',
        api.OPENIDApi.as_view(),
        name="authentication.openid.api"
    )
]
