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
__doc__ = 'Kerberos Repository URLS'

# Django system imports
from django.urls import path, re_path

# Django project imports
from authentication.generic_list import ListKerberosRepository
from authentication.generic_delete import DeleteKerberosRepository
from authentication.kerberos import views


# Required exceptions imports


urlpatterns = [
    # List view
    path('authentication/kerberos/', ListKerberosRepository.as_view(), name="authentication.kerberos.list"),
    # Edit view
    re_path('^authentication/kerberos/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.kerberos_edit,
            name="authentication.kerberos.edit"),
    # Clone view
    re_path('^authentication/kerberos/clone/(?P<object_id>[A-Fa-f0-9]+)$',
            views.kerberos_clone,
            name="authentication.kerberos.clone"),
    # Delete view
    re_path('^authentication/kerberos/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            DeleteKerberosRepository.as_view(),
            name="authentication.kerberos.delete"),

    # Authentication test views
    path('authentication/kerberos/user_search_test/',
         views.user_search_test,
         name="authentication.kerberos.user_search_test"),
]
