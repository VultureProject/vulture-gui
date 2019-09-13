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
__doc__ = 'Cluster URLS'


from system.generic_delete import DeleteUser
from system.users import views
from django.urls import path

urlpatterns = [
    path('system/users/', views.users_list, name="system.users.list"),
    path('system/users/edit/', views.users_edit, name="system.users.edit"),
    path('system/users/edit/<int:object_id>', views.users_edit,
         name="system.users.edit"),
    path('system/users/delete/<int:object_id>', DeleteUser.as_view(),
         name="system.users.delete")
]
