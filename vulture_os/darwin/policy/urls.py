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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Darwin URLS'

# Django system imports
from django.urls import path, re_path

# Django project imports
from darwin.generic_list import ListDarwinPolicy
from darwin.generic_delete import DeleteDarwinPolicy
from darwin.policy import views, api


# Required exceptions imports

urlpatterns = [
    # List view
    path('darwin/policy/', ListDarwinPolicy.as_view(), name="darwin.policy.list"),
    # Edit view
    re_path('^darwin/policy/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.policy_edit,
            name="darwin.policy.edit"),
    # Clone view
    re_path('^darwin/policy/clone/(?P<object_id>[A-Fa-f0-9]+)$',
            views.policy_clone,
            name="darwin.policy.clone"),
    # Delete view
    re_path('^darwin/policy/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            DeleteDarwinPolicy.as_view(),
            name="darwin.policy.delete"),

    path('api/v1/darwin/policy', api.DarwinPolicyAPIv1.as_view(), name="darwin.policy.api"),
    path('api/v1/darwin/policy/<int:object_id>', api.DarwinPolicyAPIv1.as_view(), name="darwin.policy.api"),
    path('api/v1/darwin/policy/<int:object_id>/<str:action>', api.DarwinPolicyAPIv1.as_view(), name="darwin.policy.api"),
]
