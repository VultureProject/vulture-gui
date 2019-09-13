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
__author__ = "Théo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'MMcapture URLs'

# Django system imports
from django.urls import path, re_path

# Darwin imports
from darwin.generic_list import ListInspectionPolicy, ListInspectionRule
from darwin.generic_delete import DeleteInspectionPolicy, DeleteInspectionRule
from darwin.inspection import views, api

urlpatterns = [
    path('darwin/inspection/', ListInspectionPolicy.as_view(), name="darwin.inspection_policies"),
    path('darwin/inspection/rules', ListInspectionRule.as_view(), name="darwin.inspection_rules"),
    path('darwin/inspection/policy/clone/', views.clone_inspection_policy, name="darwin.inspection_policies.clone"),
    path('darwin/inspection/rule/clone/', views.clone_inspection_rule, name="darwin.inspection_rules.clone"),
    path('api/v1/darwin/inspection/rules/update/', views.fetch_rules, name="darwin.inspection_rules.update"),
    re_path('^darwin/inspection/policy/edit/(?P<object_id>[A-Fa-f0-9]+)?$', views.edit_inspection_policy, name="darwin.inspection_policies.edit"),
    re_path('^darwin/inspection/policy/delete/(?P<object_id>[A-Fa-f0-9]+)?$', DeleteInspectionPolicy.as_view(), name="darwin.inspection_policies.delete"),
    re_path('^darwin/inspection/rule/edit/(?P<object_id>[A-Fa-f0-9]+)?$', views.edit_inspection_rule, name="darwin.inspection_rules.edit"),
    re_path('^darwin/inspection/rule/delete/(?P<object_id>[A-Fa-f0-9]+)?$', DeleteInspectionRule.as_view(), name="darwin.inspection_rules.delete"),
]
