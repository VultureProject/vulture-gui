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
from darwin.generic_list import ListDefenderPolicy, ListDefenderRuleset
from darwin.generic_delete import DeleteDefenderPolicy, DeleteDefenderRuleset
from darwin.defender_policy import views, api


# Required exceptions imports

urlpatterns = [
        # List view
        path('darwin/defender_policy/', ListDefenderPolicy.as_view(), name="darwin.defender_policy.list"),
        # Edit view
        re_path('^darwin/defender_policy/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
                views.defender_policy_edit,
                name="darwin.defender_policy.edit"),
        # Clone view
        re_path('^darwin/defender_policy/clone/(?P<object_id>[A-Fa-f0-9]+)$',
                views.defender_policy_clone,
                name="darwin.defender_policy.clone"),
        # Delete view
        re_path('^darwin/defender_policy/delete/(?P<object_id>[A-Fa-f0-9]+)$',
                DeleteDefenderPolicy.as_view(),
                name="darwin.defender_policy.delete"),

        path('darwin/defender_policy/defender/rulesets/',
                views.get_defender_raw_rule_set,
                name='darwin.defender_policy.rulesets'),

        path('darwin/defender_policy/defender/raw-rulesets/<slug:object_id>/',
                views.save_defender_raw_rule_set,
                name='darwin.defender_policy.raw_rulesets'),

        # List view
        path('darwin/defender_ruleset/', ListDefenderRuleset.as_view(), name="darwin.defender_ruleset.list"),
        # Edit view
        re_path('^darwin/defender_ruleset/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
                views.defender_ruleset_edit,
                name="darwin.defender_ruleset.edit"),
        # Clone view
        re_path('^darwin/defender_ruleset/clone/(?P<object_id>[A-Fa-f0-9]+)$',
                views.defender_ruleset_clone,
                name="darwin.defender_ruleset.clone"),
        # Delete view
        re_path('^darwin/defender_ruleset/delete/(?P<object_id>[A-Fa-f0-9]+)$',
                DeleteDefenderRuleset.as_view(),
                name="darwin.defender_ruleset.delete"),

        path("api/v1/darwin/defender_policy/", api.DefenderPolicyAPIv1.as_view(), name="api.darwin.defender_policy"),
        path("api/v1/darwin/defender_policy/<str:object_id>/", api.DefenderPolicyAPIv1.as_view(), name="api.darwin.defender_policy"),
]
