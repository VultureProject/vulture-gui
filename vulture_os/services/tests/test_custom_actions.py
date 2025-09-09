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

__author__ = "Fabien AMELINCK"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Tests for Frontend models'

from django.test import TestCase
from unittest.mock import patch

from services.frontend.models import Frontend
from services.frontend.form import FrontendForm
from services.rsyslogd.form import CustomActionsForm, RsyslogConditionForm


class CustomActionsCase(TestCase):
    TEST_CASE_NAME = f"{__name__}"

    def test_right_condition_validation(self):
        condition_line_form = RsyslogConditionForm({'condition': 'always', 'action': 'drop'})
        self.assertTrue(condition_line_form.is_valid())

    def test_wrong_condition_validation(self):
        condition_line_form = RsyslogConditionForm({'condition': 'always', 'action': 'set'})
        self.assertFalse(condition_line_form.is_valid())

    def test_json_validation(self):
        custom_actions_form = CustomActionsForm({'custom_actions': '[[{"condition": "always", "action": "drop"}]]'})
        self.assertTrue(custom_actions_form.is_valid())

    def test_json_string_validation(self):
        custom_actions_form = CustomActionsForm({'custom_actions': [[{'condition': 'always', 'action': 'drop'}]]})
        self.assertTrue(custom_actions_form.is_valid())

    def test_empty_json(self):
        custom_actions_form = CustomActionsForm({'custom_actions': []})
        self.assertTrue(custom_actions_form.is_valid())
        custom_actions_form = CustomActionsForm({'custom_actions': [[]]})
        self.assertTrue(custom_actions_form.is_valid())

    def test_missplaced_always_condition(self):
        """Test that 'always' condition not placed at the end raises a validation error."""
        invalid_actions = [
            [
                {"condition": "contains", "condition_variable": "$.foo", "condition_value": "bar", "action": "set", "result_variable": "$!test", "result_value": "1"},
                {"condition": "always", "action": "set", "result_variable": "$!test", "result_value": "2"},
                {"condition": "exists", "condition_variable": "$.tmp", "action": "set", "result_variable": "$!test", "result_value": "3"}
            ]
        ]
        custom_actions_form = CustomActionsForm({'custom_actions': invalid_actions})
        self.assertFalse(custom_actions_form.is_valid())
        self.assertIn("The 'Always' condition must be the last rule in the group", custom_actions_form.errors.get('custom_actions'))

    def test_multiple_always_condition(self):
        """Test that multiple 'always' conditions in a single group fail the validation."""
        invalid_actions = [
            [
                {"condition": "always", "action": "set", "result_variable": "$!test", "result_value": "1"},
                {"condition": "always", "action": "drop"}
            ]
        ]
        custom_actions_form = CustomActionsForm({'custom_actions': invalid_actions})
        self.assertFalse(custom_actions_form.is_valid())
        self.assertIn("Only one 'Always' condition is allowed per group", custom_actions_form.errors.get('custom_actions'))


class FrontendCase(TestCase):
    TEST_CASE_NAME = f"{__name__}"

    def setUp(self):
        self.logger_patcher = patch('services.frontend.models.logger')
        self.logger_patcher.start()

        self.frontend = Frontend.objects.create(
            name=f"test_frontend_{self.TEST_CASE_NAME}",
            mode="log",
            listening_mode="file",
            ruleset="raw_to_json",
            tags=["test"],
            custom_actions=[
                [
                    {
                        'condition': 'contains',
                        'condition_variable': '$.email_from_address',
                        'condition_value': 'toto@test.com',
                        'action': 'set',
                        'result_variable': '$.email_from_address',
                        'result_value': 'xxxxxx@test.com'
                    }
                ],
                [
                    {
                        'condition': 'contains',
                        'condition_variable': '$!techno',
                        'condition_value': 'rocket',
                        'action': 'unset',
                        'result_variable': '$!fuel'
                    },
                    {
                        'condition': 'exists',
                        'condition_variable': '$.life',
                        'action': 'unset',
                        'result_variable': '$!believes'
                    },
                    {
                        "condition": "iequals",
                        "condition_variable": "$.sitename",
                        "condition_value": "pluto",
                        "action": "drop"
                    },
                    {
                        'condition': 'equals',
                        'condition_variable': '$.sitename',
                        'condition_value': 'Universe',
                        'action': 'set',
                        'result_variable': '$!iplocation!where',
                        'result_value': 'kekpar'
                    },
                    {
                        "condition": "regex",
                        "condition_variable": "$.sitename",
                        "condition_value": "^[a-z]{6}$",
                        "action": "unset",
                        "result_variable": "$!location_unknown"
                    },
                    {
                        "condition": "always",
                        "action": "set",
                        "result_variable": "$!location",
                        "result_value": "nowhere"
                    }
                ]
            ]
        )

    def tearDown(self):
        # Cleanly remove the logger patch
        self.logger_patcher.stop()
        return super().tearDown()

    def test_frontend_submit(self):
        request = {
            "name": "Listener_test",
            "mode": "log",
            "listening_mode": "file",
            "ruleset": "raw_to_json",
            "tags": ["test"],
            "redis_stream_startID": "$",
            "nb_workers": 1,
            "queue_type": "direct",
            "custom_actions": '[[{"condition": "always", "action": "drop"}]]'
        }
        form = FrontendForm(request, instance=self.frontend)
        self.assertTrue(form.is_valid())

    def test_constant_rendering(self):
        """Test that render_custom_actions produces correct Rsyslog output."""
        expected_rsyslog = '''if re_match($.email_from_address, ".*toto@test.com.*") then { #contains\n    set $.email_from_address = "xxxxxx@test.com";\n}\nif re_match($!techno, ".*rocket.*") then { #contains\n    unset $!fuel;\n} else if exists($.life) then { #exists\n    unset $!believes;\n} else if re_match_i($.sitename, "^pluto\\$") then { #iequals\n    stop\n} else if $.sitename == "Universe" then { #equals\n    set $!iplocation!where = "kekpar";\n} else if re_match($.sitename, "^[a-z]{6}\\$") then { #regex\n    unset $!location_unknown;\n} else { #always\n    set $!location = "nowhere";\n}\n'''

        rendered = self.frontend.render_custom_actions()
        self.assertEqual(rendered, expected_rsyslog.strip)