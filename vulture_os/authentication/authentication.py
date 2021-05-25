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
__doc__ = 'Authentication main class'

# Django system imports
from django.conf import settings
from django.utils.translation import ugettext as _

# Django project imports

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)


class Authentication:

    def __init__(self):
        self.logger = logging.getLogger('gui')

    @property
    def menu(self):
        MENU = {
            'link': 'authentication',
            'icon': 'fas fa-fingerprint',
            'text': _('Identity Providers'),
            'url': "#",
            'submenu': [
                {
                    'link': 'ldap',
                    'text': 'LDAP',
                    'url': '/authentication/ldap/'
                },
                {
                    'link': 'kerberos',
                    'text': _('Kerberos'),
                    'url': '/authentication/kerberos/'
                },
                {
                    'link': 'radius',
                    'text': _('Radius'),
                    'url': '/authentication/radius/'
                },
                {
                    'link': 'otp',
                    'text': _('MFA & OTP'),
                    'url': '/authentication/otp/'
                },
                {
                    'link': 'totp_profiles',
                    'text': _('Time-based OTP profiles'),
                    'url': '/authentication/totp_profiles/'
                },
                {
                    'link': 'openid',
                    'text': _('OpenID federation'),
                    'url': '/authentication/openid/'
                },
                {
                    'link': 'learning_profiles',
                    'text': _('SSO Profiles'),
                    'url': '/authentication/learning_profiles/'
                }
            ]
        }

        return MENU
