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
__version__ = "3.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'IDP Tools'

from authentication.user_portal.models import UserAuthentication


def get_repo(portal, repo_id):
    ldap_repo = None
    for repo in portal.repositories.all():
        if str(repo.pk) == str(repo_id):
            ldap_repo = repo.get_daughter()
            break

    if not ldap_repo:
        # The portal does not have a LDAP repository
        raise UserAuthentication.DoesNotExist()

    return ldap_repo


MAPPING_ATTRIBUTES = {
    "first_name": {
        "type": str,
        "internal_key": "displayName"
    },
    "last_name": {
        "type": str,
        "internal_key": "givenName"
    },
    "claim_list": {
        "type": list,
        "internal_key": "initials"
    },
    "user_type": {
        "type": str,
        "internal_key": "employeeType"
    },
    "internal": {
        "type": str,
        "internal_key": "businessCategory"
    },
    "smartcardid": {
        "type": str,
        "internal_key": "employeeNumber"
    }
}


def get_internal_attributes():
    # Internal
    repo_attributes = [value["internal_key"] for value in MAPPING_ATTRIBUTES.values()]
    return repo_attributes
