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
__doc__ = 'LDAP Tools'

import logging
from django.conf import settings
from copy import deepcopy
from authentication.idp.attr_tools import get_internal_attributes

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


AVAILABLE_GROUP_KEYS = ("group_attr",)
AVAILABLE_USER_KEYS = ("user_attr", "user_mobile_attr", "user_email_attr")
AVAILABLE_USER_FILTERS = ("user_account_locked_attr", "user_change_password_attr")


class NotUniqueError(Exception):
    pass


class UserDoesntExistError(Exception):
    def __init__(self, dn=None):
        self.user_dn = dn
        if self.user_dn:
            self.message = f"User {self.user_dn} does not exist"
        else:
            self.message = "User does not exist"
        super().__init__(self.message)

class GroupDoesntExistError(Exception):
    def __init__(self, dn=None):
        self.group_dn = dn
        if self.group_dn:
            self.message = f"Group {self.group_dn} does not exist"
        else:
            self.message = "Group does not exist"
        super().__init__(self.message)


def _find_user(ldap_repo, user_dn, attr_list):
    client = ldap_repo.get_client()
    dn, attrs = client.search_by_dn(user_dn, attr_list=attr_list)
    if not dn:
        return None

    user = {"dn": dn}

    for key in AVAILABLE_USER_KEYS:
        ldap_key = getattr(ldap_repo, key)
        if ldap_key:
            user[ldap_key] = attrs.get(ldap_key, "")

    for key in AVAILABLE_USER_FILTERS:
        ldap_key = getattr(ldap_repo, f"get_{key}")
        if ldap_key:
            try:
                user[ldap_key] = attrs[ldap_key]
            except KeyError:
                pass

    for key in get_internal_attributes():
        if attrs.get(key):
            user[key] = attrs.get(key)

    for ldap_key, _ in ldap_repo.custom_attribute_mappings:
        if ldap_key in attrs:
            user[ldap_key] = attrs[ldap_key]

    return user


def _find_group(ldap_repo, group_dn, attr_list):
    client = ldap_repo.get_client()
    dn, attrs = client.search_by_dn(group_dn, attr_list=attr_list)
    if not dn:
        return None

    group = {"dn": dn}

    for key in AVAILABLE_GROUP_KEYS:
        ldap_key = getattr(ldap_repo, key)
        if ldap_key:
            group[ldap_key] = attrs[ldap_key]

    group[ldap_repo.group_member_attr] = attrs[ldap_repo.group_member_attr]
    return group


def _create_user(ldap_repository, user_dn, username, userPassword, attrs, group_dn=False):
    if _find_user(ldap_repository, user_dn, ["*"]):
        raise NotUniqueError(user_dn)

    user = {
        "sn": [username],
        "cn": [username],
        ldap_repository.user_attr: [username],
        "objectClass": ldap_repository.user_objectclasses,
        "description": ["User created by Vulture"]
    }

    for k, v in attrs.items():
        if v is None:
            attrs[k] = []
        elif not isinstance(v, list):
            attrs[k] = [v]

    user.update(attrs)
    client = ldap_repository.get_client()
    r = client.add_user(user_dn, user, userPassword, group_dn)
    logger.info(f"User {username} created in LDAP {ldap_repository.name}")
    return r, user_dn


def search_users(ldap_repo, search, by_dn=False):
    client = ldap_repo.get_client()
    tmp_users = client.search_user(f"{search}*", attr_list=["+","*"])
    data = []

    for dn, attrs in tmp_users:
        user_attr  = attrs.get(ldap_repo.user_attr)
        if not by_dn:
            data.append(user_attr[0])
        else:
            data.append(dn)

    return data


def get_user_by_dn(ldap_repo, dn, attrs_list=["+", "*"]):
    user = _find_user(ldap_repo, dn, attrs_list)
    if not user:
        raise UserDoesntExistError(dn=dn)

    # cleaning values to avoid lists of 1 element
    for key, value in user.items():
        if isinstance(value, list):
            user[key] = value[0]

    return user


def get_users_in_group(ldap_repository, group_name):
    group_dn = f"{group_name},{ldap_repository.get_client()._get_group_dn()}"
    group = _find_group(ldap_repository, group_dn, ['*'])
    if not group:
        raise GroupDoesntExistError(dn=group_dn)
    members  = []
    for member_dn in group['member']:
        members.append(_find_user(ldap_repository, member_dn, ["+", "*"]))
    return members


# def get_groups(ldap_repository):
#     ldap_client = ldap_repository.get_client()
#     group_base_dn = ldap_client._get_group_dn()
#     data = []
#     for group_dn in ldap_client.enumerate_groups():
#         if group_base_dn not in group_dn:
#             continue

#         group = _find_group(ldap_repository, group_dn, ['*'])
#         data.append(group)
#     return data


def find_user_email(ldap_repository, username):
    # No need to construct the scope, search_user does-it automatically...
    user = ldap_repository.get_client().search_user(username, attr_list=[ldap_repository.user_email_attr])
    if not user:
        raise UserDoesntExistError(dn=username)
    dn = user[0][0]
    mail = user[0][1][ldap_repository.user_email_attr]
    return dn, mail[0] if isinstance(mail, list) else mail


def create_user(ldap_repository, username, userPassword, attrs, group=False):
    group_dn = f"{group},{ldap_repository.get_client()._get_group_dn()}" if group else False
    user_dn = ldap_repository.create_user_dn(username)

    logger.debug(f"Creating user {username}({user_dn}) with attributes {attrs}")

    return _create_user(ldap_repository, user_dn, username, userPassword, attrs, group_dn)


def lock_unlock_user(ldap_repository, user_dn, lock=True):
    user = _find_user(ldap_repository, user_dn, ["*"])
    if not user:
        raise UserDoesntExistError(dn=user_dn)

    if not lock:
        logger.debug(f"Unlocking user {user_dn}")
        lock_value = ""
    else:
        logger.debug(f"Locking user {user_dn}")
        lock_value = ldap_repository.get_user_account_locked_value

    new_attrs = deepcopy(user)
    new_attrs[ldap_repository.get_user_account_locked_attr] = lock_value
    del(new_attrs["dn"])
    return update_user(ldap_repository, user_dn, new_attrs, False)


def update_user(ldap_repository, user_dn, attrs, userPassword):
    old_user = _find_user(ldap_repository, user_dn, ["*"])
    if not old_user:
        # attrs[ldap_repository.user_attr] is the username
        # update_user should return a key error if it doesn't exist (cannot create an user without it)
        return _create_user(ldap_repository, user_dn, attrs[ldap_repository.user_attr], userPassword, attrs)

    dn = old_user['dn']
    del(old_user['dn'])

    if ldap_repository.user_attr in attrs:
        if isinstance(attrs[ldap_repository.user_attr], list):
            user_attr = attrs[ldap_repository.user_attr][0] if attrs[ldap_repository.user_attr] else ''
        else:
            user_attr = attrs[ldap_repository.user_attr]
        logger.debug(f"ldap_tools::update_user: prevented username modification from '{old_user.get(ldap_repository.user_attr, [''])[0]}' to '{user_attr}'")
        assert user_attr == old_user.get(ldap_repository.user_attr, [''])[0], "Username cannot be modified after creation"

    # Add new attributes to old user
    attrs = dict(old_user, **attrs)
    for k, v in attrs.items():
        if v is None:
            attrs[k] = []
        elif not isinstance(v, list):
            attrs[k] = [v]

    client = ldap_repository.get_client()
    r = client.update_user(dn, old_user, attrs, userPassword)
    logger.info(f"User {user_dn} updated in LDAP {ldap_repository.name}")
    return r, dn


def delete_user(ldap_repository, user_dn):
    client = ldap_repository.get_client()

    old_user = _find_user(ldap_repository, user_dn, ["*"])
    if not old_user:
        raise UserDoesntExistError(dn=user_dn)

    groups = [_find_group(ldap_repository, group_dn, ["*"]) for group_dn in client.search_user_groups_by_dn(user_dn)]
    r = client.delete_user(user_dn, groups)
    logger.info(f"User {user_dn} deleted in LDAP {ldap_repository.name}")
    return r
