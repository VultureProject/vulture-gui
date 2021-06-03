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


class UserNotExistError(Exception):
    pass


def find_user(ldap_repo, user_dn, attr_list):
    client = ldap_repo.get_client()
    user = client.search_by_dn(user_dn, attr_list=attr_list)
    dn, attrs = user[0]
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

    return user


def find_group(ldap_repo, group_dn, attr_list):
    client = ldap_repo.get_client()
    group = client.search_by_dn(group_dn, attr_list=attr_list)

    dn, attrs = group[0]
    group = {"dn": dn}

    for key in AVAILABLE_GROUP_KEYS:
        ldap_key = getattr(ldap_repo, key)
        if ldap_key:
            group[ldap_key] = attrs[ldap_key]

    group[ldap_repo.group_member_attr] = attrs[ldap_repo.group_member_attr]
    return group

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


def get_users(ldap_repository, group_name):
    group_dn = f"{group_name},{ldap_repository.get_client()._get_group_dn()}"
    group = find_group(ldap_repository, group_dn, ['*'])
    members  = []
    for member_dn in group['member']:
        members.append(find_user(ldap_repository, member_dn, ["+", "*"]))    
    return members


def get_groups(ldap_repository):
    ldap_client = ldap_repository.get_client()
    group_base_dn = ldap_client._get_group_dn()
    data = []
    for group_dn in ldap_client.enumerate_groups():
        if group_base_dn not in group_dn:
            continue

        group = find_group(ldap_repository, group_dn, ['*'])
        data.append(group)
    return data


def find_user_email(ldap_repository, username):
    # No need to construct the scope, search_user does-it automatically...
    user = ldap_repository.get_client().search_user(username, attr_list=[ldap_repository.user_email_attr])
    if not user:
        raise UserNotExistError()
    dn = user[0][0]
    mail = user[0][1][ldap_repository.user_email_attr]
    return dn, mail[0] if isinstance(mail, list) else mail


def create_user(ldap_repository, username, userPassword, attrs, group_dn=False):
    if group_dn:
        group_dn = f"{group_dn},{ldap_repository.get_client()._get_group_dn()}"

    user_dn = ldap_repository.create_user_dn(username)

    try:
        if find_user(ldap_repository, user_dn, ["*"]):
            raise NotUniqueError()
    except IndexError:
        # User does not exists
        pass

    user = {
        "sn": [username],
        "cn": [username],
        ldap_repository.user_attr: [username],
        "objectClass": ["inetOrgPerson", "top"],
        "description": ["User created by Vulture"]
    }

    for k, v in attrs.items():
        if not v:
            attrs[k] = []
        elif not isinstance(v, list):
            attrs[k] = [v]

    user.update(attrs)
    client = ldap_repository.get_client()
    r = client.add_user(user_dn, user, userPassword, group_dn)
    logger.info(f"User {username} created in LDAP {ldap_repository.name}")
    return r, user_dn

def lock_unlock_user(ldap_repository, user_dn, lock=True):
    user = find_user(ldap_repository, user_dn, ["*"])
    if not user:
        raise UserNotExistError()

    lock_value = ldap_repository.get_user_account_locked_value
    if not lock:
        lock_value = ""
    
    new_attrs = deepcopy(user)
    new_attrs[ldap_repository.get_user_account_locked_attr] = lock_value
    del(new_attrs["dn"])
    return update_user(ldap_repository, user_dn, new_attrs, False)


def update_user(ldap_repository, user_dn, attrs, userPassword):
    try:
        old_user = find_user(ldap_repository, user_dn, ["*"])
        if not old_user:
            raise IndexError()
    except IndexError:
        return create_user(ldap_repository, user_dn, userPassword, attrs)

    dn = old_user['dn']
    del(old_user['dn'])

    attrs.update(old_user)
    for k, v in attrs.items():
        if not v:
            attrs[k] = []
        elif not isinstance(v, list):
            attrs[k] = [v]
    
    client = ldap_repository.get_client()
    r = client.update_user(dn, old_user, attrs, userPassword)
    logger.info(f"User {user_dn} updated in LDAP {ldap_repository.name}")
    return r, dn

def delete_user(ldap_repository, user_dn):
    group_dn = f"{ldap_repository.group_dn},{ldap_repository.base_dn}"   
    client = ldap_repository.get_client()

    old_user = find_user(ldap_repository, user_dn, ["*"])
    if not old_user:
        raise UserNotExistError()

    groups = [find_group(ldap_repository, group_dn, ["*"]) for group_dn in client.search_user_groups_by_dn(user_dn)]
    r = client.delete_user(user_dn, groups)
    logger.info(f"User {user_dn} deleted in LDAP {ldap_repository.name}")
    return r
