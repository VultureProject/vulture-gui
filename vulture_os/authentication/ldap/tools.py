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

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


AVAILABLE_GROUP_KEYS = ("group_attr",)
AVAILABLE_USER_KEYS = ("user_attr", "user_account_locked_attr", "user_change_password_attr", "user_mobile_attr", "user_email_attr", "user_smartcardid_attr")


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

def get_users(ldap_repository):
    group_dn = f"{ldap_repository.group_dn},{ldap_repository.base_dn}"
    group = find_group(ldap_repository, group_dn, ['*'])
    members  = []
    for member_dn in group['member']:
        members.append(find_user(ldap_repository, member_dn, ["+", "*"]))    
    return members


def get_groups(ldap_repository):
    ldap_client = ldap_repository.get_client()
    group_base_dn = f"{ldap_repository.group_dn},{ldap_repository.base_dn}"
    data = []
    for group_dn in ldap_client.enumerate_groups():
        if group_base_dn not in group_dn:
            continue

        group = find_group(ldap_repository, group_dn, ['*'])
        data.append(group)
    return data


def create_user(ldap_repository, username, userPassword, attrs):
    group_dn = f"{ldap_repository.group_dn},{ldap_repository.base_dn}"
    user_dn = ldap_repository.create_user_dn(username)

    try:
        if find_user(ldap_repository, user_dn, attr_list=["*"]):
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
    r = client.add_user(user_dn, user, group_dn, userPassword)
    logger.info(f"User {username} created in LDAP {ldap_repository.name}")
    return r, user_dn


def update_user(ldap_repository, username, attrs, userPassword):
    user_dn = ldap_repository.create_user_dn(username)
    try:
        old_user = find_user(ldap_repository, user_dn, attr_list=["*"])
        if not old_user:
            raise IndexError()
    except IndexError:
        return create_user(ldap_repository, username, userPassword, attrs)

    for k, v in attrs.items():
        if not v:
            attrs[k] = []
        elif not isinstance(v, list):
            attrs[k] = [v]
    
    dn = old_user['dn']
    del(old_user['dn'])
    client = ldap_repository.get_client()
    r = client.update_user(dn, old_user, attrs, userPassword)
    logger.info(f"User {username} updated in LDAP {ldap_repository.name}")
    return r, dn

def delete_user(ldap_repository, username):
    group_dn = f"{ldap_repository.group_dn},{ldap_repository.base_dn}"   
    client = ldap_repository.get_client()

    try:
        user_dn = search_users(ldap_repository, username, by_dn=True)[0]
    except Exception:
        raise UserNotExistError()

    groups = [find_group(ldap_repository, group_dn, ["*"]) for group_dn in client.search_user_groups_by_dn(user_dn)]
    r = client.delete_user(user_dn, groups)
    logger.info(f"User {user_dn} deleted in LDAP {ldap_repository.name}")
    return r
