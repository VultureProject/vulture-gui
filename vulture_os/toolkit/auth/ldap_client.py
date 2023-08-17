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
__author__ = "Florian Hagniel, Kevin GUILLEMOT"
__credits__ = ["Copyright https://github.com/ametaireau/django-auth-ldap"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'LDAP authentication client wrapper'

# Django system imports

# Django project imports
from toolkit.auth.base_auth import BaseAuth

# Extern modules imports
import copy
import ldap
import ldap.modlist as modlist
from ldap.filter import escape_filter_chars
from ldap.dn import escape_dn_chars


# Required exceptions imports
from toolkit.auth.exceptions import AuthenticationError, ChangePasswordError, UserNotFound, LDAPSizeLimitExceeded

# Logger configuration imports
import logging
logger = logging.getLogger('authentication')


class LDAPClient(BaseAuth):

    def __init__(self, settings):
        """ Instantiation method

        :param settings:
        :return:
        """
        # Connection settings
        self.host = settings.host
        self.port = settings.port
        try:
            self.user = settings.connection_dn
        except:
            self.user = ""
        try:
            self.password = settings.dn_password
        except:
            self.password = ""
        try:
            self.base_dn = settings.base_dn
        except:
            self.base_dn = ""
        self._connection_settings = {
            ldap.OPT_PROTOCOL_VERSION: settings.protocol,
            ldap.OPT_REFERRALS: 0,
            ldap.OPT_NETWORK_TIMEOUT: 5,
        }
        # User related settings
        try:
            self.user_dn = settings.user_dn
        except:
            self.user_dn = ""

        self.user_scope = settings.user_scope

        try:
            self.user_filter = settings.user_filter
        except:
            self.user_filter = ""
        try:
            self.user_attr = settings.user_attr
        except:
            self.user_attr = ""
        try:
            self.user_objectclasses = list()
            for object_class in settings.user_objectclasses:
                self.user_objectclasses.append(bytes(object_class, 'utf-8'))
        except:
            self.user_objectclasses = [b'top', b'inetOrgPerson']
        self.user_account_locked_attr = settings.user_account_locked_attr
        self.user_change_password_attr = settings.user_change_password_attr
        self.user_mobile_attr = settings.user_mobile_attr
        self.user_email_attr = settings.user_email_attr
        self.user_groups_attr = settings.user_groups_attr
        # Group related settings
        try:
            self.group_dn = settings.group_dn
        except:
            self.group_dn = ""

        self.group_scope = settings.group_scope
        if not self.group_scope:
            self.group_scope = 2  # Subtree by default
        try:
            self.group_objectclasses = list()
            for object_class in settings.group_objectclasses:
                self.group_objectclasses.append(bytes(object_class, 'utf-8'))
        except:
            self.group_objectclasses = [b'top', b'groupOfNames']

        try:
            self.group_filter = settings.group_filter
        except:
            self.group_filter = ""
        self.group_attr = settings.group_attr
        self.group_member_attr = settings.group_member_attr
        if not self.group_member_attr:
            self.group_member_attr = "member"

        self.attributes_list = [self.user_attr]
        if self.user_mobile_attr:
            self.attributes_list.append(str(self.user_mobile_attr))
        if self.user_email_attr:
            self.attributes_list.append(str(self.user_email_attr))
        self.scope = None

        proto = 'ldap'
        self.start_tls = False
        if settings.encryption_scheme == 'start-tls':
            self.start_tls = True
            self._connection_settings[ldap.OPT_X_TLS_CACERTDIR] = '/var/db/pki'
            self._connection_settings[ldap.OPT_X_TLS_REQUIRE_CERT] = ldap.OPT_X_TLS_NEVER
            self._connection_settings[ldap.OPT_X_TLS_NEWCTX] = 0
            self._connection_settings[ldap.OPT_DEBUG_LEVEL] = 255

        elif settings.encryption_scheme == 'ldaps':
            proto = 'ldaps'
            self._connection_settings[ldap.OPT_X_TLS_CACERTDIR] = '/var/db/pki'
            self._connection_settings[ldap.OPT_X_TLS_REQUIRE_CERT] = ldap.OPT_X_TLS_NEVER
            self._connection_settings[ldap.OPT_X_TLS_NEWCTX] = 0
            self._connection_settings[ldap.OPT_DEBUG_LEVEL] = 255

        if self.host.find(':') != -1:
            self.host = '[' + self.host + ']'

        self.ldap_uri = "{}://{}:{}".format(proto, self.host, self.port)
        self._ldap_connection = None

    def _format_ldap_exception(self, exception):
        if len(exception.args) > 0:
            if 'desc' in exception.args[0] and 'info' in exception.args[0]:
                return f"{exception.args[0]['desc']}: {exception.args[0]['info']}"
            elif 'desc' in exception.args[0]:
                return str(exception.args[0]['desc'])
            elif 'info' in exception.args[0]:
                return str(exception.args[0]['info'])
        return "LDAP Error: Unknown Error"

    def get_user_attributes_list(self):
        res = [self.user_attr]
        if self.user_account_locked_attr:
            res.append(self.user_account_locked_attr)
        if self.user_change_password_attr:
            res.append(self.user_change_password_attr)
        if self.user_mobile_attr:
            res.append(self.user_mobile_attr)
        if self.user_email_attr:
            res.append(self.user_email_attr)
        if self.user_groups_attr:
            res.append(self.user_groups_attr)
        if self.user_mobile_attr:
            res.append(self.user_mobile_attr)
        if self.user_email_attr:
            res.append(self.user_email_attr)
        return res


    def _get_connection(self):
        """ Internal method used to initialize/retrieve LDAP connection

        :return: LDAPObject object
        """

        if self._ldap_connection is None:
            self._ldap_connection = ldap.initialize(self.ldap_uri)
            for opt, value in self._connection_settings.items():
                self._ldap_connection.set_option(opt, value)
            # Start-TLS support
            if self.start_tls:
                logger.info("Starting Start-TLS connection")
                self._ldap_connection.start_tls_s()

        return self._ldap_connection


    def _bind_connection(self, bind_username, bind_password):
        """ Try a bind operation over LDAP connection

        :param bind_username: String with username
        :param bind_password: String with password
        :return:Nothing
        """
        logger.debug("Trying to bind connection for username {}".format(bind_username))
        self._get_connection().simple_bind_s(bind_username, bind_password)


    def unbind_connection(self):
        if self._ldap_connection:
            self._ldap_connection.unbind_s()
            self._ldap_connection = None

    # def _schema(self):
    #     self._bind_connection(self.user, self.password)

    #     res = self._get_connection().search_s("cn=subschema", ldap.SCOPE_BASE, "(objectclass=*)", ["*", "+"])
    #     subschema_entry = res[0]
    #     subschema_subentry = ldap.cidict.cidict(subschema_entry[1])
    #     subschema = ldap.schema.SubSchema(subschema_subentry)
    #     object_class_oids = subschema.listall(ldap.schema.models.ObjectClass)
    #     tmp_object_classes = [
    #         subschema.get_obj(ldap.schema.models.ObjectClass, oid) for oid in object_class_oids
    #     ]

    #     object_classes = {}
    #     for elem in tmp_object_classes:
    #         object_classes[elem.names[0]] = elem

    #     tmp_schema = {}
    #     for name, classe in object_classes.items():
    #         tmp_schema[name] = {
    #             "must": list(classe.must),
    #             "may": list(classe.may)
    #         }

    #         parents = classe.sup
    #         while len(parents) > 0:
    #             for parent in parents:
    #                 try:
    #                     parent_schema = object_classes[parent]
    #                     tmp_schema[name]['must'].extend(parent_schema.must)
    #                     tmp_schema[name]['may'].extend(parent_schema.may)
    #                 except KeyError:
    #                     parents = []
    #                     break

    #                 parents = parent_schema.sup

    #     schema = {}
    #     for key, values in tmp_schema.items():
    #         schema[key] = {
    #             "must": sorted(list(set(values['must']))),
    #             "may": sorted(list(set(values['may']))),
    #         }

    #     self.unbind_connection()
    #     return schema

    def _search(self, dn, ldap_query, username, attr_list=None):
        """ Private method used to perform a search operation over LDAP

        :param ldap_query: String with LDAP query filter
        :param username: String with username
        :return: An list with results if query match, None otherwise
        """
        # Defining searched attributes
        attributes_list = attr_list or self.attributes_list
        # Bind with svc account and look for provided username
        self._bind_connection(self.user, self.password)
        logger.debug("Searching for email/username/groups {}".format(username))
        logger.info("LDAP filter: basedn: {}, scope: {}, searchdn: {}, "
                     "attributes: {}".format(dn, self.user_scope, ldap_query,
                                             attributes_list))
        # Create pagination control
        page_control = ldap.controls.SimplePagedResultsControl(True, size=100, cookie='')
        result = []
        while True:
            # Make query with server control pagination
            msgid = self._get_connection().search_ext(dn, self.scope,
                                                     ldap_query,
                                                     attributes_list,
                                                     serverctrls=[page_control])
            try:
                rtype, rdata, rmsgid, serverctrls = self._get_connection().result3(msgid)
            except ldap.SIZELIMIT_EXCEEDED as e:
                raise LDAPSizeLimitExceeded(len(result), result)
            result.extend(rdata)
            controls = [control for control in serverctrls
                        if control.controlType == ldap.controls.SimplePagedResultsControl.controlType]
            if not controls:
                logger.error('The server ignores RFC 2696 control, quitting query.')
                break
            if not controls[0].cookie:
                break
            page_control.cookie = controls[0].cookie
        logger.debug("LDAP search_s result is: {}".format(result))
        return self._process_results(result)

    def _search_oauth2(self, username):
        """ Private method used to perform a search operation over LDAP

        :param ldap_query: String with LDAP query filter
        :param username: String with username
        :return: An list with results if query match, None otherwise
        """
        # input sanitation
        username = escape_filter_chars(username)
        base_dn = self._get_user_dn()
        # Defining user search filter
        query_filter = "({}={})".format(self.user_attr, username)
        if self.user_filter:
            query_filter = "(&{}{})".format(query_filter, self.user_filter)
        # Bind with svc account and look for provided username
        self._bind_connection(self.user, self.password)
        logger.debug("Searching for email/username/groups {}".format(username))
        logger.debug("LDAP filter: basedn: {}, scope: {}, searchdn: {}, attributes: {}".
                     format(base_dn, self.user_scope, query_filter, self.oauth2_attributes))
        oauth2_attributes = list()
        for attr in self.oauth2_attributes:
            oauth2_attributes.append(str(attr))
        result = self._get_connection().search_s(base_dn, self.scope, query_filter, oauth2_attributes)
        result = self._process_results(result)
        logger.debug("LDAP oauth2 search_s result is: {}".format(result))
        if len(result) > 0:
            return result
        else:
            return None

    def search_by_dn(self, dn, attr_list=None):
        self._bind_connection(self.user, self.password)
        try:
            result = self._get_connection().search_s(dn, ldap.SCOPE_SUBTREE, '(objectClass=*)', attr_list)
            dn, attrs = (result[0][0], self._process_results(result[0][1]))
        except ldap.NO_SUCH_OBJECT:
            dn, attrs = (None, None)

        self.unbind_connection()
        return dn, attrs

    def search_user(self, username, attr_list=None):
        """ Method used to search for a user inside LDAP repository

        :param username: String with username
        :return: An list with results if query match, None otherwise
        """
        # input sanitation
        username = escape_dn_chars(username)
        logger.debug(f"Searching for user {username} and getting attributes {attr_list}")
        # Defining user search filter
        query_filter = "({}={})".format(self.user_attr, username)
        if self.user_filter:
            query_filter = "(&{}{})".format(query_filter, self.user_filter)
        dn = self._get_user_dn()
        self.scope = self.user_scope
        return self._search(dn, query_filter, username, attr_list=attr_list)

    def enumerate_users(self):
        lst=list()
        lst.append(self.user_dn)
        lst.append(self.base_dn)
        res = self.search_user("*")
        if res:
            for result in res:
                lst.append(result[0])
        return lst

    def enumerate_groups(self):
        lst=list()
        lst.append(self.group_dn)
        lst.append(self.base_dn)
        res = self._search_group("*")
        if res:
            for result in res:
                lst.append(result[0])
        return lst


    def search_user_by_email(self, email):
        """ Method used to search for a user inside LDAP repository

        :param email: String with email address
        :return: An list with results if query match, None otherwise
        """
        # input sanitation
        email = escape_filter_chars(email)
        logger.debug(f"Searching user with email {email}")
        # Defining user search filter
        query_filter = "({}={})".format(self.user_email_attr, email)
        if self.user_filter:
            query_filter = "(&{}{})".format(query_filter, self.user_filter)
        dn = self._get_user_dn()
        self.scope = self.user_scope

        brut_result = self._search(dn, query_filter, email)
        if not brut_result:
            raise UserNotFound("User not found in database for email '{}'".format(email))

        return self._format_user_results(brut_result[0][0], brut_result[0][1])


    def search_user_by_username(self, username):
        """ Method used to search for a user inside LDAP repository

        :param email: String with username
        :return: The first user matching query if at least one is found, None otherwise
        """
        found_users = self.search_user(username)
        if not found_users:
            raise UserNotFound(f"User not found in database for username '{username}'")
        return self._format_user_results(found_users[0][0], found_users[0][1])


    def update_password(self, username, old_password, cleartext_password, **kwargs):
        """ Update a user password inside LDAP Repo

        :param username: String with username
        :param cleartext_password: String with cleartext password
        :return: True if Success, False otherwise
        """

        logger.info("Updating password for username {}".format(username))

        """ First search for user """
        found = self.search_user(username)
        if found:
            cn = found[0][0]
            self._bind_connection(self.user, self.password)
            try:
                old_password=None
                result = self._get_connection().passwd_s(cn, old_password, cleartext_password)
                if result == (None, None):
                    return result

                result = self._process_results(result)
                logger.debug("LDAP passwd_s result is: {}".format(result))
            except ldap.LDAPError as e:
                logger.error(f"LDAP passwd_s error: {e}")
                raise ChangePasswordError(self._format_ldap_exception(e))
            except Exception as e:
                logger.exception(e)
                raise ChangePasswordError("LDAPClient: an unknown error occured")

            if len(result):
                return result

        raise ChangePasswordError("Cannot find user '{}'".format(username))


    def _search_group(self, groupname, attr_list=None):
        """ Method used to search a group inside LDAP repository

        :param groupname: String with groupname
        :return: An list with results if query match, None otherwise
        """
        logger.debug(f"Searching group {groupname} and getting attributes {attr_list}")
        # Defining group search filter
        query_filter = "({}={})".format(self.group_attr, groupname)
        if self.group_filter:
            query_filter = "(&{}{})".format(query_filter, self.group_filter)
        dn = self._get_group_dn()
        self.scope = self.group_scope
        group_member_attr = str(self.group_member_attr.lower())
        self.attributes_list.append(group_member_attr)
        results = self._search(dn, query_filter, groupname, attr_list=attr_list)
        self.attributes_list.remove(group_member_attr)
        return results


    def search_group(self, groupname, attr_list=None):
        # input sanitation
        groupname = escape_filter_chars(groupname)
        return self._search_group(groupname, attr_list)


    def search_user_groups(self, username):
        """ Method used to retrieve user's group

        :param username: String with username
        :return: List of Distinguished Name (DN) group's user
        """

        if not self.user_groups_attr:
            return 'N/A'
        group_list = list()
        user_groups_attr = str(self.user_groups_attr.lower())
        group_membership_attr=str(self.group_member_attr.lower())

        logger.debug("Looking for {}'s groups".format(username.encode('utf-8')))

        """ Search "memberOf style" groups inside the given user entry """
        self.attributes_list.append(user_groups_attr)
        user_info = self.search_user(username)
        self.attributes_list.remove(user_groups_attr)

        if user_info:
            userdn=user_info[0][0]
            group_list = user_info[0][1].get(user_groups_attr)
            #This can return None
            if not group_list:
                group_list=list()
        else:
            raise UserNotFound("User {} not found in {}".format(username, self.user_scope))

        logger.debug("{}'s groups are: {}".format(username.encode('utf-8'), group_list))

        """ Search "member style" membership of the given user user inside groups entries """
        self.attributes_list.append(group_membership_attr)
        for group_info in self._search_group("*"):
            group_dn=group_info[0]
            members=group_info[1].get(self.group_member_attr.lower())
            if members:
                for member in members:
                    if member == userdn and group_dn not in group_list:
                        group_list.append(group_dn)
        self.attributes_list.remove(group_membership_attr)

        return group_list

    def search_user_groups_by_dn(self, dn):
        if not self.group_member_attr:
            return []
        group_membership_attr = str(self.group_member_attr.lower())
        self.attributes_list.append(group_membership_attr)
        group_list = []
        for group_info in self._search_group("*"):
            group_dn=group_info[0]
            members=group_info[1].get(self.group_member_attr.lower())
            if members:
                for member in members:
                    if member==dn and group_dn not in group_list:
                        group_list.append(group_dn)
        self.attributes_list.remove(group_membership_attr)
        return group_list

    def _get_user_dn(self):
        """ Return search DN of User. DN of user is a concatenation of Base DN
         and user DN

        :return: String with DN
        """
        dn = ""
        if self.base_dn and self.user_dn:
            dn = "{},{}".format(self.user_dn, self.base_dn)
        elif self.base_dn:
            dn = self.base_dn
        elif self.user_dn:
            dn = self.user_dn
        return dn

    def _get_group_dn(self):
        """ Return search DN of Group. DN of group is a concatenation of Base DN
         and group DN

        :return: String with DN
        """
        dn = ''
        if self.base_dn and self.group_dn:
            dn = "{},{}".format(self.group_dn, self.base_dn)
        elif self.base_dn:
            dn = self.base_dn
        elif self.user_dn:
            dn = self.group_dn
        return dn

    def is_user_account_locked(self, user_dn):
        """Method used to check if a user account is locked

        :param user_dn: String with username
        :return:True if account is locked, False otherwise
        """

        if not self.user_account_locked_attr:
            return False
        logger.debug("Looking if account {} is locked".format(user_dn))
        # query_filter = "(dn={})".format(username)
        # if self.user_filter:
        #     query_filter = "(&{}{}{})".format(query_filter, self.user_filter,
        #                                       self.user_account_locked_attr)
        # dn = self._get_user_dn()
        # self.scope = self.user_scope
        # logger.info(query_filter)
        result = self._search(user_dn, self.user_account_locked_attr, user_dn)
        if result:
            logger.info("{} account is locked".format(user_dn))
            return True
        else:
            logger.info("{} account is not locked".format(user_dn))
            return False

    def is_password_expired(self, user_dn):
        """ Method used to search if a user account need to change its password

        :param username: String with username
        :return: True if user account need to change its password, False otherwise
        """

        if not self.user_change_password_attr:
            return False
        logger.debug("Looking if account {} needs to change its password"
                    .format(user_dn))
        # query_filter = "({}={})".format(self.user_attr, username)
        # if self.user_filter:
        #     query_filter = "(&{}{}{})".format(query_filter, self.user_filter,
        #                                       self.user_change_password_attr)
        # dn = self._get_user_dn()
        # self.scope = self.user_scope
        result = self._search(user_dn, self.user_change_password_attr, user_dn)
        if result:
            logger.info("{} account need to change its password"
                        "".format(user_dn))
            return True
        else:
            logger.info("{} account doesn't need to change its password"
                        "".format(user_dn))
            return False


    def authenticate(self, username, password, **kwargs):
        """Authentication method of LDAP repository, which returns dict of specified attributes:their values
        :param username: String with username
        :param password: String with password
        :param oauth2_attributes: List of attributes to retrieve
        :return:
        """
        return_status = kwargs.get('return_status', False)
        logger.debug("Trying to authenticate username {}".format(username))
        # Prevent bind with empty password. As wrote in RFC 4511 LDAP server
        # won't raise an error message at bind
        if len(password) == 0:
            raise AuthenticationError("Empty password is not allowed")
        # Looking for user DN, if found we can try a bind
        found = self.search_user(username, attr_list=["+", "*"])

        if found is not None and len(found) > 0:
            dn = found[0][0]
            logger.debug("User {} was found in LDAP, its DN is: {}"
                        .format(username.encode('utf-8'), dn))
            self._bind_connection(dn, password)
            # Auth check
            if type(self._ldap_connection.whoami_s()) is None:
                raise AuthenticationError("LDAP bind failed for username {}".format(username))
            else:
                logger.debug("Successful bind for username {}".format(username))
                if return_status is True:
                    return True

                result = self._format_user_results(dn, found[0][1])
                return result
        else:
            logger.error("Unable to find username {} in LDAP repository"
                         "".format(username.encode('utf-8')))
            raise UserNotFound("Unable to find {}".format(username))


    def user_lookup_enrichment(self, ldap_attr, value):
        """  """
        # input sanitation
        value = escape_filter_chars(value)
        # Defining user search filter
        query_filter = "({}={})".format(ldap_attr, value)
        if self.user_filter:
            query_filter = "(&{}{})".format(query_filter, self.user_filter)
        dn = self._get_user_dn()
        self.scope = self.user_scope
        logger.debug(f"Lookup on dn {dn} using query filter {query_filter} and value {value}")
        # Search LDAP_ALL_USER_ATTRIBUTES & LDAP_ALL_OPERATIONAL_ATTRIBUTES
        user_infos = self._search(dn, query_filter, value, attr_list=["+", "*"])
        if not user_infos:
            logger.error("Ldap_client::user_lookup:User with {} in {} not found in LDAP".format(query_filter, self.scope))
            raise UserNotFound("Unable to find user {}".format(value))
        if len(user_infos) > 1:
            logger.warning("Ldap_client::user_lookup: Found multiple users with {} in {} - Getting the first".format(query_filter, self.scope))
        user_dn = user_infos[0][0]
        user_attrs = self._format_user_results(user_dn, user_infos[0][1])
        return user_attrs

    def _format_user_results(self, user_dn, user_attrs):
        res = {}
        user_groups = []
        user_attrs = _DeepStringCoder("utf-8").decode(user_attrs)
        # Standardize attributes
        for key, val in user_attrs.items():
            if key == "userPassword":
                continue
            elif key == self.user_groups_attr:
                user_groups = val
                # Groups MUST be a list - do not convert to str if len == 1
                continue
            if isinstance(val, list) and len(val) == 1:
                val = val[0]
            if isinstance(val, bytes):
                val = val.hex()
            res[key] = val
            # Add user_email and user_phone keys for OTP + SSO compatibility
            if key == self.user_mobile_attr:
                res['user_phone'] = val
            elif key == self.user_email_attr:
                res['user_email'] = val
        # Retrieve username with user_attr
        username = res.get(self.user_attr)
        if not username:
            raise UserNotFound("Cannot retrieve {} for user {}".format(self.user_attr, user_dn))
        res['name'] = username
        res['dn'] = user_dn
        res['account_locked'] = self.is_user_account_locked(user_dn)
        res['password_expired'] = self.is_password_expired(user_dn)
        user_groups = [*user_groups, *self.search_user_groups_by_dn(user_dn)]
        res['user_groups'] = user_groups
        if self.user_groups_attr:
            res[self.user_groups_attr] = user_groups
        return res

    def _process_results(self, results):
        """
        Returns a sanitized copy of raw LDAP results. This scrubs out
        references, decodes utf8, etc.
        :param results: result to parse
        """
        results = _DeepStringCoder('utf-8').decode(results)
        return results

    def test_ldap_connection(self):
        """ Method used to test LDAP connectivity. In order to test it, LDAP
         connection is initialized then a bind with service account is done
        """
        response = {
            'status': None,
            'reason': None
        }
        try:
            self._bind_connection(self.user, self.password)
            response['status'] = True
        except ldap.LDAPError as e:
            logger.error(e)
            response['status'] = False
            response['reason'] = self._format_ldap_exception(e)
        except Exception as e:
            logger.error(e)
            response['status'] = False
            response['reason'] = "An unknown error occurred"
        return response

    def test_user_connection(self, username, password):
        """ Method used to perform test search over LDAP Repository
        :param username: String with username
        :param password: String with password
        """
        response = dict()
        try:
            response = self.authenticate(username, password)
            response['status'] = True

        except UserNotFound as e:
            response['status'] = False
            response['reason'] = "User doesn't exist"
        except ldap.INVALID_CREDENTIALS as e:
            logger.error(f"LDAPClient::test_user_connection: Invalid credentials for {username}")
            logger.debug(f"credentials are: '{username}' and '{password}'")
            response['status'] = False
            response['reason'] = self._format_ldap_exception(e)
        except ldap.LDAPError as e:
            logger.error(str(e))
            response['status'] = False
            response['reason'] = self._format_ldap_exception(e)
        except Exception as e:
            logger.exception(e)
            response['status'] = False
            response['reason'] = "An unknown error occurred"

        return response

    def test_group_search(self, group_name):
        response = {
            'status': None,
            'reason': None,
            'groups': []
        }
        try:
            group_info = self.search_group(group_name)
            if group_info:
                for group in group_info:
                    group_members = group[1].get(self.group_member_attr.lower(), [])
                    if len(group_members) > 0:
                        group_members = [m.decode('utf-8') if isinstance(m, bytes) else m for m in group_members]
                    response['groups'].append({
                        'group_dn': group[0],
                        'group_members': group_members
                    })
            response['status'] = True
        except ldap.LDAPError as e:
            logger.error(e)
            response['status'] = False
            response['reason'] = self._format_ldap_exception(e)
        except Exception as e:
            logger.exception(e)
            response['status'] = False
            response['reason'] = "An unknown error has occurred"
        return response

    def add_new_user(self, username, password, email, phone, group, update_group):
        self._bind_connection(self.user, self.password)

        # Concatenate username with group ou and cn
        dn = "cn="+str(username)
        for g in group.split(',')[1:]:
            dn += ","+str(g)

        attrs = {
            'objectClass': self.user_objectclasses,
            'sn': [bytes(username, "utf-8")],
            self.user_attr: [bytes(username, "utf-8")],
            'userPassword' : [bytes(password, "utf-8")],
            'description' : [b"User automatically registrered by Vulture"]
        }

        if self.user_groups_attr:
            attrs[self.user_groups_attr] = [bytes(group, "utf-8")]
        if self.user_mobile_attr:
            attrs[self.user_mobile_attr] = [bytes(phone, "utf-8")]
        if self.user_email_attr:
            attrs[self.user_email_attr] = [bytes(email, "utf-8")]

        # Convert our dict to nice syntax for the add-function using modlist-module
        ldif = modlist.addModlist(attrs)

        logger.debug("LDAP::add_new_user: Adding new user '{}' in ldap database".format(dn))
        # Do the actual synchronous add-operation to the ldapserver
        self._get_connection().add_s(dn, ldif)
        logger.info("LDAP::add_new_user: User '{}' successfully added in ldap database".format(dn))

        if update_group and self.group_member_attr:
            attrs = [(ldap.MOD_ADD, self.group_member_attr, dn)]
            logger.debug("LDAP::add_new_user: Adding user '{}' to group '{}'".format(dn, group))
            self._get_connection().modify_s(group, attrs)
            logger.info("LDAP::add_new_user: User '{}' successfully added to group '{}'".format(dn, group))

        # Its nice to the server to disconnect and free resources when done
        self.unbind_connection()

    def add_group(self, dn, attrs):
        logger.info(f"LDAPClient::add_group: adding group {dn} with attributes {attrs}")
        self._bind_connection(self.user, self.password)

        for k, v in attrs.items():
            attrs[k] = list()
            if not isinstance(v, list):
                v = [v]
            for d in v:
                if not isinstance(d, bytes):
                    attrs[k].append(bytes(d, 'utf-8'))
                else:
                    attrs[k].append(d)

        ldif = modlist.addModlist(attrs)
        self._get_connection().add_s(dn, ldif)
        self.unbind_connection()

    def add_user(self, dn, attributes, userPassword, group_dn):
        def add_to_group():
            attrs = [(ldap.MOD_ADD, self.group_member_attr, bytes(dn, "utf-8"))]
            logger.info("LDAP::add_user: Adding user '{}' to group '{}'".format(dn, group_dn))
            try:
                self._get_connection().modify_s(group_dn, attrs)
            except ldap.TYPE_OR_VALUE_EXISTS:
                logger.warning(f"LDAP::add_user: user already in group")
                pass
            except (ldap.UNDEFINED_TYPE, ldap.NO_SUCH_OBJECT):
                # Group does not exist. Creating it
                self.add_group(group_dn, {
                    "member": [dn],
                    "objectClass": self.group_objectclasses
                })

        self._bind_connection(self.user, self.password)

        for k, v in attributes.items():
            if not isinstance(v, list):
                v = [v]

            attributes[k] = [bytes(d, "utf-8") for d in v]

        ldif = modlist.addModlist(attributes)
        try:
            self._get_connection().add_s(dn, ldif)
        except (ldap.ALREADY_EXISTS, ldap.TYPE_OR_VALUE_EXISTS):
            # Nothing to do here
            pass

        if group_dn:
            logger.info(f"Adding user {dn} in group {group_dn}")
            add_to_group()

        if userPassword:
            self._get_connection().passwd_s(dn, None, userPassword)

        self.unbind_connection()

    def update_user(self, dn, old_attributes, new_attributes, userPassword):
        self._bind_connection(self.user, self.password)

        # Convert values to bytes
        for k, v in old_attributes.items():
            old_attributes[k] = [bytes(d, "utf-8") for d in v]

        for k, v in new_attributes.items():
            new_attributes[k] = [bytes(d, "utf-8") for d in v]

        ldif = modlist.modifyModlist(old_attributes, new_attributes)
        self._get_connection().modify_s(dn, ldif)

        if userPassword:
            self._get_connection().passwd_s(dn, None, userPassword)

        self.unbind_connection()

    def delete_user(self, dn, groups=[]):
        self._bind_connection(self.user, self.password)

        for group in groups:
            group_dn = group['dn']
            del group['dn']
            old_group = copy.deepcopy(group)
            group[self.group_member_attr].remove(dn)

            final_group = {}
            for k, v in group.items():
                final_group[k] = [bytes(e, 'utf-8') for e in v]

            if len(group[self.group_member_attr]) == 0:
                # Group is empty, we can delete it
                self._get_connection().delete_s(group_dn)
            else:
                ldif = modlist.modifyModlist(old_group, final_group)
                self._get_connection().modify_s(group_dn, ldif)

        self._get_connection().delete_s(dn)
        self.unbind_connection()

class _DeepStringCoder(object):
    """
    Encodes and decodes strings in a nested structure of lists, tuples, and
    dicts. This is helpful when interacting with the Unicode-unaware
    python-ldap.
    """
    def __init__(self, encoding):
        self.encoding = encoding

    def decode(self, value):
        try:
            if isinstance(value, bytes):
                value = value.decode(self.encoding)
            elif isinstance(value, list):
                value = self._decode_list(value)
            elif isinstance(value, tuple):
                value = tuple(self._decode_list(value))
            elif isinstance(value, dict):
                value = self._decode_dict(value)
        except UnicodeDecodeError:
            pass

        return value

    def _decode_list(self, value):
        return [self.decode(v) for v in value]

    def _decode_dict(self, value):
        # Attribute dictionaries should be case-insensitive. python-ldap
        # defines this, although for some reason, it doesn't appear to use it
        # for search results.
        decoded = ldap.cidict.cidict()

        for k, v in value.items():
            decoded[self.decode(k)] = self.decode(v)

        return decoded
