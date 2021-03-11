#!/usr/bin/python
#-*- coding: utf-8 -*-
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "3.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'System utils sso_forward'


# Django system imports
from django.conf                      import settings
from django.http                      import HttpResponse, HttpResponseRedirect

# Django project imports
from authentication.base_repository import BaseRepository
from authentication.learning_profiles.models import LearningProfile
from portal.system.sso_clients               import SSOClient
from views.responses                  import create_gzip_response
from toolkit.system.aes_utils import AESCipher
from system.pki.models import PROTOCOLS_TO_INT, CERT_PATH
from toolkit.http.utils import parse_html

# Required exceptions imports
from bson.errors                      import InvalidId
from .exceptions                       import CredentialsMissingError

# Extern modules imports
from base64                           import b64encode
from bs4                              import BeautifulSoup
from bson                             import ObjectId
from json                             import loads as json_loads
from re                               import search as re_search
from robobrowser.forms                import Form
from robobrowser.forms.fields         import BaseField
from ssl                              import SSLContext, CERT_REQUIRED, CERT_NONE

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('portal_authentication')


# Global variables
learning_field_html = {'learn':'text', 'learn_secret':'password'}




class SSOForward(object):
    def __init__(self, request, application, authentication, user_infos):
        self.ssl_context = None
        ssl_client_certificate = None
        if application.authentication.sso_forward_url[:5] == "https" and application.authentication.sso_forward_tls_proto:
            self.ssl_context = SSLContext()
            # Use setter instead of kwargs, kwargs does not work...
            self.ssl_context.minimum_version = PROTOCOLS_TO_INT[application.authentication.sso_forward_tls_proto]
            if application.authentication.sso_forward_tls_cert:
                self.ssl_context.verify_mode = CERT_REQUIRED
                ssl_client_certificate = CERT_PATH
            else:
                self.ssl_context.verify_mode = CERT_NONE

        self.sso_client   = SSOClient(application.authentication.sso_forward_user_agent or request.META.get('HTTP_USER_AGENT',None),
                                      application.backend.headers.filter(enabled=True, type="request",
                                                       action__in=['add-header', 'set-header']),
                                    request.META.get('HTTP_REFERER', None),
                                    ssl_client_certificate,
                                    self.ssl_context)
        self.application  = application
        self.credentials  = authentication.credentials
        self.backend_id   = authentication.backend_id
        self.oauth2_token = authentication.redis_portal_session.get_oauth2_token(authentication.authenticated_on_backend())
        #self.user_infos = authentication.redis_portal_session.get_user_infos(self.backend_id)
        self.user_infos = user_infos
        logger.debug("SSOFORWARD::_init_: Object successfully created")


    def retrieve_sso_profile(self, username, field):
        aes             = AESCipher(str(settings.SECRET_KEY)+str(self.application.id)+str(self.backend_id)+str(username)+str(field))
        encrypted_field = aes.key.encode('hex')
        sso             = LearningProfile.objects.filter(encrypted_name=encrypted_field, login=username).first()
        return sso


    def retrieve_sso_field(self, username, field):
        sso  = self.retrieve_sso_profile(username, field)
        data = sso.get_data(sso.encrypted_value, str(self.application.id), str(self.backend_id), str(username), str(field))
        return data


    def stock_sso_field(self, username, field, value):
        try:
            sso_profile = self.retrieve_sso_profile(username, field)
            if not sso_profile:
                raise Exception("Cannot retrieve sso profile")
        except Exception as e:
            logger.debug("Cannot retrieve sso profile '{}' for user '{}' : {}".format(field, username, e))
            try:
                sso_profile = LearningProfile()
                sso_profile.set_data(str(self.application.id), self.application.name, str(self.backend_id),
                                     BaseRepository.objects.get(pk=self.backend_id).name,
                                     str(username),
                                     str(field),
                                     str(value))
                sso_profile.store()
            except Exception as e:
                logger.error("SSOForward::stock_sso_field: Unable to store SSO Profile (field={},username={}) : {}".format(field, username, str(e)))


    def retrieve_credential(self, request, field_username, field_password, fw_type):
        if self.application.sso_forward_basic_mode == 'learning':
            learning_field_html = {field_username:'text', field_password:'password'}
            fields_to_learn, fields_to_stock, datas = dict(),dict(),dict()
            for field_name,field_html in learning_field_html.items():
                try:
                    field_value = request.POST[field_name]
                    datas[field_name], fields_to_stock[field_name] = field_value,field_value
                except Exception as e:
                    logger.debug("SSOForward{}::retrieve_credentials: Unable to retrieve field '{}' from POST data : {}".format(fw_type, field_name, str(e)))
                    try:
                        datas[field_name] = self.retrieve_sso_field(self.credentials[0], field_name)
                    except Exception as e:
                        logger.debug("SSOForward{}::retrieve_credentials: Unable to retrieve field '{}' from POST data : {}".format(fw_type, field_name, str(e)))
                if not datas.get(field_name, None):
                    fields_to_learn[field_name] = field_html

            if fields_to_learn:
                raise CredentialsMissingError("SSOForward{}::retrieve_credentials: Learning field(s) missing : {}".format(fw_type, fields_to_learn), fields_to_learn)

            return datas, fields_to_stock, self.application.get_redirect_uri()
        else:
            return {field_username:self.credentials[0], field_password:self.credentials[1]}, dict(), ""


    def generate_response(self, request, response, redirect_url):

        final_response = HttpResponseRedirect(redirect_url)
        final_response = self.sso_client.fill_response(response, final_response, self.application.get_redirect_uri())

        """ We want to immediately return the result of the SSO Forward POST Request """
        if self.application.authentication.sso_forward_return_post:
            final_response.status_code = response.status_code

            matched = None
            if self.application.authentication.sso_forward_enable_capture and self.application.authentication.sso_forward_capture_content:
                ##TODO: MAKE THE CAPTURE/REPLACE/ADDITIONNAL REQUEST 
                #  ON ALL THE RESPONSE (HEADERS INCLUDED !)
                # response_raw = ""
                # for key,item in response.headers:
                #     response_raw += str(key)+": "+str(item)+"\r\n"
                # response_raw += response.text

                matched = re_search(self.application.authentication.sso_forward_capture_content, response.content) # response_raw

            final_response_body = self.sso_client.advanced_sso_perform(matched, self.application, response)

            if "gzip" in final_response.get('Content-Encoding', ""):
                final_response = create_gzip_response(request, final_response_body)
                final_response = self.sso_client.fill_response(response, final_response, self.application.get_redirect_uri())
            else:
                final_response.content = final_response_body
            final_response['Content-Length'] = len(final_response.content)
            logger.debug("SSOForward::generate_response: sso_forward_return_post activated - final response generated")

        # elif response.status_code not in (301,302,303) or not self.application.authentication.sso_forward_follow_redirect:
        #     """ simply redirect to the default Application entry point """
        #     final_response.status_code = 302
        #     # redirect user to url redirected
        #     final_response['Location'] = asked_url
        #     del final_response['Content-Length']
        #     del final_response['Content-Encoding']
        #     logger.debug("SSOForward::generate_response: Generated response redirects to '{}'".format(asked_url))

        return final_response



class SSOForwardPOST(SSOForward):
    def __init__(self, request, application, authentication, user_infos):
        super(SSOForwardPOST, self).__init__(request, application, authentication, user_infos)
        self.credentials = authentication.credentials


    def get_autologon_user(self, **kwargs):
        return False, self.credentials[0]


    def get_autologon_password(self, **kwargs):
        return False, self.credentials[1]


    def get_oauth2_token(self, **kwargs):
        return False, self.oauth2_token


    def get_user_info(self, **kwargs):
        return False, self.user_infos.get(kwargs['sso_profile']['value'], "")


    def get_learn_and_secret(self, **kwargs):
        learning_name = kwargs['learning_name']
        for key, item in kwargs['request'].POST.items():
            if learning_name in key.split(';vlt;'):
                logger.debug("SSOForward::get_learn_and_secret: Learning field '{}' successfully retrieven in POST")
                return True, item
        try:
            profile_value = self.retrieve_sso_field(self.credentials[0], learning_name)
            if profile_value:
                logger.debug("SSOForward::get_learn_and_secret: Learning field '{}' successfully  retrieven in Mongo".format(profile_value))
                return False, profile_value
        except Exception as e:
            logger.info("SSOCLIENT::process_form: Cannot retrieve field '{}' from LearningProfile : asking-it with learning. Exception : {}".format(learning_name, str(e)))
        raise CredentialsMissingError("Cannot find learning field '{}' for username '{}'".format(learning_name, self.credentials[0]), {learning_name : learning_field_html[kwargs['control_type']]})


    def get_auto(self, **kwargs):
        return False, kwargs['control_values'][kwargs['profile_name']]


    def get_custom(self, **kwargs):
        return False, kwargs['sso_profile']['value']


    def retrieve_credentials(self, request):
        sso_profiles = json_loads(self.application.authentication.sso_forward_content)
        # Make a request
        logger.debug("SSOForwardPOST::authenticate: Trying to retrieve URL '{}'".format(self.application.authentication.sso_forward_url))

        control_ids, control_names, control_values = dict(), dict(), dict()

        if not self.application.authentication.sso_forward_direct_post:
            url, response = self.sso_client.get(self.application.authentication.sso_forward_url, True)
            logger.info("SSOForwardPOST::authenticate: Url '{}' successfully retrieven".format(self.application.authentication.sso_forward_url))
            # convert-it to robobrowser.forms.Form list
            forms = [i for i in parse_html(response.content, self.application.authentication.sso_forward_url) if str(i.method).upper() != 'GET']
            # retrieve id of form
            form_id = -1
            for sso_profile in sso_profiles:
                if sso_profile.get('type', 'None') == 'id':
                    form_id = int(sso_profile.get('value', '-1'))

            # Stock control names/ids/values in dicts
            # Convert controls in dict to access them more easily
            try:
                # Try to retrieve mechanize form with id
                for control_name, control in forms[form_id].fields.items():
                    if isinstance(control._parsed, list):
                        control_id = control._parsed[0].attrs.get('id', "")
                        control_value = control._parsed[0].attrs.get('value', "")
                    else:
                        control_id = control._parsed.attrs.get('id', "")
                        control_value = control._parsed.attrs.get('value', "")
                    if control_id:
                        control_names[control_id] = control_name
                    control_ids[control_name]     = str(control_id)
                    control_values[control_name]  = control_value
            except Exception as e:
                logger.error("SSOForwardPOST::retrieve_credentials: Cannot retrieve form with id '{}' on url '{}'".format(form_id, url))
                logger.exception(e)
                raise

        fields_to_learn, form_data, profiles_to_stock = dict(),dict(),dict()
        sso_profile_functions = {'autologon_user'    :self.get_autologon_user, 
                                'autologon_password' :self.get_autologon_password,
                                'oauth2_token'       :self.get_oauth2_token,
                                'learn'              :self.get_learn_and_secret,
                                'learn_secret'       :self.get_learn_and_secret,
                                'auto'               :self.get_auto,
                                'repo'               :self.get_user_info,
                                'custom'             :self.get_custom}

        # Fill POST form data if (name and value) of field are defined
        for name, value in control_values.items():
            if name and value:
                form_data[name] = value

        for sso_profile in [i for i in sso_profiles if i['name'] != 'id']:
            to_stock = False
            if sso_profile['send_type'] == 'cookie':
                try:
                    profile_name, learning_name = sso_profile['name'], sso_profile['name']
                    to_stock, profile_value = sso_profile_functions[sso_profile['type']](request=request, learning_name=learning_name,
                                                                                         profile_name=profile_name, sso_profile=sso_profile,
                                                                                         control_values=control_values, control_type=sso_profile['type'])
                    self.sso_client.add_cookies({profile_name: profile_value})
                    self.sso_client.banned_cookies.append(profile_name)
                except CredentialsMissingError as e:
                    fields_to_learn[e.fields_missing.keys()[0]] = e.fields_missing.values()[0]
            #elif sso_profile['type'] != 'auto':
            else:
                # Get the name & id of this profile
                try:
                    profile_name, profile_id = sso_profile['name'].split(';vlt;')
                except:
                    profile_name, profile_id = sso_profile['name'], ""
                logger.debug("SSOForwardPOST::authenticate: profile_name is '{}', profile id is '{}'".format(profile_name, profile_id))
                control_id = control_ids.get(profile_name, None)
                control_name = control_names.get(profile_id, None)
                # If name is variable, get the new name by id
                if not control_id and control_name:
                    profile_name = control_name
                    # control_id = profile_id
                    learning_name = profile_id
                else:
                    learning_name = profile_name
                try:
                    to_stock, profile_value = sso_profile_functions[sso_profile['type']](request=request, learning_name=learning_name,
                                                                                         profile_name=profile_name, sso_profile=sso_profile,
                                                                                         control_values=control_values, control_type=sso_profile['type'])
                    form_data[profile_name] = profile_value

                except CredentialsMissingError as e:

                    logger.info("SSOForwardPOST::authenticate: Field missing for SSO : '{}' , it will be asked with learning".format(e.fields_missing.keys()[0]))
                    fields_to_learn[e.fields_missing.keys()[0]] = e.fields_missing.values()[0]

                except KeyError as e:
                    logger.exception(e)
                    logger.info("SSOForwardPOST::authenticate: Field missing for SSO : '{}' , it will not be present in SSO request".format(e))

            if to_stock:
                profiles_to_stock[profile_name] = profile_value

        if fields_to_learn:
            raise CredentialsMissingError("SSOForwardPOST::retrieve_credentials: Learning field(s) missing : {}".format(fields_to_learn), fields_to_learn)

        return form_data, profiles_to_stock, forms[form_id].action if not self.application.authentication.sso_forward_direct_post else self.application.authentication.sso_forward_url


    def authenticate(self, post_datas, **kwargs):
        post_url = kwargs['post_url']
        url, response  = self.sso_client.post(post_url, self.application.authentication.sso_forward_content_type or "default", post_datas, self.application.authentication.sso_forward_follow_redirect)

        return response



class SSOForwardBASIC(SSOForward):
    def __init__(self, request, application, authentication):
        super(SSOForwardBASIC, self).__init__(request, application, authentication)


    def retrieve_credentials(self, request):
        return self.retrieve_credential(request, 'basic_username', 'basic_password', 'BASIC')


    def authenticate(self, credentials, **kwargs):
        if self.application.sso_forward_only_login:
            url = self.application.sso_forward_basic_url
        else:
            url = self.application.private_uri

        redis_session                = kwargs['redis_session']
        self.sso_client.session.auth = (credentials['basic_username'] , credentials['basic_password'])
        logger.debug("SSOForwardBASIC::authenticate: Header successfully created with credentials for user '{}'".format(credentials['basic_username']))
        url, response                = self.sso_client.get(url, self.application.sso_forward_follow_redirect)
        logger.debug("SSOForwardBASIC::authenticate: URL '{}' successfully gotten with Basic header for user '{}'".format(url, credentials['basic_username']))

        #### POSSIBILITY OF VERIFY CREDENTIALS => IF RESPONSE.STATUS_CODE == 401
        if not self.application.sso_forward_only_login:
            redis_session.setHeader("Authorization:Basic "+b64encode('%s:%s'%(credentials['basic_username'],credentials['basic_password'])).replace('\n', '')+"\r\n")
            logger.info("SSOForwardBASIC::authenticate: Basic infos successfully written in Redis session")

        return response



class SSOForwardKERBEROS(SSOForward):
    def __init__(self, request, application, authentication):
        super(SSOForwardKERBEROS, self).__init__(request, application, authentication)


    def retrieve_credentials(self, request):
        return self.retrieve_credential(request, 'kerberos_username', 'kerberos_password', 'KERBEROS')


    def authenticate(self, credentials, **kwargs):
        # Create header
        if self.application.sso_forward_only_login:
            url = self.application.sso_forward_basic_url
        else:
            url = self.application.private_uri

        redis_session = kwargs['redis_session']

        kerberos_repo = KerberosRepository.objects.with_id(ObjectId(self.backend_id))
        if not kerberos_repo:
            raise InvalidId("")

        kerberos_TGT  = kerberos_repo.get_backend().create_tgt(self.backend_id, credentials['kerberos_username'], credentials['kerberos_password'], "HTTP/"+self.application.app_krb_service)

        if kerberos_TGT:
            logger.debug("SSOForwardKRB5::authenticate: TGT successfully created with credentials for user '{}'".format(credentials['kerberos_username']))

            self.sso_client.session.headers.update({'Authorization':'Negotiate %s'%str(kerberos_TGT)})
            url, response = self.sso_client.get(url, self.application.sso_forward_follow_redirect)
            logger.info("SSOForwardKRB5::authenticate: URL '{}' successfully gotten with Kerberos TGT".format(url))

            #### POSSIBILITY OF VERIFY CREDENTIALS => IF RESPONSE.STATUS_CODE == 401
            if not self.application.sso_forward_only_login:
                redis_session.setKrb5Infos(credentials['kerberos_username'], self.application.app_krb_service, self.backend_id)
                logger.debug("SSOForwardKRB5::authenticate: Kerberos infos for user '{}' successfully written in Redis session".format(credentials['kerberos_username']))

        return response

