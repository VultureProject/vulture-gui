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
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Django view used to handle authentication and SSO'


# MONGO IMPORT REQUIRED
from sys import path
path.append("/home/vlt-os/vulture_os/portal")

# Django system imports
from django.conf                     import settings
from django.http                     import (HttpResponseRedirect, HttpResponseServerError, HttpResponseForbidden,
                                             JsonResponse, HttpResponse)
from django.utils import timezone

# Django project imports
from system.cluster.models           import Cluster
from portal.views.responses          import (response_redirect_with_portal_cookie, set_portal_cookie, split_domain)
from portal.system.authentications   import (Authentication, POSTAuthentication, BASICAuthentication,
                                             KERBEROSAuthentication, DOUBLEAuthentication)
from portal.system.sso_forwards      import SSOForwardPOST, SSOForwardBASIC, SSOForwardKERBEROS
from workflow.models import Workflow
from authentication.openid.models import OpenIDRepository
from authentication.user_portal.models import UserAuthentication
from portal.system.redis_sessions import REDISBase, REDISPortalSession, RedisOpenIDSession, REDISOauth2Session
from portal.views.responses import error_response

# Required exceptions imports
from bson.errors                     import InvalidId
from django.core.exceptions          import ValidationError
from django.utils.datastructures     import MultiValueDictKeyError
from ldap                            import LDAPError
from OpenSSL.SSL                     import Error as OpenSSLError
from pymongo.errors                  import PyMongoError
from redis                           import ConnectionError as RedisConnectionError, RedisError
from requests.exceptions             import ConnectionError as RequestsConnectionError
from sqlalchemy.exc                  import DBAPIError
from portal.system.exceptions        import (TokenNotFoundError, RedirectionNeededError, CredentialsMissingError,
                                             CredentialsError, REDISWriteError, TwoManyOTPAuthFailure, ACLError)
from toolkit.auth.exceptions import AuthenticationError, OTPError
from toolkit.system.hashes import random_sha256
from toolkit.http.utils import build_url_params
from oauthlib.oauth2 import OAuth2Error
from django.core.exceptions import ObjectDoesNotExist

from ast import literal_eval

# Extern modules imports
from requests_oauthlib import OAuth2Session
from base64 import b64decode

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('portal_authentication')


STATE_REDIS_KEY = "oauth_state"


def openid_configuration(request, portal_id):
    try:
        portal = UserAuthentication.objects.get(pk=portal_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden()

    # Build the callback url
    # Get scheme
    scheme = request.META['HTTP_X_FORWARDED_PROTO']
    # Asked FQDN (with or without port)
    fqdn = request.META['HTTP_HOST']

    issuer = "{}://{}".format(scheme, fqdn)

    return JsonResponse(portal.generate_openid_config(issuer))



def openid_start(request, workflow_id, repo_id):
    """ First, try to retrieve concerned objects """
    try:
        repo = OpenIDRepository.objects.get(pk=repo_id)
        workflow = Workflow.objects.get(pk=workflow_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected.")

    try:
        # Build the callback url
        # Get scheme
        scheme = request.META['HTTP_X_FORWARDED_PROTO']
        # Asked FQDN (with or without port if needed)
        fqdn = request.META['HTTP_HOST']
        w_path = workflow.public_dir
        callback_url = workflow.authentication.get_openid_callback_url(scheme, fqdn, w_path, repo.id_alea)

        oauth2_session = repo.get_oauth2_session(callback_url)
        authorization_url, state = repo.get_authorization_url(oauth2_session)

        global_config = Cluster.get_global_config()
        """ Retrieve token and cookies to instantiate Redis wrapper objects """
        # Retrieve cookies required for authentication
        portal_cookie_name = global_config.portal_cookie_name
        portal_cookie = request.COOKIES.get(portal_cookie_name) or random_sha256()
        # We must stock the state into Redis
        redis_portal_session = REDISPortalSession(REDISBase(), portal_cookie)
        redis_portal_session[STATE_REDIS_KEY] = state
        redis_portal_session.write_in_redis(workflow.authentication.auth_timeout)

        # Finally we redirect the user to authorization_url
        response = HttpResponseRedirect(authorization_url)
        # Needed for Safari and mobiles support
        response['Content-Length'] = 0
        response.set_cookie(portal_cookie_name, portal_cookie, domain=split_domain(fqdn), httponly=False, secure=scheme=="https")

        return response

    except Exception as e:
        logger.exception(e)
        return error_response(workflow.authentication, "An error occurred")


def openid_callback(request, workflow_id, repo_id):
    """
    """
    """ First, try to retrieve concerned objects """
    try:
        repo = OpenIDRepository.objects.get(pk=repo_id)
        workflow = Workflow.objects.get(pk=workflow_id)
        portal = workflow.authentication
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected.")

    # Build the callback url
    # Get scheme
    scheme = request.META['HTTP_X_FORWARDED_PROTO']
    fqdn = request.META['HTTP_HOST']
    w_path = workflow.public_dir
    callback_url = workflow.authentication.get_openid_callback_url(scheme, fqdn, w_path, repo.id_alea)

    redirect_url = scheme + "://" + fqdn + w_path

    global_config = Cluster.get_global_config()
    token_name = global_config.public_token
    """ Retrieve token and cookies to instantiate Redis wrapper objects """
    # Retrieve cookies required for authentication
    portal_cookie_name = global_config.portal_cookie_name

    try:
        code = request.GET['code']
        state = request.GET['state']
        # Cookie can be empty, it will be created in Authentication class
        portal_cookie = request.COOKIES.get(portal_cookie_name) or random_sha256()

        # Use POSTAuthentication to print errors with html templates
        authentication = Authentication(portal_cookie, workflow, scheme)
        # Set redirect url in redis
        authentication.set_redirect_url(redirect_url)

        # Get user session with cookie
        redis_portal_session = REDISPortalSession(REDISBase(), portal_cookie)
        assert state == redis_portal_session[STATE_REDIS_KEY]
        # If state is correct, remove-it in Redis to prevent re-use
        redis_portal_session.delete_key(STATE_REDIS_KEY)
        oauth2_session = repo.get_oauth2_session(callback_url)
        token = repo.fetch_token(oauth2_session, code)['access_token']
        # Save token in Redis for later use
        #redis_portal_session['oauth_token'] = token

        # Retrieve user's infos from provider
        claims = repo.get_userinfo(oauth2_session)
        logger.info(f"OpenID_callback::{portal}: Claims retrieved from {repo.userinfo_endpoint} for token {token} : {claims}")
        repo_attributes = {}
        # Make LDAP Lookup if configured
        if workflow.authentication.lookup_ldap_repo:
            ldap_attr = workflow.authentication.lookup_ldap_attr
            claim = claims.get(workflow.authentication.lookup_claim_attr)
            if not claim:
                logger.error("OpenID_callback: Cannot retrieve user claim '{}' from user claims '{}'".format(workflow.authentication.lookup_claim_attr, claims))
            else:
                ldap_connector = workflow.authentication.lookup_ldap_repo.get_client()
                # Enrich user claims with LDAP infos - merge dictionnaries
                repo_attributes = ldap_connector.user_lookup_enrichment(ldap_attr, claim)
                logger.info(f"OpenID_callback::{portal}: Repo attributes retrieved from "
                            f"{workflow.authentication.lookup_ldap_repo} for {ldap_attr}={claim} : {repo_attributes}")

        # Create user scope depending on GUI configuration attributes
        user_scope = workflow.authentication.get_user_scope(claims, repo_attributes)
        logger.info(f"OpenID_callback::{portal}: User scope created from claims(/repo) : {user_scope}")

        # Set authentication attributes required
        authentication.backend_id = repo_id
        authentication.credentials = [claims.get('name') or claims.get('sub'), ""]
        if not user_scope.get('name'):
            user_scope['name'] = claims.get('name') or claims.get('sub')
        authentication.register_user({**claims, **repo_attributes}, user_scope)

    except KeyError as e:
        logger.exception(e)
        return HttpResponseRedirect(redirect_url)

    except RedisConnectionError as e:
        logger.exception(e)
        return HttpResponseServerError()

    except AssertionError as e:
        logger.exception(e)
        return HttpResponseRedirect(redirect_url)

    except OAuth2Error as e:
        logger.exception(e)
        return HttpResponseRedirect(redirect_url)

    except Exception as e:
        logger.exception(e)
        return error_response(workflow.authentication, "An error occurred")

    response = authenticate(request, workflow, portal_cookie, token_name, double_auth_only=True, sso_forward=True, openid=False) \
               or authentication.generate_response()

    return set_portal_cookie(response, portal_cookie_name, portal_cookie, redirect_url)



def openid_authorize(request, portal_id):
    try:
        scheme = request.META['HTTP_X_FORWARDED_PROTO']
    except KeyError:
        logger.error("PORTAL::openid_authorize: could not get scheme from request")
        return HttpResponseServerError()

    try:
        portal = UserAuthentication.objects.get(pk=portal_id)
    except UserAuthentication.DoesNotExist:
        logger.error("PORTAL::openid_authorize: could not find a portal with id {}".format(portal_id))
        return HttpResponseServerError()
    except Exception as e:
        logger.error("PORTAL::openid_authorize: an unknown error occurred while searching for portal with id {}: {}".format(portal_id, e))
        return HttpResponseServerError()

    # Check mandatory URI parameters presence
    try:
        client_id = request.GET['client_id']
        redirect_uri = request.GET['redirect_uri']
        scope = request.GET['scope']
        response_type = request.GET['response_type']
    except KeyError as e:
        logger.exception(e)
        return error_response(portal, "Invalid parameter: {}.".format(e.args[0]))

    # Check parameters validity
    try:
        assert client_id == portal.oauth_client_id, "Client authentication failed due to unknown client."
        assert redirect_uri in portal.oauth_redirect_uris, "Invalid redirect URI."
        assert scope == "openid", "The requested scope is invalid."
        assert response_type == "code", "The requested response_type is invalid."
    except AssertionError as e:
        logger.exception(e)
        return error_response(portal, str(e))

    try:
        global_config = Cluster.get_global_config()

        """ Retrieve token and cookies to instantiate Redis wrapper objects """
        # Retrieve cookies required for authentication
        portal_cookie_name = global_config.portal_cookie_name
        token_name = global_config.public_token
        portal_cookie = request.COOKIES.get(portal_cookie_name) or random_sha256()
    except Exception as e:
        logger.error("PORTAL::log_in: an unknown error occurred while retrieving global config : {}".format(e))
        return HttpResponseServerError()

    # Prefix ID to prevent conflicts between portal.id and workflow.id
    workflow = Workflow(authentication=portal, fqdn=portal.external_fqdn, id=f"portal_{portal.id}", name=portal.name)

    # OpenID=True returns a response redirect with token
    response = authenticate(request, workflow, portal_cookie, token_name, sso_forward=False, openid=True)

    return set_portal_cookie(response, portal_cookie_name, portal_cookie, f"https://{portal.external_fqdn}")


def openid_token(request, portal_id):
    try:
        scheme = request.META['HTTP_X_FORWARDED_PROTO']
    except KeyError:
        logger.error("PORTAL::openid_authorize: could not get scheme from request")
        return HttpResponseServerError()

    try:
        portal = UserAuthentication.objects.get(pk=portal_id)
    except UserAuthentication.DoesNotExist:
        logger.error("PORTAL::openid_authorize: could not find a portal with id {}".format(portal_id))
        return HttpResponseServerError()
    except Exception as e:
        logger.error("PORTAL::openid_authorize: an unknown error occurred while searching for portal with id {}: {}".format(portal_id, e))
        return HttpResponseServerError()

    try:
        assert request.POST.get('grant_type') == "authorization_code", "The authorization grant type is not supported by the authorization server."
        assert request.POST.get('redirect_uri'), "Missing required parameter: redirect_uri."
        assert request.POST.get('code'), "Missing required parameter: code."
    except AssertionError as e:
        logger.exception(e)
        return JsonResponse({'error':"invalid_request", "error_description": str(e)},
                            status=400)

    # Check mandatory URI parameters presence
    try:
        client_id, client_secret = b64decode(request.headers.get("Authorization").replace("Basic ", "")).decode('utf8').split(':')
        assert client_id == portal.oauth_client_id
        assert client_secret == portal.oauth_client_secret
    except Exception as e:
        logger.exception(e)
        return JsonResponse({'error':"invalid_grant", "error_description": "Authorization error"},
                            status=400)

    try:
        session = RedisOpenIDSession(REDISBase(), f"token_{request.POST.get('code')}")
        assert session['client_id'] == client_id, "Invalid client_id."
        assert session['redirect_uri'] == request.POST.get('redirect_uri'), "Invalid redirect_uri."
        return JsonResponse({
            'access_token': session['access_token'],
            'token_type': "Bearer",
            'scope': ["openid"],
            'created_at': int(timezone.now().timestamp()),
        })
    except RedisError as e:
        return JsonResponse({"error": "internal_error", "error_description": "Session error"}, status=500)
    except AssertionError as e:
        logger.exception(e)
        return JsonResponse({'error':"invalid_request", "error_description": str(e)},
                            status=400)


def openid_userinfo(request, portal_id=None, workflow_id=None):
    try:
        scheme = request.META['HTTP_X_FORWARDED_PROTO']
    except KeyError:
        logger.error("PORTAL::openid_userinfo: could not get scheme from request")
        return HttpResponseServerError()

    try:
        if portal_id:
            assert UserAuthentication.objects.filter(pk=portal_id).exists()
            workflow_id = f"portal_{portal_id}"
        elif workflow_id:
            assert Workflow.objects.filter(pk=workflow_id).exists()
        assert workflow_id
    except (ObjectDoesNotExist, AssertionError):
        logger.error("PORTAL::openid_userinfo: could not find a portal with id {} or workflow with id {}".format(portal_id, workflow_id))
        return HttpResponseServerError()
    except Exception as e:
        logger.error("PORTAL::openid_userinfo: an unknown error occurred while searching for portal with id {}: {}".format(portal_id, e))
        return HttpResponseServerError()

    try:
        assert request.headers.get('Authorization')
        assert request.headers.get('Authorization').startswith("Bearer ")

        oauth2_token = request.headers.get('Authorization').replace("Bearer ", "")
        session = REDISOauth2Session(REDISBase(), f"oauth2_{oauth2_token}")

        assert session['workflow'] == workflow_id
        assert session['scope']
        return JsonResponse(literal_eval(session['scope']))
    except Exception as e:
        logger.exception(e)
        return HttpResponse(status=401)



def authenticate(request, workflow, portal_cookie, token_name, double_auth_only=False, sso_forward=True, openid=False):

    scheme = request.META['HTTP_X_FORWARDED_PROTO']

    if not double_auth_only:
        authentication_classes = {'form':POSTAuthentication, 'basic':BASICAuthentication, 'kerberos':KERBEROSAuthentication}

        try:
            # Instantiate authentication object to retrieve application auth_type
            authentication = Authentication(portal_cookie, workflow, scheme)
            # And then instantiate the right authentication class with auth_type ('form','basic','kerberos')
            authentication = authentication_classes[workflow.authentication.auth_type](portal_cookie, workflow, scheme,
                                                                                       redirect_url=request.GET.get(
                                                                                           "redirect_url"))
            logger.debug("PORTAL::log_in: Authentication successfully created")

        # Application does not need authentication
        except RedirectionNeededError as e:
            logger.error("PORTAL::log_in: {}".format(str(e)))
            return HttpResponseRedirect(e.redirect_url)

        # Redis connection error
        except RedisConnectionError as e:
            logger.error("PORTAL::log_in: Unable to connect to Redis server : {}".format(str(e)))
            return HttpResponseServerError()

        # Token not found while instantiating RedisSession or RedisAppSession
        except TokenNotFoundError as e:
            logger.error("PORTAL::log_in: {}".format(str(e)))

            # Redirect to the same uri, to stock token in Redis via session filter
            return HttpResponseRedirect("")

        # If redis_session.keys['application_id'] does not exists : FORBIDDEN
        except (Workflow.DoesNotExist, ValidationError, InvalidId) as e:
            logger.error("PORTAL::log_in: Application with id '{}' not found"
                         .format(authentication.redis_session.keys.get('application_id')))
            return HttpResponseForbidden()

        # If assertionError : Ask credentials by portal
        except AssertionError as e:
            logger.error("PORTAL::log_in: AssertionError while trying to create Authentication : ".format(e))
            return authentication.ask_credentials_response(request=request)


        """ If user is not authenticated : try to retrieve credentials and authenticate him on backend/fallback-backends """
        # If the user is not authenticated and application need authentication
        if not authentication.is_authenticated():
            try:
                backend_id = authentication.authenticate_sso_acls()
                if not backend_id:
                    # Retrieve credentials
                    authentication.retrieve_credentials(request)
                    logger.debug("PORTAL::log_in: Credentials successfully retrieved")

                    # Authenticate user with retrieved credentials
                    authentication_results = authentication.authenticate(request)
                    logger.debug("PORTAL::log_in: Authentication succeed on backend {}, "
                                 "user infos : {}".format(authentication.backend_id, authentication_results))
                    user_scope = workflow.authentication.get_user_scope({}, authentication_results)
                    # Register authentication results in Redis
                    portal_cookie, oauth2_token = authentication.register_user(authentication_results, user_scope)
                    logger.debug("PORTAL::log_in: User {} successfully registered in Redis".format(authentication.credentials[0]))

                    if authentication_results.get('password_expired', None):
                        logger.info("PORTAL::log_in: User '{}' must change its password, redirect to self-service portal"
                                    .format(authentication.credentials[0]))
                        app_url = workflow.get_redirect_uri()
                        return HttpResponseRedirect(str(token_name)+'/self/change')
                # If the user is already authenticated (retrieved with RedisPortalSession ) => SSO
                else:
                    portal_cookie, oauth2_token = authentication.register_sso(backend_id)
                    logger.info("PORTAL::log_in: User {} successfully SSO-powered ! "
                                "OAuth2 session = {}".format(authentication.credentials[0],
                                                             authentication.redis_oauth2_session.keys))

            except AssertionError as e:
                logger.error("PORTAL::log_in: Bad captcha taped for username '{}' : {}"
                             .format(authentication.credentials[0], e))
                return authentication.ask_credentials_response(request=request, error="Bad captcha")

            except AuthenticationError as e:
                logger.error("PORTAL::log_in: AuthenticationError while trying to authenticate user '{}' : {}"
                             .format(authentication.credentials[0], e))
                return authentication.ask_credentials_response(request=request, error="Bad credentials")

            except ACLError as e:
                logger.error("PORTAL::log_in: ACLError while trying to authenticate user '{}' : {}"
                             .format(authentication.credentials[0], e))
                return authentication.ask_credentials_response(request=request, error="Bad credentials")

            except (DBAPIError, PyMongoError, LDAPError) as e:
                logger.error("PORTAL::log_in: Repository driver Error while trying to authentication user '{}' : {}"
                             .format(authentication.credentials[0], e))
                return authentication.ask_credentials_response(request=request,
                                                               error="Bad credentials")

            except (MultiValueDictKeyError, AttributeError, KeyError) as e:
                # vltprtlsrnm is always empty during the initial redirection. Don't log that
                if str(e) != "vltprtlsrnm":
                    logger.error("PORTAL::log_in: Error while trying to authentication user '{}' : {}"
                                 .format(authentication.credentials[0], e))
                return authentication.ask_credentials_response(request=request)

            except REDISWriteError as e:
                logger.error("PORTAL::log_in: RedisWriteError while trying to register user '{}' informations : {}"
                             .format(authentication.credentials[0], e))
                return HttpResponseServerError()

            except Exception as e:
                logger.exception(e)
                return HttpResponseServerError()
    else:
        authentication = POSTAuthentication(portal_cookie, workflow, scheme)

    # If the user is authenticated but not double-authenticated and double-authentication required
    if authentication.double_authentication_required():
        logger.info("PORTAL::log_in: Double authentication required for user {}".format(authentication.credentials[0]))
        try:
            # Instantiate DOUBLEAuthentication object
            db_authentication = DOUBLEAuthentication(portal_cookie, workflow, scheme)
            logger.debug("PORTAL::log_in: DoubleAuthentication successfully created")
            # And try to retrieve credentials
            db_authentication.retrieve_credentials(request)
            logger.debug("PORTAL::log_in: DoubleAuthentication credentials successfully retrieved")
            # And use them to authenticate user
            db_authentication.authenticate(request)
            logger.info("PORTAL::log_in: User '{}' successfully double authenticated"
                        .format(authentication.credentials[0]))

        except AssertionError as e:
            """ If redis_portal_session does not exists or can't retrieve otp key in redis """
            logger.error("PORTAL::log_in: DoubleAuthentication failure for username '{}' : {}"
                         .format(authentication.credentials[0], str(e)))
            return authentication.ask_credentials_response(request=request,
                                                           error="Portal cookie expired")

        except (Workflow.DoesNotExist, ValidationError, InvalidId) as e:
            """ Invalid POST 'vulture_two_factors_authentication' value """
            logger.error("PORTAL::log_in: Double-authentication failure for username {} : {}"
                         .format(authentication.credentials[0], str(e)))
            return HttpResponseForbidden("Intrusion attempt blocked")

        except REDISWriteError as e:
            """ Cannot register double-authentication in Redis : internal server error """
            logger.error("PORTAL::log_in: Failed to write double-authentication results in Redis for username '{}' : {}"
                         .format(db_authentication.credentials[0], str(e)))
            return HttpResponseServerError()

        # If authentication failed : create double-authentication key and ask-it
        except CredentialsError as e:
            """ CredentialsError: no OTP credentials provided : ask-them """
            logger.error("PORTAL::log_in: Double-authentication failure for username {} : {}"
                         .format(authentication.credentials[0], str(e)))
            try:
                db_authentication.create_authentication()
                return db_authentication.ask_credentials_response(request=request)

            except (OTPError, REDISWriteError, RedisConnectionError) as e:
                """ Error while sending/registering in Redis the OTP informations : display portal"""
                logger.error("PORTAL::log_in: Failed to create/send double-authentication key : {}".format(str(e)))
                db_authentication.deauthenticate_user()
                logger.info("PORTAL::log_in: User '{}' successfully deauthenticated due to db-authentication error"
                            .format(authentication.credentials[0]))
                return authentication.ask_credentials_response(request=request,
                                                               error="<b> Error sending OTP Key </b> </br> "+str(e))
            except Exception as e:
                logger.exception(e)

        except AuthenticationError as e:
            """ Bad OTP key """
            logger.error("PORTAL::log_in: DoubleAuthentication failure for username {} : {}"
                         .format(authentication.credentials[0], str(e)))
            try:
                db_authentication.create_authentication()
                db_authentication.authentication_failure()
                logger.debug("PORTAL:log_in: DoubleAuthentication failure successfully registered in Redis")
                return db_authentication.ask_credentials_response(request=request,
                                                                  error="<b> Bad OTP key </b>")

            except TwoManyOTPAuthFailure as e:
                logger.error("PORTAL::log_in: Two many OTP authentication failures for username'{}', "
                             "redirecting to portal".format(authentication.credentials[0]))
                db_authentication.deauthenticate_user()
                logger.info("PORTAL::log_in: User '{}' successfully deauthenticated due to db-authentication error"
                            .format(authentication.credentials[0]))
                return authentication.ask_credentials_response(request=request, error=str(e))

            except (OTPError, REDISWriteError, RedisConnectionError) as e:
                logger.error("PORTAL::log_in: Error while preparing double-authentication : {}".format(str(e)))
                return db_authentication.ask_credentials_response(request=request,
                                                                  error="<b> Error sending OTP Key </b> </br> "+str(e))

        except OTPError as e:
            """ OTP Error while authenticating given token """
            logger.error("PORTAL::log_in: Double-authentication failure for username {} : {}"
                         .format(authentication.credentials[0], str(e)))
            return db_authentication.ask_credentials_response(request=request,
                                                              error="<b> OTP Error </b> {}".format(str(e)))

        except TwoManyOTPAuthFailure as e:
            logger.error("PORTAL::log_in: Two many OTP authentication failures for username'{}', "
                         "redirecting to portal".format(authentication.credentials[0]))
            db_authentication.deauthenticate_user()
            logger.info("PORTAL::log_in: User '{}' successfully deauthenticated due to db-authentication error"
                        .format(authentication.credentials[0]))
            return authentication.ask_credentials_response(request=request, error=e.message)

    if sso_forward:
        # If we arrive here : the user is authenticated
        #  and double-authenticated if double-authentication needed
        sso_methods = {
            'form': SSOForwardPOST,
            'basic': SSOForwardBASIC,
            'kerberos': SSOForwardKERBEROS
        }

        portal = workflow.authentication

        """ If SSOForward enabled : perform-it """
        if portal.enable_sso_forward:
            # Retrieve user_infos
            user_infos = authentication.get_user_infos(workflow.id)
            # Try to retrieve credentials from authentication object
            try:
                if not authentication.credentials[0] or not authentication.credentials[1]:
                    authentication.get_credentials(request)
                # If we cannot retrieve them, ask credentials
                assert authentication.credentials[0]  # or not authentication.credentials[1]:

                logger.info("PORTAL::log_in: Credentials successfuly retrieven for SSO performing")

            except Exception as e:
                logger.error("PORTAL::log_in: Error while retrieving credentials for SSO : ")
                logger.exception(e)
                return authentication.ask_credentials_response(request=request,
                                                               error="Credentials not found")

            try:
                # Instantiate SSOForward object with sso_forward type
                sso_forward = sso_methods[portal.sso_forward_type](request, workflow, authentication, user_infos)
                logger.info("PORTAL::log_in: SSOForward successfully created")
                # Get credentials needed for sso forward : AutoLogon or Learning
                sso_data, profiles_to_stock, url = sso_forward.retrieve_credentials(request)
                logger.info("PORTAL::log_in: SSOForward credentials successfully retrieven")
                # If credentials retrieven needs to be stocked
                for profile_name,profile_value in profiles_to_stock.items():
                    sso_forward.stock_sso_field(authentication.credentials[0], profile_name, profile_value)

                # Use 'sso_data' and 'url' to authenticate user on application
                response = sso_forward.authenticate(sso_data, post_url=url, redis_session=authentication.redis_portal_session)
                logger.info("PORTAL::log_in: SSOForward performing success")
                # Generate response depending on application.sso_forward options
                final_response = sso_forward.generate_response(request, response, authentication.get_redirect_url())
                logger.info("PORTAL::log_in: SSOForward response successfuly generated")

                return final_response

            # If learning credentials cannot be retrieved : ask them
            except CredentialsMissingError as e:
                logger.error("PORTAL::log_in: Learning credentials missing : asking-them")
                return authentication.ask_learning_credentials(request=request,
                                                               fields=e.fields_missing)

            # If KerberosBackend object cannot be retrieved from mongo with the backend_id that the user is authenticated on
            except InvalidId:
                logger.error("PORTAL::log_in: The user is authenticated on a not Kerberos backend, cannot do SSOForward")

            except (RequestsConnectionError,OpenSSLError) as e:
                logger.error("PORTAL::log_in: ConnectionError while trying to SSO to backend : ")
                logger.exception(e)

            except Exception as e:
                logger.error("PORTAL::log_in: Unexpected error while trying to perform SSO Forward :")
                logger.exception(e)

    # If we arrive here, the user is authenticated
    if openid:
        token = random_sha256()
        authentication.register_openid(token,
                                       scope=request.GET['scope'],
                                       client_id=request.GET['client_id'],
                                       redirect_uri=request.GET['redirect_uri'])

        return HttpResponseRedirect(build_url_params(request.GET['redirect_uri'],
                                                     state=request.GET.get('state', ""),
                                                     code=token))


def log_in(request, workflow_id=None):
    """ Handle authentication in Vulture Portal
    :param request: Django request object
    :returns: Home page if user auth succeed. Logon page if auth failed
    """
    """ First, try to retrieve concerned objects """
    try:
        scheme = request.META["HTTP_X_FORWARDED_PROTO"]
        host = request.META["HTTP_HOST"]
        workflow = Workflow.objects.get(pk=workflow_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected.")

    try:
        global_config = Cluster.get_global_config()

        """ Retrieve token and cookies to instantiate Redis wrapper objects """
        # Retrieve cookies required for authentication
        portal_cookie_name = global_config.portal_cookie_name
        token_name = global_config.public_token
        portal_cookie = request.COOKIES.get(portal_cookie_name) or random_sha256()
    except Exception as e:
        logger.error("PORTAL::log_in: an unknown error occurred while retrieving global config : {}".format(e))
        return HttpResponseServerError()

    response = authenticate(request, workflow, portal_cookie, portal_cookie_name) or \
               HttpResponseRedirect("#")

    try:
        kerberos_token_resp = authentication_results['data']['token_resp']
        response['WWW-Authenticate'] = 'Negotiate ' + str(kerberos_token_resp)
    except:
        pass

    redirect_url = scheme + "://" + host + workflow.public_dir

    logger.info("PORTAL::log_in: Return response {}".format(response))
    return set_portal_cookie(response, portal_cookie_name, portal_cookie, redirect_url)
