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
__author__ = "Thomas Carayol / Jérémie Jourdin / Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "3.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Django views used to handle authentication events'


# Django system imports
from django.conf                     import settings
from django.http                     import HttpResponseServerError, HttpResponseForbidden, JsonResponse
from django.views.decorators.csrf    import csrf_exempt

# Django project imports
from system.cluster.models import Cluster
from portal.system.authentications   import OAUTH2Authentication
from portal.system.redis_sessions    import REDISBase
from workflow.models import Workflow

# Required exceptions imports
from django.core.exceptions          import ValidationError
from django.utils.datastructures     import MultiValueDictKeyError
from ldap                            import LDAPError
from psycopg.errors                  import PlpgsqlError
from redis                           import ConnectionError as RedisConnectionError
from portal.system.exceptions        import ACLError, TokenNotFoundError
from toolkit.auth.exceptions import AuthenticationError

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('portal_authentication')


""" Try to authenticate users in backend, if successful authentication return oauth2 token
:param request: Django request object
:param username: Username of user to authenticate
:param password: Password of user to authenticate
:param app_id: MongoDB object_id of application
"""
@csrf_exempt
def log_in(request):

    logger.debug("OAuth2_PORTAL:: Entering in log_in")

    cluster            = Cluster.objects.get()
    portal_cookie_name = cluster.getPortalCookie()

    try:
        authentication         = OAUTH2Authentication(request.POST.get('app_id', None))
        logger.info("OAUTH2::log_in: OAUTH2Authentication successfully created")
        authentication.retrieve_credentials(request.POST.get('username', None), request.POST.get('password', None), request.COOKIES.get(portal_cookie_name, None))
        logger.info("OAUTH2::log_in: Credentials successfully retrieved for user '{}'".format(authentication.credentials[0]))
        authentication_results = authentication.authenticate()
        logger.info("OAUTH2::log_in: Authentication succeed for user '{}'".format(authentication.credentials[0]))
        response               = authentication.generate_response(authentication_results)
        logger.info("OAUTH2::log_in: Response successfully generated for user '{}' : {}".format(authentication.credentials[0], response))
        return response

    # Redis connection error
    except RedisConnectionError as e:
        logger.error("OAUTH2::log_in: Unable to connect to Redis server : {}".format(str(e)))
        return HttpResponseServerError()

    except (Workflow.DoesNotExist, ValidationError) as e: # InvalidId
        logger.error("OAUTH2::log_in: Workflow with id '{}' not found : {}".format(request.POST.get('app_id', None), str(e)))

    except AssertionError as e:
        logger.error("OAUTH2::log_in: AssertionError while authenticating user '{}' : {}".format(request.POST.get('username',None), e))

    except AuthenticationError as e:
        logger.error("OAUTH2::log_in: AuthenticationError while trying to authenticate user '{}' : {}".format(request.POST.get('username',None), e))

    except ACLError as e:
        logger.error("OAUTH2::log_in: ACLError while trying to authenticate user '{}' : {}".format(request.POST.get('username',None), e))

    except (PlpgsqlError, LDAPError) as e:
        logger.error("OAUTH2::log_in: Repository driver Error while trying to authenticate user '{}' : {}".format(request.POST.get('username',None), e))

    except (MultiValueDictKeyError, AttributeError, KeyError) as e:
        logger.error("OAUTH2::log_in: Error while trying to authenticate user '{}' : {}".format(request.POST.get('username',None), e))

    except Exception as e:
        logger.error("OAUTH2::log_in: Error while trying to authenticate user '{}' : ".format(request.POST.get('username',None)))
        logger.exception(e)

    return HttpResponseForbidden()


""" Compare sent token with tokens in Redis , if match return token's permissions
:param request: Django request object
:param token: Token sent
"""
@csrf_exempt
def is_valid_token(request):
    if request.POST:
        try:
            token = request.POST['token']
            logger.debug("OAuth2Portal::is_valid_token: Token retrieved from POST data")

        except Exception as e:
            logger.error("OAuth2Portal::is_valid_token: Error while trying to retrieve 'token' from POST : {}".format(e))
            return HttpResponseForbidden()

        """ Connect to Redis """
        r = REDISBase()
        if not r:
            logger.error("OAuth2Portal::is_valid_token: Unable to connect to REDIS !")
            return HttpResponseServerError()
        logger.debug("OAuth2Portal::is_valid_token: Successfully connected to Redis")

        try:
            data = r.hgetall("oauth2_"+str(token))
            if data in ("", "None", None, {}):
                logger.error("OAuth2Portal:is_valid_token: None value was retrieved from Redis")
                raise TokenNotFoundError("Token '{}' not found in Redis".format("oauth2_"+str(token)))

            logger.debug("OAuth2Portal::is_valid_token: Oauth2 data successfully retrieved from Redis : {}".format(data))
            scope = data.get('scope', '{}')
            if scope != '{}':
                body = {
                    'active': "true",
                    'scope' : scope
                }
            else:
                body = {
                    'active': 'true'
                }

        except Exception as e:
            logger.error("OAuth2Portal:is_valid_token: Exception while retrieving data's token from Redis : {}".format(e))
            body = {"active": "false"}

        logger.debug("OAuth2Portal::is_valid_token: Returning '{}'".format(body))
        return JsonResponse(body)

    else:
        return HttpResponseForbidden()
