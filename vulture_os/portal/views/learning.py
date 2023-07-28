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
__author__ = "Jérémie Jourdin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "3.0.0"
__maintainer__ =\
    "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Django views used to handle authentication events'

import sys

from django.conf import settings
sys.path.append("/home/vlt-gui/vulture/portal")

from django.http import HttpResponse, HttpResponseForbidden
from system.learning_helper import displayLearningPortal

# Logger configuration
import logging
import logging.config
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('portal_authentication')

from gui.models.system_settings import Cluster
from gui.models.application_settings import Application

from portal.system.portal_helper import response_with_portalCookie, getPortalSession

from portal.system.redis_sessions import REDISAppSession
from system.sso_forward import doSSOForward_POST, doSSOForward_BASIC, doSSOForward_Action

from bson.objectid import ObjectId
from base64 import b64encode

def log_in(request):

    logger.debug("PORTAL: Entering in Learning")

    cluster = Cluster.objects.get()
    portal_cookie_name = cluster.getPortalCookie()
    portal_cookie = request.COOKIES.get(portal_cookie_name) or None

    """ Retrieve Portal Session from parameters given in the request """
    data = getPortalSession(logger, None, portal_cookie, None)
    if not isinstance(data, tuple):
        return data
    else:
        (redis_base, portal_session) = data

    """ portal_session must exists ! """
    if not portal_session.exists():
        logger.error("PORTAL::Learning: Unable to find portal session in Redis")
        return HttpResponseForbidden("Intrusion attempt blocked")


    """ Retrieve Application Session from parameters given in the request """
    app_cookie_name = cluster.getAppCookie()
    app_cookie = request.COOKIES.get(app_cookie_name)
    try:
        app_session = REDISAppSession(redis_base, app_cookie)
    except:
        logger.info("PORTAL::Learning: Unable to find application session in Redis")
        return HttpResponseForbidden("Intrusion attempt blocked")


    """ Retrieve the application on with we want to do learning """
    if not request.POST:
        logger.error("PORTAL::Learning: Invalid HTTP Method")
        return HttpResponseForbidden()
    try:
        app_id = request.POST.get('vulture_learning')
    except Exception as error:
        logger.error('PORTAL::Learning: No application id given')
        logger.error(error)
        return HttpResponseForbidden()

    app = Application.objects.with_id(ObjectId(app_id))
    if app is None:
        logger.info ("PORTAL::Learning: Application with id '" + str (app_id) + "' not found !")
        return HttpResponseForbidden()


    """ Prepare HTTP Response (by default, We redirect to the URI requested by the user at first) """
    response = HttpResponse()
    response_app_redirect = portal_session.keys['url_'+str(app.id)]

    """ Find logged user and backend stored in portal Session, for this AppID """
    backend            = portal_session.keys['backend_'+str(app.id)]
    logged_user        = portal_session.keys['login_'+backend]
    oauth2_token       = portal_session.keys['oauth2_'+backend]
    autologon_password = portal_session.getAutologonPassword(backend, logged_user)

    """ Perform SSO Forward if needed
        If learning is enable: It can only be for FORM or BASIC SSO Forward
    """
    if app.sso_enabled and app.sso_forward == "form":
        logger.debug ("LEARNING::log_in: calling doSSOForward_POST")
        response, sso_response, sso_response_body, sso_learning, = doSSOForward_POST(logger, request, response, app, logged_user, autologon_password, backend, oauth2_token)

    elif app.sso_enabled and app.sso_forward == "basic":
        logger.debug ("LEARNING::log_in: calling doSSOForward_BASIC")
        response, sso_response, sso_response_body, sso_learning, basic_username, basic_password = doSSOForward_BASIC(logger, request, response, app, logged_user, autologon_password, backend)

        """ Check if we have to save the header in Redis, so that mod_vulture can propagate it """
        if not app.sso_forward_only_login and (basic_username and basic_password):
            base64string = b64encode('%s:%s' % (basic_username, basic_password)).replace('\n', '')
            basic_header = "Authorization: Basic %s\r\n" % base64string
            logger.debug(
                "LEARNING::log_in: Storing the following header in Redis : {},{}".format(app_cookie, basic_header))
            app_session.setHeader(app_cookie, logged_user, basic_header)

    elif app.sso_enabled :
        logger.info( "LEARNING::log_in: Unknown authentication type for SSO : " + str(app.sso_forward) )
        return HttpResponseForbidden()

    """ SSO is not possible: Missing required variables """
    if sso_learning:
        return displayLearningPortal (request, app, sso_learning)
    else:
        """ Handle the SSOForward Response """
        response = doSSOForward_Action (response_app_redirect, app, request, response, sso_response, sso_response_body)

    """ Send response, with the portal cookie to the user """
    return response_with_portalCookie(logger, app, response, portal_cookie_name, portal_cookie)




