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
__maintainer__ ="Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Django views to display Self-service portal'

import sys

from django.conf import settings
sys.path.append("/home/vlt-gui/vulture/portal")

from django.shortcuts import render_to_response
from django.template import RequestContext

# Logger configuration
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('portal_authentication')

from django.http import HttpResponseRedirect, HttpResponseServerError, HttpResponseForbidden
from portal.system.redis_sessions import REDISBase, REDISPortalSession
from system.cluster.models import Cluster


def handle_disconnect (request, workflow_id=None):

    """ Handle User Disconnection
    If we are here, mod_vulture has already delete the application session in redis
    According to the configuration of App, this handler will:
     - Display a "Logout Message"
     - Destroy the portal session
     - Redirect to the application (ie: display the Login portal)

    :param request: Django request object
    :returns: Self-service portal
    """
    global_config = Cluster.get_global_config()

    """ Try to find the application with the requested URI """
    try:
        workflow = Workflow.objects.get(pk=workflow_id)
    except:
        logger.error("DISCONNECT::handle_disconnect: Unable to find workflow having id '{}'".format(workflow_id))
        return HttpResponseForbidden ("Invalid Workflow.")

    """ Get portal_cookie name from cluster """
    portal_cookie_name = global_config.portal_cookie_name
    """ Get portal cookie value (if exists) """
    portal_cookie = request.COOKIES.get(portal_cookie_name, None)
    if portal_cookie:
        logger.debug("DISCONNECT::handle_disconnect: portal_cookie Found: {}".format(portal_cookie))
    else:
        logger.error("DISCONNECT::handle_disconnect: portal_cookie not found !")
        return HttpResponseForbidden("Access Denied.")

    """ Connect to Redis """
    r = REDISBase()
    if not r:
        logger.info("PORTAL::self: Unable to connect to REDIS !")
        return HttpResponseServerError()

    portal_session = REDISPortalSession(r, portal_cookie)
    """ The user do not have a portal session: Access is forbidden """
    if not portal_session.exists():
        return HttpResponseForbidden("Invalid session.")

    # FIXME
    """ Destroy portal session if needed """
    if workflow.app_disconnect_portal:
        logger.info("DISCONNECT::handle_disconnect: portal session '{}' has been destroyed".format (portal_cookie))
        portal_session.destroy()

    # FIXME
    """ Display Logout message if needed (otherwise redirect to application) """
    if workflow.app_display_logout_message:
        template=workflow.template
        style='<link rel="stylesheet" type="text/css" href="/'+str(global_config.public_token)+'/templates/portal_%s.css">' % (str(template.id))
        logger.debug ("DISCONNECT::handle_disconnect: Display template '{}'".format (template.name))
        return render_to_response ("portal_%s_html_logout.conf" % (str(template.id)),
                               {'style':style, 'app_url':workflow.get_redirect_uri()}, context_instance=RequestContext(request))
    else:
        logger.debug ("DISCONNECT::handle_disconnect: Redirecting to redirect_uri '{}'".format(workflow.get_redirect_uri()))
        return HttpResponseRedirect(workflow.get_redirect_uri())
