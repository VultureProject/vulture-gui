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
__author__ = "Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Portal URLS'


# Django system imports
from django.urls import path, re_path

# Django project imports

# Needed by handle_disconnect : Crash otherwise
#from portal.views.disconnect import handle_disconnect
from portal.views.logon import (log_in, openid_start, openid_callback, openid_configuration, openid_authorize,
                                openid_token, openid_userinfo)
from portal.views.disconnect import handle_disconnect
# from portal.views.oauth2_portal import log_in as oauth2_log_in, is_valid_token
# from portal.views.portal_statics import template_image
# from portal.views.register import registration
# from portal.views.self import self as portal_self


urlpatterns = [
    ##############################-PORTAL ROUTES-##################################

    # Self-Service
    # re_path('/(?P<token_name>[A-Za-z0-9]+)/self/(?P<proxy_app_id>[A-Za-z0-9]+)$', portal_self, name="Self-Service"),
    # re_path('/(?P<token_name>[A-Za-z0-9]+)/self/(?P<action>[a-z]+)/(?P<proxy_app_id>[A-Za-z0-9]+)$', portal_self,
    #     name="Self-Service"),
    #
    # # Registration & login
    # re_path('/(?P<token_name>[A-Za-z0-9]+)/register/(?P<proxy_app_id>[A-Za-z0-9]+)$', registration, name="Registration"),
    re_path('^portal/(?P<workflow_id>[A-Za-z0-9]+)/oauth2/start/(?P<repo_id>[A-Za-z0-9]+)', openid_start, name="OpenID start"),
    re_path('^portal/(?P<workflow_id>[A-Za-z0-9]+)/oauth2/callback/(?P<repo_id>[A-Za-z0-9]+)', openid_callback, name="OpenID callback"),
    re_path('^portal/(?P<portal_id>[A-Za-z0-9]+)/oauth2/authorize', openid_authorize, name="OpenID authorize"),
    re_path('^portal/(?P<portal_id>[A-Za-z0-9]+)/oauth2/token', openid_token, name="OpenID token"),
    re_path('^portal/(?P<portal_id>[A-Za-z0-9]+)/oauth2/userinfo', openid_userinfo, name="OpenID user_infos"),
    re_path('^portal/(?P<portal_id>[A-Za-z0-9]+)/.well-known/openid-configuration', openid_configuration, name="OpenID configuration"),
    re_path('^portal/(?P<workflow_id>[A-Za-z0-9]+)/vulture_disconnect$', handle_disconnect, name="Disconnect"),
    re_path('^portal/(?P<workflow_id>[A-Za-z0-9]+)/.*$', log_in, name="Log in"),
    # re_path('/2fa/otp', log_in),
    #
    # # OAuth2
    # re_path('/_oauth2/_login', oauth2_log_in, name="OAuth2"),
    # re_path('/_oauth2/_token', is_valid_token, name="OAuth2"),
    #
    # # Logout
    # re_path('/disconnect/(?P<app_id>[A-Za-z0-9]+)$', handle_disconnect, name="Disconnect"),
    #
    # # Templates
    # re_path('/[A-Za-z0-9]+/portal_statics/(?P<image_id>[A-Za-z0-9]+)?/[A-Za-z0-9]+', template_image,
    #     name="Template"),
]
