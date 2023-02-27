#!/home/vlt-os/env/bin/python
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

__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Authentication dedicated views of VultureOS GUI'

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext as _
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.conf import settings
from django.urls import reverse

from system.cluster.models import Cluster
from system.users.models import User
from toolkit.auth.ldap_client import LDAPClient

import logging.config
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def authent(request):
    """
    """
    error = None
    url_next = request.GET.get('next', reverse('gui.dashboard.services'))

    def render_form(**kwargs):
        return render(request, 'gui/logon.html', {
            'url_next': url_next,
            **kwargs
        })

    if request.POST:
        username = request.POST['username']
        password = request.POST['password']

        cluster = Cluster.objects.get()
        config_model = cluster.get_global_config()

        """ If LDAP authentication is enabled """
        if config_model.ldap_repository:
            ldap_client = LDAPClient(config_model.ldap_repository)
            """ Try to authenticate user on LDAP """
            try:
                if ldap_client.authenticate(username, password, return_status=True):
                    """ If authentication succeed """
                    try:
                        user = User.objects.get(username=username)
                        """ User already exists - check rights """
                        """ If user is not allowed, ask admin to set rights """
                        # TODO : is_active is sufficient ?
                        if not user.is_active:
                            logger.info("User '{}' successfully authenticated on LDAP but user is not active.".
                                        format(username))
                            # WARNING : Do NOT set variable into that field, to prevent XSS !
                            return render_form(info="Authentication succeed. </br>"
                                                    "<b>Ask administrator to set your rights.</b>")
                        else:
                            logger.info("User {} successfully authenticated on LDAP, and is_active.".
                                        format(user.username))
                            return HttpResponseRedirect(url_next)
                    except ObjectDoesNotExist:
                        """ If user not found in internal MongoDB """
                        """ Create-it with no right """
                        user = User.objects.create_user(username=username,
                                                        password="",
                                                        is_active=False,
                                                        is_superuser=False,
                                                        is_staff=False,
                                                        is_ldapuser=True)
                        user.save()
                        # WARNING : Do NOT set variable into that field, to prevent XSS !
                        return render_form(info="Your user has been successfully added. </br>"
                                                "<b>Ask your administrator to set your rights.</b>")
            except Exception as e:
                logger.error("Failed to authenticate user '{}' on LDAP : {}".format(username, e))

        user = authenticate(username=username, password=password)
        if user:
            login(request, user)

            url_next = request.POST.get('next', '/')
            if url_next == "":
                url_next = "/"

            logger.info("User {} successfully authenticated".format(user.username))
            return HttpResponseRedirect(url_next)

        error = _("Failed to authenticate")
        logger.error('User {} failed to authenticate'.format(username))

    return render_form(error=error)


@login_required
def log_out(request):
    """
    """
    logout(request)
    return HttpResponseRedirect(reverse('gui.login'))
