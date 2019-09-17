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
__doc__ = 'Classes used to delete objects'

# Django system imports
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext_lazy as _
from django.views.generic import View

# Django project imports
from system.cluster.models import NetworkAddress, Node
from system.pki.models import TLSProfile, X509Certificate
from system.users.models import User
from toolkit.mongodb.mongo_base import MongoBase
from toolkit.redis.redis_base import RedisBase

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class DeleteView(View):
    template_name = 'generic_delete.html'
    menu_name = _("")
    obj = None
    redirect_url = ""
    delete_url = ""

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request, object_id, **kwargs):
        try:
            obj_inst = self.obj.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseForbidden('Injection detected.')

        return render(request, self.template_name, {
            'object_id': object_id,
            'menu_name': self.menu_name,
            'delete_url': self.delete_url,
            'redirect_url': self.redirect_url,
            'obj_inst': obj_inst
        })

    def post(self, request, object_id, **kwargs):
        confirm = request.POST.get('confirm')
        if confirm == 'yes':
            try:
                obj_inst = self.obj.objects.get(pk=object_id)
            except ObjectDoesNotExist:
                return HttpResponseForbidden('Injection detected.')
            obj_inst.delete()
        return HttpResponseRedirect(self.redirect_url)


class DeleteTLSProfile(DeleteView):
    menu_name = _("System -> TLS Profile -> Delete")
    obj = TLSProfile
    redirect_url = "/system/tls_profile/"
    delete_url = "/system/tls_profile/delete/"

    # get and post methods herited from mother class


class DeleteNode(DeleteView):
    menu_name = _("System -> Nodes -> Delete node")
    obj = Node
    redirect_url = "/system/cluster/"
    delete_url = "/system/cluster/delete/"

    # get methods herited from mother class

    def post(self, request, object_id, **kwargs):
        confirm = request.POST.get('confirm')
        if confirm == 'yes':
            try:
                obj_inst = self.obj.objects.get(pk=object_id)
            except ObjectDoesNotExist:
                return HttpResponseForbidden("Injection detected")

            """ Before Deleting the node we need to remove it from mongoDB """
            c = MongoBase()
            c.connect()
            c.connect_primary()
            c.repl_remove(obj_inst.name + ":9091")

            """ Before Deleting the node we need to remove it from Redis """
            c = RedisBase(obj_inst.management_ip)
            c.slave_of('NO', 'ONE')

            # Fixme: Cleanup Sentinel ?

            """ Let's rock """
            obj_inst.delete()

        return HttpResponseRedirect(self.redirect_url)


class DeleteUser(DeleteView):
    """ Class dedicated to delete an User object with its id """
    menu_name = _("System -> Users -> Delete")
    obj = User
    redirect_url = '/system/users/'
    delete_url = '/system/users/delete/'

    # get and post methods from mother class
