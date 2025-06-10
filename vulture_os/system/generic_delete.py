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
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.generic import View

# Django project imports
from applications.backend.models import Backend
from services.frontend.models import Listener, Frontend
from system.cluster.models import Cluster, Node
from system.pki.models import TLSProfile
from system.users.models import User
from toolkit.mongodb.mongo_base import MongoBase
from toolkit.redis.redis_base import RedisBase, SentinelBase

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from redis import AuthenticationError, ResponseError

# Extern modules imports

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

        used_by = self.used_by(obj_inst)

        return render(request, self.template_name, {
            'object_id': object_id,
            'menu_name': self.menu_name,
            'delete_url': self.delete_url,
            'redirect_url': self.redirect_url,
            'obj_inst': obj_inst,
            'obj_name': obj_inst._meta.verbose_name,
            'used_by': used_by
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

    def used_by(self, object):
        """ Retrieve all objects that use the current view
        Return an empty list, printed in template as "Used by this object:"
        """
        return []


class DeleteTLSProfile(DeleteView):
    menu_name = _("System -> TLS Profile -> Delete")
    obj = TLSProfile
    redirect_url = "/system/tls_profile/"
    delete_url = "/system/tls_profile/delete/"

    def used_by(self, object):
        """ Retrieve all listerners and servers that use the current TLSProfile
        Return a set of strings, printed in template as "Used by this object:"
        """
        return set(listener.frontend for listener in object.listener_set.all()).union(set(server.backend for server in object.server_set.all()))

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
                node_name = obj_inst.name
            except ObjectDoesNotExist:
                return HttpResponseForbidden("Injection detected")

            """ Before Deleting the node we need to remove it from mongoDB """
            c = MongoBase()
            c.connect_primary()
            c.repl_remove(node_name + ":9091")

            """ Before Deleting the node we need to remove it from Redis """
            c = SentinelBase(obj_inst.management_ip, 26379)
            try:
                c.sentinel_remove()
            except ResponseError as e:
                logger.error(e)

            c = RedisBase(obj_inst.management_ip, password=Cluster.get_global_config().redis_password)
            try:
                c.replica_of('NO', 'ONE')
                obj_inst.api_request("toolkit.redis.redis_base.set_password", ("", Cluster.get_global_config().redis_password), internal=True)
            except AuthenticationError:
                c = RedisBase(obj_inst.management_ip)
                c.replica_of('NO', 'ONE')

            """ Let's rock """
            obj_inst.delete()

            """ Remove Statuses of node from Frontends and Backends """
            #TODO Rework statuses to be real relational objects and ease their removal/update in code
            for frontend in Frontend.objects.all().only('status'):
                frontend.status.pop(node_name, None)
                frontend.save(update_fields=['status'])
            for backend in Backend.objects.all().only('status'):
                backend.status.pop(node_name, None)
                backend.save(update_fields=['status'])

            """ Reload every configurations """
            Cluster.api_request("services.pf.pf.gen_config")
            Cluster.api_request("services.pf.pf.reload_service", run_delay=settings.SERVICE_RESTART_DELAY)
            Cluster.api_request("services.haproxy.haproxy.configure_node")
            Cluster.api_request("services.haproxy.haproxy.reload_service", run_delay=settings.SERVICE_RESTART_DELAY)
            Cluster.api_request("services.rsyslogd.rsyslog.build_conf")
            Cluster.api_request("services.rsyslogd.rsyslog.restart_service", run_delay=settings.SERVICE_RESTART_DELAY)
            Cluster.api_request("toolkit.redis.redis_base.renew_sentinel_configuration")
            Cluster.api_request("toolkit.network.network.delete_hostname", node_name)

        return HttpResponseRedirect(self.redirect_url)

    def used_by(self, object):
        """ Retrieve all related objects that reference the current Node
        Return a set of strings, printed in template as "Used by this object:"
        """
        used_by = set(object.frontend_set.all())
        used_by = used_by.union(set(f"Listener '{listener}' in {listener.frontend}" for listener in Listener.objects.filter(network_address__in=object.addresses())))

        try:
            node_cert = object.get_certificate()
            used_by.add(f"X509 Certificate '{node_cert.name}'")
            used_by = used_by.union(set(node_cert.certificate_of.all()))
            used_by = used_by.union(set(node_cert.logomelasticsearch_set.all()))
            used_by = used_by.union(set(node_cert.logommongodb_set.all()))
            used_by = used_by.union(set(node_cert.logomrelp_set.all()))
            used_by = used_by.union(set(f"API Custom certificate of {f}" for f in node_cert.certificate_used_by_api_parser.all()))
            used_by = used_by.union(set(f"SSO Forward Client certificate of '{p}'" for p in node_cert.userauthentication_set.all()))

            tls_profiles = node_cert.certificate_of.all()
            for p in tls_profiles:
                used_by = used_by.union(set(f"TLS Profile of '{listener}' in {listener.frontend}" for listener in p.listener_set.all()))
                used_by = used_by.union(set(f"TLS Profile of '{server}' in {server.backend}" for server in p.server_set.all()))
        except ObjectDoesNotExist:
            pass

        return sorted(str(obj) for obj in used_by)

class DeleteUser(DeleteView):
    """ Class dedicated to delete an User object with its id """
    menu_name = _("System -> Users -> Delete")
    obj = User
    redirect_url = '/system/users/'
    delete_url = '/system/users/delete/'

    # get and post methods from mother class
