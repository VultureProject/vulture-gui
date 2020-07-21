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

__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Classes used to delete objects'

# Django system imports
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db.models.deletion import ProtectedError
from django.http import HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext_lazy as _
from django.views.generic import View

# Django project imports
from darwin.access_control.models import AccessControl
from darwin.defender_policy.models import DefenderPolicy
from darwin.policy.models import DarwinFilter, DarwinPolicy
from darwin.log_viewer.models import DefenderRuleset
from darwin.inspection.models import InspectionPolicy, InspectionRule
from services.frontend.models import BlacklistWhitelist, Frontend
from system.cluster.models import Cluster
from workflow.models import Workflow

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.exceptions import ServiceError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


# Do NOT instantiate directly - it's an abstract class
# Create a child class and instantiate-it
# Do not forget used_by mandatory method in all childs
class DeleteView(View):
    template_name = 'generic_delete.html'
    menu_name = _("")
    obj = None
    redirect_url = ""
    delete_url = ""

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(DeleteView, self).dispatch(*args, **kwargs)

    def used_by(self, object=None):
        return []

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
            'obj_inst': obj_inst,
            'used_by': self.used_by(obj_inst)
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


class DeleteDarwinPolicy(DeleteView):
    menu_name = _("Darwin -> Policy -> Delete")
    obj = DarwinPolicy
    redirect_url = "/darwin/policy/"
    delete_url = "/darwin/policy/delete/"

    # This method is mandatory for all child classes
    # Returns [] if nothing to do
    def used_by(self, policy):
        """ Retrieve all objects that use the current object
        Return a list of strings, printed in template as "Used by this object:"
        """
        return [frontend.name for frontend in Frontend.objects.filter(darwin_policies=policy)]

    # get methods inherited from mother class
    def post(self, request, object_id, **kwargs):
        confirm = request.POST.get('confirm')
        if confirm == 'yes':
            try:
                obj_inst = self.obj.objects.get(pk=object_id)
            except ObjectDoesNotExist:
                return HttpResponseForbidden('Injection detected.')

            logger.info("Deleting filter policy configuration files associated with Darwin policy...")

            try:
                filter_conf_paths = [obj.conf_path for obj in obj_inst.filterpolicy_set.all()]

                obj_inst.delete()

                for filter_conf_path in filter_conf_paths:
                    Cluster.api_request("services.darwin.darwin.delete_filter_conf", filter_conf_path)
                Cluster.api_request("services.darwin.darwin.build_conf")
            except ProtectedError as e:
                error = "Policy is still used. Cannot remove"

        return HttpResponseRedirect(self.redirect_url)


class DeleteBlacklistWhitelists(DeleteView):
    menu_name = _("Darwin -> WAF Rules -> Delete")
    obj = BlacklistWhitelist
    redirect_url = "/darwin/waf_rules/"
    delete_url = "/darwin/waf_rules/delete/"

    # This method is mandatory for all child classes
    # Returns [] if nothing to do
    def used_by(self, object):
        """ Retrieve all objects that use the current object
        Return a list of strings, printed in template as "Used by this object:"
        """
        # TODO: Workflow use
        # return [str(i) for i in object.]
        return []

    # get methods inherited from mother class
    def post(self, request, object_id, **kwargs):
        confirm = request.POST.get('confirm')
        if confirm == 'yes':
            try:
                obj_inst = self.obj.objects.get(pk=object_id)
            except ObjectDoesNotExist:
                return HttpResponseForbidden('Injection detected.')

            frontend = obj_inst.frontend
            obj_inst.delete()

            for node in frontend.get_nodes():
                api_res = node.api_request("services.haproxy.haproxy.build_conf", frontend.id)
                if not api_res.get('status'):
                    logger.error("Access_Control::edit: API error while trying to "
                                 "restart HAProxy service : {}".format(api_res.get('message')))

        return HttpResponseRedirect(self.redirect_url)


class DeleteInspectionPolicy(DeleteView):
    menu_name = _("Darwin -> Packet Inspection policies -> Delete")
    obj = InspectionPolicy
    redirect_url = "/darwin/inspection/"
    delete_url = "/darwin/inspection/policy/delete/"

    # This method is mandatory for all child classes
    # Returns [] if nothing to do
    def used_by(self, object):
        """ Retrieve all objects that use the current object
        Return a list of strings, printed in template as "Used by this object:"
        """
        # TODO: Frontend use
        # return [str(i) for i in object.]
        return []

    # get methods inherited from mother class
    def post(self, request, object_id, **kwargs):
        confirm = request.POST.get('confirm')
        if confirm == 'yes':
            try:
                obj_inst = self.obj.objects.get(pk=object_id)
            except ObjectDoesNotExist:
                return HttpResponseForbidden('Injection detected.')

            try:
                obj_inst.delete()
                obj_inst.delete_policy_file()
            except Exception as e:
                logger.error(e)

        return HttpResponseRedirect(self.redirect_url)


class DeleteInspectionRule(DeleteView):
    menu_name = _("Darwin -> Packet Inspection rules -> Delete")
    obj = InspectionRule
    redirect_url = "/darwin/inspection/"
    delete_url = "/darwin/inspection/rule/delete/"

    # This method is mandatory for all child classes
    # Returns [] if nothing to do
    def used_by(self, object):
        """ Retrieve all objects that use the current object
        Return a list of strings, printed in template as "Used by this object:"
        """
        # TODO: Frontend use
        # return [str(i) for i in object.]

    # get methods inherited from mother class
    def post(self, request, object_id, **kwargs):
        confirm = request.POST.get('confirm')
        if confirm == 'yes':
            try:
                obj_inst = self.obj.objects.get(pk=object_id)
            except ObjectDoesNotExist:
                return HttpResponseForbidden('Injection detected.')

            obj_inst.delete()

        return HttpResponseRedirect(self.redirect_url)

class DeleteDefenderPolicy(DeleteView):
    menu_name = _("Darwin -> Defender Policy -> Delete")
    obj = DefenderPolicy
    redirect_url = "/darwin/defender_policy/"
    delete_url = "/darwin/defender_policy/delete/"

    # This method is mandatory for all child classes
    # Returns [] if nothing to do
    def used_by(self, object):
        """ Retrieve all objects that use the current object
        Return a list of strings, printed in template as "Used by this object:"
        """
        to_return = [
            "Workflow {frontend_name} - {fqdn} - {public_dir} - {backend_name}".format(
                frontend_name=workflow.frontend.name,
                fqdn=workflow.fqdn,
                public_dir=workflow.public_dir,
                backend_name=workflow.backend.name,
            )
            for workflow in Workflow.objects.filter(defender_policy=object)
        ]

        return to_return

    # get methods inherited from mother class
    def post(self, request, object_id, **kwargs):
        confirm = request.POST.get('confirm')
        if confirm == 'yes':
            DefenderPolicy.objects.get(pk=object_id).delete()
            Cluster.api_request("darwin.defender_policy.policy.delete_defender_conf", object_id)
        return HttpResponseRedirect(self.redirect_url)


class DeleteDefenderRuleset(DeleteView):
    menu_name = _("Darwin -> Defender ruleset -> Delete")
    obj = DefenderRuleset
    redirect_url = "/darwin/defender_ruleset/"
    delete_url = "/darwin/defender_ruleset/delete/"

    # This method is mandatory for all child classes
    # Returns [] if nothing to do
    def used_by(self, object):
        """ Retrieve all objects that use the current object
        Return a list of strings, printed in template as "Used by this object:"
        """
        to_return = [
            "Defender policy {name}".format(name=defender_policy.name)
            for defender_policy in DefenderPolicy.objects.filter(defender_ruleset=object)
        ]

        return to_return

    # get methods inherited from mother class
    def post(self, request, object_id, **kwargs):
        confirm = request.POST.get('confirm')
        if confirm == 'yes':
            DefenderRuleset.objects.get(pk=object_id).delete()
        return HttpResponseRedirect(self.redirect_url)


class DeleteAccessControl(DeleteView):
    menu_name = _("Security Engine -> Access Control -> Delete")
    obj = AccessControl
    redirect_url = "/darwin/acl/"
    delete_url = "/darwin/acl/delete/"

    # get, post and used_by methods herited from mother class
