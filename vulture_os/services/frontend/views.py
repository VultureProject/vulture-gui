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
__doc__ = 'Listeners View'


# Django system imports
from django.conf import settings
from django.http import (JsonResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect)
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

# Django project imports
from applications.logfwd.models import LogOM
from darwin.policy.models import DarwinBuffering, DarwinPolicy
from gui.forms.form_utils import DivErrorList
from services.frontend.form import FrontendForm, ListenerForm, LogOMTableForm, FrontendReputationContextForm
from services.frontend.models import Frontend, FrontendReputationContext, Listener, FILEBEAT_MODULE_CONFIG
from system.cluster.models import Cluster, Node
from toolkit.api.responses import build_response, build_form_errors
from toolkit.http.headers import HeaderForm, DEFAULT_FRONTEND_HEADERS
from toolkit.api_parser.utils import get_api_parser
from toolkit.network.network import parse_proxy_url

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from django.db.models.deletion import ProtectedError
from services.exceptions import ServiceConfigError, ServiceError, ServiceReloadError
from system.exceptions import VultureSystemError

# Extern modules imports
from copy import deepcopy
from json import loads as json_loads
from re import findall as re_findall
from sys import exc_info
from traceback import format_exception

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def frontend_clone(request, object_id=None):
    """ Frontend view used to clone a Frontend object
    N.B: Do not totally clone the object and save-it in MongoDB
        because some attributes are unique constraints

    :param request: Django request object
    :param object_id: MongoDB object_id of a Frontend object
    """
    if not object_id:
        return HttpResponseRedirect(reverse('services.frontend.list'))

    """ Retrieve object from id in MongoDB """
    try:
        frontend = Frontend.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    """ Retrieve all related objects before reset primary key """
    header_form_list = []
    reputationctx_form_list = []
    # Do NOT clone listeners to prevent overriding
    for h_tmp in frontend.headers.all():
        header_form_list.append(HeaderForm(instance=h_tmp))
    for r_tmp in frontend.frontendreputationcontext_set.all():
        reputationctx_form_list.append(FrontendReputationContextForm(instance=r_tmp))

    filebeat_configs = deepcopy(FILEBEAT_MODULE_CONFIG)
    if frontend.filebeat_module and frontend.filebeat_config:
        filebeat_configs[frontend.filebeat_module]=frontend.filebeat_config

    frontend.pk = None
    frontend.name = 'Copy of ' + str(frontend.name)

    form = FrontendForm(None, instance=frontend, error_class=DivErrorList)

    return render(request, 'services/frontend_edit.html', {
        'form': form, 'listener_form': ListenerForm(),
        'headers': header_form_list, 'header_form': HeaderForm(),
        'reputation_contexts': reputationctx_form_list,
        'reputationctx_form': FrontendReputationContextForm(),
        'log_om_table': LogOMTableForm(auto_id=False),
        'filebeat_module_config': filebeat_configs,
        'object_id': ""
    })


def frontend_delete(request, object_id, api=False):
    """ Delete Frontend and related Listeners """
    error = ""
    try:
        frontend = Frontend.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    listeners = frontend.listener_set.all()

    if((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes")
       or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")):

        # Save frontend nodes before delete-it
        nodes = frontend.get_nodes()

        # Save frontend filename before delete-it
        frontend_filename = frontend.get_base_filename()

        # Save Frontend id before deleting it
        frontend_id = frontend.pk

        # Save rsyslog frontend conf filename
        # Whatever the type, delete the file because its name is its id
        rsyslog_filename = frontend.get_rsyslog_base_filename()  # if frontend.mode != "tcp" else ""

        # Save filebeat conf filename
        # Whatever the type, delete the file because its name is its id
        filebeat_filename = frontend.get_filebeat_base_filename()  if frontend.mode == "filebeat" else ""

        # Check if darwin buffering should be reloaded
        # that is, if the frontend is associated with a policy with at least one filter with buffering configured
        was_darwin_buffered = DarwinBuffering.objects.filter(destination_filter__policy__frontend_set=frontend).exists()

        had_expected_timezone = frontend.expected_timezone is not None

        try:
            # If POST request and no error: delete frontend
            frontend.delete()

            # API request deletion of frontend filename
            for node in nodes:
                node.api_request('services.haproxy.haproxy.delete_conf', frontend_filename)

                # And reload HAProxy services
                node.api_request('services.haproxy.haproxy.reload_service')

                # Delete frontend conf
                if rsyslog_filename:
                    node.api_request('services.rsyslogd.rsyslog.delete_conf', rsyslog_filename)

                if had_expected_timezone:
                    node.api_request("services.rsyslogd.rsyslog.configure_timezones")

                # Regenerate Rsyslog system conf and restart
                node.api_request('services.rsyslogd.rsyslog.build_conf')
                node.api_request('services.rsyslogd.rsyslog.restart_service')

                # Delete Filebeat conf and restart if concerned
                if filebeat_filename:
                    node.api_request('services.filebeat.filebeat.stop_service', frontend_id)
                    node.api_request('services.filebeat.filebeat.delete_conf', filebeat_filename)

                # Reload darwin buffering if necessary
                if was_darwin_buffered:
                    DarwinPolicy.update_buffering()
                    node.api_request("services.darwin.darwin.reload_conf")

                # Update node's PF configuration
                node.api_request("services.pf.pf.gen_config")

            if api:
                return JsonResponse({
                    'status': True
                }, status=204)
            return HttpResponseRedirect(reverse('services.frontend.list'))

        except ProtectedError as e:
            logger.error("Error trying to delete Frontend '{}': Object is currently used :".format(frontend.name))
            logger.exception(e)
            error = "Object is currently used by a Workflow, cannot be deleted"

            if api:
                return JsonResponse({
                    'status': False,
                    'error': error,
                    'protected': True
                }, status=500)

        except Exception as e:
            # If API request failure, bring up the error
            logger.error("Error trying to delete frontend '{}': API|Database failure. Details:".format(frontend.name))
            logger.exception(e)
            error = "API or Database request failure: {}".format(str(e))

            if api:
                return JsonResponse({'status': False,
                                     'error': error}, status=500)
    if api:
        return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)

    # If GET request or POST request and API/Delete failure
    return render(request, 'generic_delete.html', {
        'obj_inst': frontend,
        'related_objs': listeners,
        'error': error,
        'redirect_url': '/services/frontend/',
        'menu_name': 'Services -> Listeners -> Delete'
    })


def frontend_edit(request, object_id=None, api=False):
    frontend = None
    listener_form_list = []
    header_form_list = []
    reputationctx_form_list = []
    node_listeners = dict()
    darwin_buffering_needs_refresh = False
    if object_id:
        try:
            frontend = Frontend.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                return JsonResponse({'error': _("Object does not exist.")}, status=404)
            return HttpResponseForbidden("Injection detected")

    """ Create form with object if exists, and request.POST (or JSON) if exists """
    empty = {} if api else None
    if hasattr(request, "JSON") and api:
        validate = request.JSON.get('validate', True)
        form = FrontendForm(request.JSON or {}, instance=frontend, error_class=DivErrorList)
    else:
        validate = request.POST.get('validate', True) not in (False, "false", "False")
        form = FrontendForm(request.POST or empty, instance=frontend, error_class=DivErrorList)

    def render_form(front, **kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                logger.error("Frontend api form error : {}".format(form.errors.get_json_data()))
                return JsonResponse({"errors": build_form_errors(form.errors)}, status=400)

            if save_error:
                logger.error("Frontend api save error : {}".format(save_error))
                return JsonResponse({'error': save_error[0], 'details': save_error[1]}, status=500)

        if not listener_form_list and front:
            for l_tmp in front.listener_set.all():
                listener_form_list.append(ListenerForm(instance=l_tmp))

        if not header_form_list and front:
            for h_tmp in front.headers.all():
                header_form_list.append(HeaderForm(instance=h_tmp))

        # If it is a new object, add default-example headers
        if not front and request.method == "GET":
            for header in DEFAULT_FRONTEND_HEADERS:
                header_form_list.append(HeaderForm(header))

        if not reputationctx_form_list and front and front.pk:
            for r_tmp in front.frontendreputationcontext_set.all():
                reputationctx_form_list.append(FrontendReputationContextForm(instance=r_tmp))

        filebeat_configs = deepcopy(FILEBEAT_MODULE_CONFIG)
        if front and front.filebeat_module and front.filebeat_config:
            filebeat_configs[front.filebeat_module]=front.filebeat_config

        return render(request, 'services/frontend_edit.html',
                      {'form': form, 'listeners': listener_form_list, 'listener_form': ListenerForm(),
                       'headers': header_form_list, 'header_form': HeaderForm(),
                       'reputation_contexts': reputationctx_form_list,
                       'reputationctx_form': FrontendReputationContextForm(),
                       'log_om_table': LogOMTableForm(auto_id=False),
                       'filebeat_module_config': filebeat_configs,
                       'object_id': (frontend.id if frontend else "") or "", **kwargs})

    if request.method in ("POST", "PUT"):
        """ Handle JSON formatted listeners """
        try:
            if api and hasattr(request, "JSON"):
                listener_ids = request.JSON.get('listeners', [])
                assert isinstance(listener_ids, list), "Listeners field must be a list."
            else:
                listener_ids = json_loads(request.POST.get('listeners', "[]"))
        except Exception as e:
            return render_form(frontend, save_error=["Error in Listeners field : {}".format(e),
                                                     str.join('', format_exception(*exc_info()))])
        header_objs = []
        reputationctx_objs = []

        if form.data.get('mode') == "http":
            """ Handle JSON formatted headers """
            try:
                if api and hasattr(request, "JSON"):
                    header_ids = request.JSON.get('headers', [])
                    assert isinstance(header_ids, list), "Headers field must be a list."
                else:
                    header_ids = json_loads(request.POST.get('headers', "[]"))
            except Exception as e:
                return render_form(frontend, save_error=["Error in Request-headers field : {}".format(e),
                                                         str.join('', format_exception(*exc_info()))])

            """ For each header in list """
            for header in header_ids:
                """ If id is given, retrieve object from mongo """
                try:
                    if frontend and hasattr(header, "id"):
                        instance_h = frontend.headers.get(pk=header['id'])
                    else:
                        instance_h = None
                except ObjectDoesNotExist:
                    form.add_error("headers", "Request-header with id {} not found.".format(header['id']))
                    continue
                """ And instantiate form with the object, or None """
                header_f = HeaderForm(header, instance=instance_h)
                if not header_f.is_valid():
                    form.add_error("headers", header_f.errors.get_json_data() if api else
                                              header_f.errors.as_ul())
                    continue
                # Save forms in case we re-print the page
                header_form_list.append(header_f)
                # And save objects list, to save them later, when Frontend will be saved
                header_objs.append(header_f.save(commit=False))

        """ Handle JSON formatted ReputationContext """
        try:
            if api and hasattr(request, "JSON"):
                reputationctx_ids = request.JSON.get('reputation_contexts', [])
            else:
                reputationctx_ids = json_loads(request.POST.get('reputation_contexts', "[]"))
            assert isinstance(reputationctx_ids, list), "reputation_contexts field must be a list."
        except Exception as e:
            return render_form(frontend, save_error=["Error in ReputationConext field : {}".format(e),
                                                     str.join('', format_exception(*exc_info()))])

        """ For each reputation_context in list """
        for reputationctx in reputationctx_ids:
            """ Instantiate form """
            reputationctx_f = FrontendReputationContextForm(reputationctx)
            if not reputationctx_f.is_valid():
                form.add_error("reputation_ctx", reputationctx_f.errors.get_json_data() if api else
                                                 reputationctx_f.errors.as_ul())
                continue
            # Save forms in case we re-print the page
            reputationctx_form_list.append(reputationctx_f)
            # And save objects list, to save them later, when Frontend will be saved
            reputationctx_objs.append(reputationctx_f.save(commit=False))

        listener_objs = []
        if form.data.get('mode') in ("http", "tcp") \
        or form.data.get('mode') == "log" and form.data.get('listening_mode') in ("tcp", "udp", "tcp,udp", "relp") \
        or form.data.get('mode') == "filebeat" and form.data.get('filebeat_listening_mode') in ("tcp", "udp"):

            # At least one Listener is required if Frontend enabled, except for listener of type "File", and "API"
            if form.data.get('enabled') and not listener_ids:
                form.add_error(None, "At least one listener is required if frontend is enabled.")

            """ For each listener in list """
            for listener in listener_ids:
                """ If id is given, retrieve object from mongo """
                try:
                    instance_l = Listener.objects.get(pk=listener['id']) if listener.get('id') else None
                except ObjectDoesNotExist:
                    form.add_error("listeners", "Listener with id {} not found.".format(listener['id']))
                    continue

                """ And instantiate form with the object, or None """
                listener_f = ListenerForm(listener, instance=instance_l)

                if listener_f.data.get('tls_profiles') == ['']:
                    listener_f.data['tls_profiles'] = None

                if not listener_f.is_valid():
                    form.add_error("listeners", listener_f.errors.as_json() if api else [error for error_list in listener_f.errors.as_data().values() for error in error_list])
                    continue

                listener_form_list.append(listener_f)
                listener_obj = listener_f.save(commit=False)
                listener_objs.append(listener_obj)

                """ For each listener, get node """
                for nic in listener_obj.network_address.nic.all().only('node'):
                    if nic.node:
                        if not node_listeners.get(nic.node):
                            node_listeners[nic.node] = list()
                        node_listeners[nic.node].append(listener_obj)

        old_nodes = None
        old_rsyslog_filename = ""
        old_haproxy_filename = ""
        old_filebeat_filename = ""
        if frontend:
            old_nodes = frontend.get_nodes()

            # Get current Rsyslog configuration filename
            if frontend.enable_logging:
                old_rsyslog_filename = frontend.get_rsyslog_base_filename()
                # Get current Filebeat configuration filename
                if frontend.mode == "filebeat":
                    old_filebeat_filename = frontend.get_filebeat_base_filename()

            # Get current Haproxy configuration filename
            if not frontend.rsyslog_only_conf and not frontend.filebeat_only_conf:
                old_haproxy_filename = frontend.get_base_filename()

        # Frontend used by workflow type change check
        if object_id and "mode" in form.changed_data:
            if frontend.workflow_set.exists():
                form.add_error('mode', "You can't modify frontend's type, currently used by workflow(s) : {}".format(", ".join([w.name for w in frontend.workflow_set.all().only('name')])))
            if frontend.userauthentication_set.exists():
                form.add_error('mode', "You can't modify frontend's type, currently used by IDP(s) : {}".format(", ".join([w.name for w in frontend.userauthentication_set.all().only('name')])))

        # If errors has been added in form
        if not form.is_valid():
            logger.error("Frontend form errors: {}".format(form.errors.as_json()))
            return render_form(frontend)

        # Save the form to get an id if there is not already one
        frontend = form.save(commit=False)
        frontend.configuration = {}

        if frontend.mode == "log" and frontend.listening_mode in ("file", "kafka", "redis"):
            if frontend.node:
                node_listeners[frontend.node] = []
            else:
                for node in Node.objects.all():
                    node_listeners[node] = []
        elif frontend.mode == "filebeat" and frontend.filebeat_listening_mode in ("file", "api"):
            # For now, with filebeat API, we have to select a dedicated node
            # FIXME: Be able to automaticaly distribute API parsers among Vulture cluster
            if frontend.node:
                node_listeners[frontend.node] = []
        elif frontend.mode == "log" and frontend.listening_mode == "api":
            # Listen on all nodes in case of a master mongo change for Vulture's API Parsers
            for node in Node.objects.all():
                node_listeners[node] = []


        try:
            """ For each node, the conf differs if listener chosen """
            """ Generate the conf """
            if validate:
                logger.debug("Generating conf of frontend '{}'".format(frontend.name))
                for node, listeners in node_listeners.items():
                    # HAProxy conf does not use reputationctx_list, Rsyslog conf does
                    frontend.configuration[node.name] = frontend.generate_conf(listener_list=listeners,
                                                                           header_list=header_objs,
                                                                           node=node)
                    if node.state == "UP":
                        frontend.test_conf(node.name)
                        logger.info(f"FRONTEND::Edit: Configuration test ok on node {node.name}")
                    else:
                        logger.warning(f"FRONTEND::Edit: Configuration test skipped on node {node.name} (state {node.state})")
        except ServiceError as e:
            logger.exception(e)
            return render_form(frontend, save_error=[str(e), e.traceback])

        except Exception as e:
            logger.exception(e)
            return render_form(frontend, save_error=["No referenced error",
                                                     str.join('', format_exception(*exc_info()))])

        """ If the object already exists """
        if frontend.id:
            try:
                changed_data = form.changed_data
                new_nodes = node_listeners.keys()

                for node in old_nodes:
                    if old_rsyslog_filename:
                        """ If the ruleset has changed, we need to delete the old-named file """
                        """ Or if the mode has changed, we need to delete the old-named file """
                        """ Or if logging is disabled, we need to delete the rsyslog file """
                        if frontend.mode in ["log", "filebeat"] and "ruleset" in changed_data \
                        or "mode" in changed_data \
                        or not frontend.enable_logging \
                        or node not in new_nodes:
                            # API request to delete rsyslog frontend filename
                            logger.info(f"Rsyslogd config '{old_rsyslog_filename}' deletion asked on node {node}.")
                            node.api_request('services.rsyslogd.rsyslog.delete_conf', old_rsyslog_filename)
                            # API request to rebuild global rsyslog configuration
                            logger.info(f"Rsyslogd global config reload asked on node {node}.")
                            node.api_request('services.rsyslogd.rsyslog.build_conf')
                            # API request to ensure timezone rulesets are up-to-date on node
                            node.api_request('services.rsyslogd.rsyslog.configure_timezones')
                            # And reload of Rsyslog service
                            node.api_request('services.rsyslogd.rsyslog.restart_service')

                    if old_filebeat_filename:
                        if frontend.mode != "filebeat" \
                        or node not in new_nodes:
                            logger.info(f"Filebeat config '{old_rsyslog_filename}' deletion asked on node {node}.")
                            # Stop Filebeat service and delete old config file
                            node.api_request('services.filebeat.filebeat.stop_service', frontend.id)
                            node.api_request('services.filebeat.filebeat.delete_conf', old_filebeat_filename)

                    if old_haproxy_filename:
                        if frontend.rsyslog_only_conf \
                        or frontend.filebeat_only_conf \
                        or node not in new_nodes:
                            logger.info(f"HAProxy config '{old_haproxy_filename}' deletion asked on node {node}.")
                            # API request deletion of frontend filename
                            node.api_request('services.haproxy.haproxy.delete_conf', old_haproxy_filename)
                            # And reload of HAProxy service
                            node.api_request('services.haproxy.haproxy.reload_service')

            except Exception as e:
                logger.exception(e)
                return render_form(frontend, save_error=["Cluster API request failure: {}".format(e),
                                                         str.join('', format_exception(*exc_info()))])

        """ If the conf is OK, save the Frontend object """
        # Is that object already in db or not
        try:
            if frontend.mode == "http":
                frontend.ruleset = "haproxy"
            elif frontend.mode == "tcp":
                frontend.ruleset = "haproxy_tcp"

            if frontend.enable_logging:
                log_forwarders = set()
                """ Handle LogForwarders selected objects in log_condition """
                for log_om_name in re_findall("{{([^}]+)}}", frontend.log_condition):
                    try:
                        # Only id because we do not need any attribute
                        log_om = LogOM().select_log_om_by_name(log_om_name)
                        """ If the relation does not already exists : create-it """
                        log_forwarders.add(log_om.id)
                    except ObjectDoesNotExist:
                        form.add_error("log_condition", "LogForwarder not found.")
                        return render_form(frontend)

                frontend.log_forwarders_id = log_forwarders

            logger.debug("Saving frontend")
            frontend.last_update_time = timezone.now()
            frontend.save()
            logger.debug("Frontend '{}' (id={}) saved in MongoDB.".format(frontend.name, frontend.id))

            """ And all the listeners early created """
            for listener in listener_objs:
                listener.frontend = frontend
                logger.debug("Saving listener {}".format(str(listener)))
                listener.save()

            """ Delete listeners deleted in form """
            for listener in frontend.listener_set.exclude(pk__in=[listener.id for listener in listener_objs]):
                listener.delete()
                logger.info("Deleting listener {}".format(listener))

            """ If mode is HTTP """
            if frontend.mode == "http":
                """ Remove request-headers removed """
                for header in frontend.headers.all():
                    if header not in header_objs:
                        frontend.headers.remove(header)

                """ Associate added request-headers """
                for header in header_objs:
                    new_object = not header.id
                    header.save()
                    if new_object:
                        frontend.headers.add(header)
                    logger.debug("HTTP Headers {} associated to Frontend {}".format(header, frontend))

            # Delete all intermediary objects
            FrontendReputationContext.objects.filter(frontend=frontend).delete()
            # And re-create them
            for reputationctx in reputationctx_objs:
                FrontendReputationContext.objects.create(frontend=frontend,
                                                         reputation_ctx=reputationctx.reputation_ctx,
                                                         enabled=reputationctx.enabled,
                                                         arg_field=reputationctx.arg_field,
                                                         dst_field=reputationctx.dst_field)

            for node in node_listeners.keys():

                logger.info("Writing conf of frontend '{}' on node '{}'".format(frontend.name, node.name))

                if frontend.expected_timezone is not None or "expected_timezone" in form.changed_data:
                    node.api_request('services.rsyslogd.rsyslog.configure_timezones')

                if frontend.enable_logging:
                    """ We need to configure Rsyslog, it will check if conf has changed & restart service if needed """
                    api_res = node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)
                    if not api_res.get('status'):
                        raise ServiceConfigError("on node {}:  API request error.".format(node.name), "rsyslog",
                                                traceback=api_res.get('message'))
                    api_res = node.api_request("services.rsyslogd.rsyslog.restart_service")

                """ We need to configure Filebeat, it will check if conf has changed """
                if frontend.mode == "filebeat":
                    api_res = node.api_request("services.filebeat.filebeat.build_conf", frontend.id)
                    if not api_res.get('status'):
                        raise ServiceConfigError("on node {}: API request error.".format(node.name), "filebeat",
                                                 traceback=api_res.get('message'))

                if not frontend.rsyslog_only_conf and not frontend.filebeat_only_conf:
                    """ Reload HAProxy service - After rsyslog / filebeat to prevent logging crash """
                    api_res = node.api_request("services.haproxy.haproxy.build_conf", frontend.id)
                    if not api_res.get('status'):
                        raise ServiceReloadError("on node {}: API request error.".format(node.name), "haproxy",
                                                 traceback=api_res.get('message'))
                    api_res = node.api_request("services.haproxy.haproxy.reload_service")
                    if not api_res.get('status'):
                        raise ServiceReloadError("on node {}: API request error.".format(node.name), "haproxy",
                                                 traceback=api_res.get('message'))
                    frontend.status[node.name] = "WAITING"
                    frontend.save()

            # Check if reload logrotate conf if needed
            # meaning if there is a log_forwarder file enabled used by this frontend
            if frontend.enable_logging and (frontend.log_forwarders.filter(logomfile__enabled=True).count() > 0 or
                                            frontend.log_forwarders_parse_failure.filter(logomfile__enabled=True).count()):
                # Reload LogRotate config
                Cluster.api_request("services.logrotate.logrotate.reload_conf")

            # If the frontend is associated with a policy containing buffered filters
            # then the buffering policy needs a refresh
            if DarwinBuffering.objects.filter(destination_filter__policy__frontend_set=frontend).exists():
                # Don't remove this condition, the variable can also be set above
                darwin_buffering_needs_refresh = True

            # Reload darwin buffering if necessary
            if darwin_buffering_needs_refresh:
                logger.debug("frontend_edit: frontend has darwin bufferings, will update buffering policy")
                DarwinPolicy.update_buffering()
                Cluster.api_request("services.darwin.darwin.reload_conf")

            # Reload cluster PF configuration
            Cluster.api_request("services.pf.pf.gen_config")

        except (VultureSystemError, ServiceError) as e:
            """ Error saving configuration file """
            """ The object has been saved, delete-it if needed """
            if not frontend.id:
                for listener in frontend.listener_set.all():
                    listener.delete()

                frontend.delete()

            logger.exception(e)
            return render_form(frontend, save_error=[str(e), e.traceback])

        except Exception as e:
            """ If we arrive here, the object has not been saved """
            logger.exception(e)
            return render_form(frontend, save_error=["Failed to save object in database :\n{}".format(e),
                                                     str.join('', format_exception(*exc_info()))])

        if api:
            return build_response(frontend.id, "services.frontend.api", COMMAND_LIST)
        return HttpResponseRedirect(reverse('services.frontend.list'))

    return render_form(frontend)


def frontend_start(request, object_id, api=False):
    if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return HttpResponseBadRequest()

    try:
        frontend = Frontend.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden('Injection detected.')

    try:
        """ Returns a string, or raise ServiceError """
        res = frontend.enable()
    except ServiceError as e:
        logger.exception(e)
        return JsonResponse({'status': False, 'error': str(e), 'error_details': e.traceback})

    return JsonResponse({'status': True, 'message': res})


def frontend_pause(request, object_id, api=False):
    if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return HttpResponseBadRequest()

    try:
        frontend = Frontend.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden('Injection detected.')

    try:
        res = frontend.disable()
    except ServiceError as e:
        logger.exception(e)
        return JsonResponse({'status': False, 'error': str(e), 'error_details': e.traceback})

    return JsonResponse({'status': True, 'message': res})


def frontend_test_apiparser(request):
    try:
        type_parser = request.POST.get('api_parser_type')

        data = {}
        for k, v in request.POST.items():
            if v in ('false', 'true'):
                v = v == "true"

            data[k] = v

        if data.get('api_parser_use_proxy', True) and data.get('api_parser_custom_proxy', None):
            # parse_proxy_url will validate and return a correct url
            proxy = parse_proxy_url(data.get('api_parser_custom_proxy', None))
            if not proxy:
                return JsonResponse({'status': False, 'error': "Wrong proxy format"})
            data['api_parser_custom_proxy'] = proxy

        parser = get_api_parser(type_parser)(data)
        return JsonResponse(parser.test())

    except Exception as e:
        logger.error(e, exc_info=1)
        return JsonResponse({
            'status': False,
            'error': str(e)
        })


def frontend_fetch_apiparser_data(request):
    try:
        type_parser = request.POST.get('api_parser_type')

        data = {}
        for k, v in request.POST.items():
            if v in ('false', 'true'):
                v = v == 'true'

            data[k] = v

        parser = get_api_parser(type_parser)(data)
        return JsonResponse(parser.fetch_data())

    except Exception as e:
        logger.error(e, exc_info=1)
        return JsonResponse({
            'status': False,
            'error': str(e)
        })


COMMAND_LIST = {
    'start': frontend_start,
    'pause': frontend_pause,
}
