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
from django.utils.translation import ugettext_lazy as _

# Django project imports
from applications.logfwd.models import LogOM
from gui.forms.form_utils import DivErrorList
from services.frontend.form import FrontendForm, ListenerForm, LogOMTableForm, FrontendReputationContextForm
from services.frontend.models import Frontend, FrontendReputationContext, Listener
from system.cluster.models import Cluster, Node
from toolkit.api.responses import build_response
from toolkit.http.headers import HeaderForm, DEFAULT_FRONTEND_HEADERS
from toolkit.api_parser.utils import get_api_parser

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from django.db.models.deletion import ProtectedError
from services.exceptions import ServiceConfigError, ServiceError, ServiceReloadError
from system.exceptions import VultureSystemError

# Extern modules imports
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
        return HttpResponseRedirect('/services/frontend/')

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

    frontend.pk = None
    frontend.name = 'Copy of ' + str(frontend.name)

    form = FrontendForm(None, instance=frontend, error_class=DivErrorList)

    return render(request, 'services/frontend_edit.html', {
        'form': form, 'listener_form': ListenerForm(),
        'headers': header_form_list, 'header_form': HeaderForm(),
        'reputation_contexts': reputationctx_form_list,
        'reputationctx_form': FrontendReputationContextForm(),
        'log_om_table': LogOMTableForm(auto_id=False),
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

        # Save frontend filename before delete-it
        frontend_filename = frontend.get_base_filename()

        # Save rsyslog frontend conf filename
        # Whatever the type, delete the file because its name is its id
        rsyslog_filename = frontend.get_rsyslog_base_filename()  # if frontend.mode != "tcp" else ""

        try:
            # If POST request and no error: detete frontend
            frontend.delete()

            # TODO: Verify which node(s) are concerned for API requests ?
            # API request deletion of frontend filename
            Cluster.api_request('services.haproxy.haproxy.delete_conf', frontend_filename)

            # And reload of HAProxy service
            Cluster.api_request('services.haproxy.haproxy.reload_service')

            # Delete frontend conf
            if rsyslog_filename:
                Cluster.api_request('services.rsyslogd.rsyslog.delete_conf', rsyslog_filename)

            # Regenerate Rsyslog system conf and restart
            Cluster.api_request('services.rsyslogd.rsyslog.build_conf')

            if api:
                return JsonResponse({
                    'status': True
                }, status=204)
            return HttpResponseRedirect(reverse('services.frontend.list'))

        except ProtectedError as e:
            logger.error("Error trying to delete Frontend '{}': Object is currently used :".format(frontend.name))
            logger.exception(e)
            error = "Object is currently used by a Workflow, cannot be deleted"

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
    if object_id:
        try:
            frontend = Frontend.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                return JsonResponse({'error': _("Object does not exist.")}, status=404)
            return HttpResponseForbidden("Injection detected")

    """ Create form with object if exists, and request.POST (or JSON) if exists """
    if hasattr(request, "JSON") and api:
        form = FrontendForm(request.JSON or None, instance=frontend, error_class=DivErrorList)
    else:
        form = FrontendForm(request.POST or None, instance=frontend, error_class=DivErrorList)

    def render_form(front, **kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                logger.error("Frontend api form error : {}".format(form.errors.get_json_data()))
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                logger.error("Frontend api save error : {}".format(save_error))
                return JsonResponse({'error': save_error[0]}, status=500)

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
        if not reputationctx_form_list and front:
            for r_tmp in front.frontendreputationcontext_set.all():
                reputationctx_form_list.append(FrontendReputationContextForm(instance=r_tmp))
        redis_fwd = LogOM.objects.filter(name="Internal_Dashboard").only('id').first()
        return render(request, 'services/frontend_edit.html',
                      {'form': form, 'listeners': listener_form_list, 'listener_form': ListenerForm(),
                       'headers': header_form_list, 'header_form': HeaderForm(),
                       'reputation_contexts': reputationctx_form_list,
                       'reputationctx_form': FrontendReputationContextForm(),
                       'log_om_table': LogOMTableForm(auto_id=False),
                       'redis_forwarder': redis_fwd.id if redis_fwd else 0,
                       'object_id': (frontend.id if frontend else "") or "", **kwargs})

    if request.method in ("POST", "PUT"):
        """ Handle JSON formatted listeners """
        try:
            if api:
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
                if api:
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
                    instance_h = frontend.headers.get(pk=header['id']) if frontend and header['id'] else None
                except ObjectDoesNotExist:
                    form.add_error(None, "Request-header with id {} not found. Injection detected ?")
                    continue
                """ And instantiate form with the object, or None """
                header_f = HeaderForm(header, instance=instance_h)
                if not header_f.is_valid():
                    if api:
                        form.add_error(None, header_f.errors.get_json_data())
                    else:
                        form.add_error('headers', header_f.errors.as_ul())
                    continue
                # Save forms in case we re-print the page
                header_form_list.append(header_f)
                # And save objects list, to save them later, when Frontend will be saved
                header_objs.append(header_f.save(commit=False))

        """ Handle JSON formatted ReputationContext """
        try:
            if api:
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
                form.add_error(None if api else "reputation_ctx",
                               reputationctx_f.errors.get_json_data() if api else reputationctx_f.errors.as_ul())
                continue
            # Save forms in case we re-print the page
            reputationctx_form_list.append(reputationctx_f)
            # And save objects list, to save them later, when Frontend will be saved
            reputationctx_objs.append(reputationctx_f.save(commit=False))

        listener_objs = []
        if form.data.get('mode') != "impcap" and form.data.get('listening_mode') not in ("file", "api"):
            """ For each listener in list """
            for listener in listener_ids:
                """ If id is given, retrieve object from mongo """
                try:
                    instance_l = Listener.objects.get(pk=listener['id']) if listener['id'] else None
                except ObjectDoesNotExist:
                    form.add_error(None, "Listener with id {} not found.".format(listener['id']))
                    continue

                """ And instantiate form with the object, or None """
                listener_f = ListenerForm(listener, instance=instance_l)
                if not listener_f.is_valid():
                    if api:
                        form.add_error("listeners", listener_f.errors.as_json())
                    else:
                        form.add_error("listeners", listener_f.errors.as_ul())
                    continue
                listener_form_list.append(listener_f)
                listener_obj = listener_f.save(commit=False)
                listener_objs.append(listener_obj)

                """ For each listener, get node """
                for nic in listener_obj.network_address.nic.all().only('node'):
                    if not node_listeners.get(nic.node):
                        node_listeners[nic.node] = list()
                    node_listeners[nic.node].append(listener_obj)

        # Get current Rsyslog configuration filename
        old_rsyslog_filename = frontend.get_rsyslog_base_filename() if frontend and frontend.enable_logging else ""

        # If errors has been added in form
        if not form.is_valid():
            logger.error("Frontend form errors: {}".format(form.errors.as_json()))
            return render_form(frontend)

        # Save the form to get an id if there is not already one
        frontend = form.save(commit=False)
        frontend.configuration = {}

        if frontend.mode == "impcap":
            node_listeners[frontend.impcap_intf.node] = []
        elif frontend.listening_mode == "file":
            node_listeners[frontend.node] = []
        elif frontend.listening_mode == "api":
            # Listen on all nodes in case of a master mongo change
            for node in Node.objects.all():
                node_listeners[node] = []

        # At least one Listener is required if Frontend enabled, except for listener of type "File", "pcap" and "API"
        if not listener_objs and frontend.enabled and frontend.mode != "impcap" and frontend.listening_mode not in ("file", "api"):
            form.add_error(None, "At least one listener is required if frontend is enabled.")
            return render_form(frontend)

        try:
            """ For each node, the conf differs if listener chosen """
            """ Generate the conf """
            logger.debug("Generating conf of frontend '{}'".format(frontend.name))
            for node, listeners in node_listeners.items():
                # HAProxy conf does not use reputationctx_list, Rsyslog conf does
                frontend.configuration[node.name] = frontend.generate_conf(listener_list=listeners,
                                                                           header_list=header_objs)
            """ Save the conf on disk, and test-it with haproxy -c """
            logger.debug("Writing/Testing conf of frontend '{}'".format(frontend.name))
            frontend.test_conf()
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

                """ If the ruleset has changed, we need to delete the old-named file """
                if frontend.mode == "log" and "ruleset" in changed_data and old_rsyslog_filename:

                    # API request deletion of rsyslog frontend filename
                    Cluster.api_request('services.rsyslogd.rsyslog.delete_conf', old_rsyslog_filename)
                    logger.info("Rsyslogd config '{}' deletion asked.".format(old_rsyslog_filename))

                """ If it is an Rsyslog only conf """
                if (frontend.mode == "log" and frontend.listening_mode in ("udp", "file", 'api')) \
                        or frontend.mode == "impcap":

                    """ And if it was not before saving """
                    if "mode" in changed_data or "listening_mode" in changed_data:
                        """ Delete old HAProxy conf """
                        frontend_filename = frontend.get_base_filename()

                        # API request deletion of frontend filename
                        Cluster.api_request('services.haproxy.haproxy.delete_conf', frontend_filename)
                        logger.info("HAProxy config '{}' deletion asked.".format(frontend_filename))

                        # And reload of HAProxy service
                        Cluster.api_request('services.haproxy.haproxy.reload_service')

                    """ If it is an HAProxy only conf """
                elif frontend.mode not in ("log", "impcap") and not frontend.enable_logging:
                    """ And it was not """
                    if "mode" in changed_data or "enable_logging" in changed_data:
                        # API request deletion of rsyslog frontend filename
                        Cluster.api_request('services.rsyslogd.rsyslog.delete_conf', old_rsyslog_filename)
                        logger.info("Rsyslogd config '{}' deletion asked.".format(old_rsyslog_filename))

                        # And reload of Rsyslog service
                        Cluster.api_request('services.rsyslogd.rsyslog.restart_service')

            except Exception as e:
                logger.exception(e)
                return render_form(frontend, save_error=["Cluster API request failure: {}".format(e),
                                                         str.join('', format_exception(*exc_info()))])

        if form.errors:
            logger.error("Frontend form errors: {}".format(form.errors))
            return render_form(frontend)

        """ If the conf is OK, save the Frontend object """
        # Is that object already in db or not
        first_save = not frontend.id
        try:
            if frontend.mode == "http":
                frontend.ruleset = "haproxy"
            elif frontend.mode == "tcp":
                frontend.ruleset = "haproxy_tcp"
            elif frontend.mode == "impcap":
                frontend.ruleset = "impcap"

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
            frontend.save()
            logger.debug("Frontend '{}' (id={}) saved in MongoDB.".format(frontend.name, frontend.id))

            """ And all the listeners early created """
            for l in listener_objs:
                l.frontend = frontend
                logger.debug("Saving listener {}".format(str(l)))
                l.save()

            """ Delete listeners deleted in form """
            for l in frontend.listener_set.exclude(pk__in=[l.id for l in listener_objs]):
                l.delete()
                logger.info("Deleting listener {}".format(l))

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

            # Re-generate config AFTER save, to get ID
            for node, listeners in node_listeners.items():
                frontend.configuration[node.name] = frontend.generate_conf(listener_list=listeners)

            for node in node_listeners.keys():
                """ asynchronous API request to save conf on node """
                # Save conf first, to raise if there is an error
                frontend.save_conf(node)
                logger.debug("Write conf of frontend '{}' asked on node '{}'".format(frontend.name, node.name))

                """ We need to configure Rsyslog, it will check if conf has changed & restart service if needed """
                api_res = node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.id)
                if not api_res.get('status'):
                    raise ServiceConfigError("on node {}\n API request error.".format(node.name), "rsyslog",
                                             traceback=api_res.get('message'))

                if not frontend.rsyslog_only_conf:
                    """ Reload HAProxy service - After rsyslog to prevent logging crash """
                    api_res = node.api_request("services.haproxy.haproxy.reload_service")
                    if not api_res.get('status'):
                        raise ServiceReloadError("on node {}\n API request error.".format(node.name), "haproxy",
                                                 traceback=api_res.get('message'))
                    frontend.status[node.name] = "WAITING"
                    frontend.save()

            # Check if reload logrotate conf if needed
            # meaning if there is a log_forwarder file enabled used by this frontend
            if frontend.enable_logging and (frontend.log_forwarders.filter(logomfile__enabled=True).count() > 0 or
                                            frontend.log_forwarders_parse_failure.filter(logomfile__enabled=True).count()):
                # Reload LogRotate config
                Cluster.api_request("services.logrotate.logrotate.reload_conf")

        except (VultureSystemError, ServiceError) as e:
            """ Error saving configuration file """
            """ The object has been saved, delete-it if needed """
            if first_save:
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
        return HttpResponseRedirect('/services/frontend')

    return render_form(frontend)


def frontend_start(request, object_id, api=False):
    if not request.is_ajax() and not api:
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
    if not request.is_ajax() and not api:
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
