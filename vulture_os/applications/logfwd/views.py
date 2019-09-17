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
__doc__ = 'Log Forwarders View'


# Django system imports
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.db.models.deletion import ProtectedError
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext_lazy as _
from django.views.generic import View

# Django project imports
from applications.logfwd.form import (LogOMFileForm, LogOMRELPForm, LogOMHIREDISForm, LogOMFWDForm,
                                      LogOMElasticSearchForm, LogOMMongoDBForm)
from applications.logfwd.models import LogOM, LogOMFile, LogOMRELP, LogOMHIREDIS, LogOMFWD, LogOMElasticSearch, LogOMMongoDB
from gui.forms.form_utils import DivErrorList
from services.frontend.models import Frontend, Listener
from system.cluster.models import Node
from toolkit.api.responses import build_response

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.exceptions import ServiceConfigError

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


LOGFWD_MODELS = {
    'File': LogOMFile,
    'RELP': LogOMRELP,
    'Redis': LogOMHIREDIS,
    'Syslog': LogOMFWD,
    'Elasticsearch': LogOMElasticSearch,
    'MongoDB': LogOMMongoDB
}

LOGFWD_FORMS = {
    'File': LogOMFileForm,
    'RELP': LogOMRELPForm,
    'Redis': LogOMHIREDISForm,
    'Syslog': LogOMFWDForm,
    'Elasticsearch': LogOMElasticSearchForm,
    'MongoDB': LogOMMongoDBForm
}


def logfwd_clone(request, fw_type, object_id):
    """ LogFwd view used to clone an object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints
 
    :param request: Django request object
    :param fw_type:    Type of LogOM object
    :param object_id: MongoDB object_id of a LogOM object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return logfwd_edit(request, fw_type)

    """ Retrieve the object with given object id and type """
    try:
        log_om = LOGFWD_MODELS[fw_type].objects.get(pk=object_id)
    except KeyError as e:
        logger.exception(e)
        return HttpResponseForbidden("LogForwarder type not found.")
    except ObjectDoesNotExist as e:
        logger.exception(e)
        return HttpResponseForbidden("LogForwarder' id not found.")

    log_om.pk = None
    log_om.name = "Copy_of_" + str(log_om.name)

    form = LOGFWD_FORMS[fw_type](instance=log_om, error_class=DivErrorList)

    return render(request, 'apps/logfwd_{}.html'.format(LOGFWD_MODELS[fw_type].__name__), {'form': form})


def logfwd_edit(request, fw_type, object_id=None, api=False):
    """ """
    """ Retrieve the object with given object id and type, or create a new one """
    try:
        if object_id:
            log_om = LOGFWD_MODELS[fw_type].objects.get(pk=object_id)
            if request.method in ("POST", "PUT") and log_om.internal:
                if api:
                    return JsonResponse({'error': _("You cannot edit an internal Log Forwarder.")}, status=403)
                else:
                    return HttpResponseForbidden("An internal log forwarder is not editable.")
        else:
            log_om = LOGFWD_MODELS[fw_type]()
    except KeyError as e:
        logger.exception(e)
        if api:
            return JsonResponse({'error': _("Type does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected.")
    except ObjectDoesNotExist as e:
        logger.exception(e)
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected.")

    if hasattr(request, "JSON") and api:
        form = LOGFWD_FORMS[fw_type](request.JSON or None, instance=log_om, error_class=DivErrorList)
    else:
        form = LOGFWD_FORMS[fw_type](request.POST or None, instance=log_om, error_class=DivErrorList)

    if request.method in ("POST", "PUT") and form.is_valid():
        # Save the form to get an id if there is not already one
        log_om = form.save(commit=False)
        log_om.save()

        """ After saving, reload the Rsyslog conf of all Frontends that uses this LogForwarder """
        """ For each node """
        for node in Node.objects.all().only():
            """ If the LogForwarder is used by an enable frontend on this node """
            frontends = []
            # FIXME : Add .distinct("frontend"):
            for listener in Listener.objects.filter(frontend__log_forwarders=log_om.id,
                                                    network_address__nic__node=node.id).distinct():
                if listener.frontend.id not in frontends:
                    api_res = node.api_request("services.rsyslogd.rsyslog.build_conf", listener.frontend.id)
                    if not api_res.get('status'):
                        raise ServiceConfigError("on node {}\n API request error.".format(node.name), "rsyslog",
                                                 traceback=api_res.get('message'))
                    frontends.append(listener.frontend.id)

        if api:
            return build_response(log_om.id, "applications.logfwd.api", COMMAND_LIST)
        return HttpResponseRedirect('/apps/logfwd')

    if api:
        return JsonResponse(form.errors.get_json_data(), status=400)
    return render(request, 'apps/logfwd_{}.html'.format(LOGFWD_MODELS[fw_type].__name__), {'form': form})


def logfwd_delete(request, fw_type, object_id, api=False):
    """  """
    """ Retrieve the object with given object id and type """

    error = None

    try:
        log_om = LOGFWD_MODELS[fw_type].objects.get(pk=object_id)
        if log_om.internal:
            if api:
                return JsonResponse({'error': _("You cannot edit an internal Log Forwarder.")}, status=403)
            else:
                return HttpResponseForbidden("An internal log forwarder is not editable.")
    except KeyError as e:
        logger.exception(e)
        if api:
            return JsonResponse({'error': _("Type does not exist.")}, status=404)
        return HttpResponseForbidden("LogForwarder type not found.")
    except ObjectDoesNotExist as e:
        logger.exception(e)
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("LogForwarder' id not found.")

    """ Verify if the LogOM is used by a frontend """
    used_frontends = []
    for frontend in Frontend.objects.all().only('name', 'log_forwarders'):
        if frontend.log_forwarders.filter(pk=object_id):
            used_frontends.append(frontend.name)

    if ((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes")
        or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")) \
            and not used_frontends:

        try:
            # Delete the object
            log_om.delete()

            if api:
                return JsonResponse({
                        'status': True
                    }, status=204)
            return HttpResponseRedirect('/apps/logfwd')
        except ProtectedError as e:
            logger.error("Error trying to delete Log Forwarder '{}': Object is currently used :".format(log_om.name))
            logger.exception(e)
            error = "Object is currently used, cannot be deleted"

    elif used_frontends and api:
        return JsonResponse({'error': _("The log forwarder is currently used by frontend : {}".format(used_frontends))},
                            status=403)

    """ If we arrive here, something went wrong """
    if api:
        return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)

    return render(request, "generic_delete.html",
    {
        'obj_inst': log_om,
        'used_by': used_frontends,
        'error': error,
        'redirect_url': '/apps/logfwd/',
        'menu_name': 'Applications -> Logs Forwarder -> Delete'
    })


def logfwd_enable(request, fw_type, object_id):
    raise NotImplementedError()

def logfwd_disable(request, fw_type, object_id):
    raise NotImplementedError()


COMMAND_LIST = {
    'enable': logfwd_enable,
    'disable': logfwd_disable,
}
