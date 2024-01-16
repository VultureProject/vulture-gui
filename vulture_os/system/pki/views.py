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
__doc__ = 'Network View'


# Django system imports
from django.conf import settings
from django.http import HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.http.response import HttpResponseNotFound
from django.shortcuts import render, HttpResponse
from django.utils.translation import gettext_lazy as _
from django.urls import reverse

# Django project imports
from gui.forms.form_utils import DivErrorList
from system.exceptions import VultureSystemConfigError
from system.pki.form import TLSProfileForm, X509ExternalCertificateForm, X509InternalCertificateForm
from system.pki.models import CIPHER_SUITES, PROTOCOLS_HANDLER, TLSProfile, X509Certificate
from system.cluster.models import Cluster
from toolkit.api.responses import build_response, build_form_errors
from services.frontend.models import Listener
from applications.backend.models import Server

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist

# Extern modules imports
from sys import exc_info
from traceback import format_exception

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def pki_getcert(request, object_id):
    try:
        x509_model = X509Certificate.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    response = HttpResponse(x509_model.cert, content_type='application/force-download')
    response['Content-Disposition'] = 'attachment; filename=' + str(x509_model.name) + '.pem'
    return response


def pki_getbundle(request, object_id):
    try:
        x509_model = X509Certificate.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    response = HttpResponse(x509_model.as_bundle(), content_type='application/force-download')
    response['Content-Disposition'] = 'attachment; filename=' + str(x509_model.name).replace(" ", "_") + '.pem-bundle'
    return response


def pki_getcrl(request, object_id):
    try:
        x509_model = X509Certificate.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    response = HttpResponse(x509_model.get_crl(), content_type='application/force-download')
    response['Content-Disposition'] = 'attachment; filename=' + str(x509_model.name).replace(" ", "_") + '.crl'
    return response


def pki_gencrl(request, object_id):
    try:
        x509_model = X509Certificate.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    try:
        x509_model.gen_crl()
    except Exception as e:
        logger.error("PKI::genCRL: {}".format(str(e)))
        pass

    return HttpResponseRedirect('/system/pki/')


def pki_revoke(request, object_id):
    try:
        x509_model = X509Certificate.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseNotFound(_("Object not found"))

    x509_model.revoke()

    return HttpResponseRedirect('/system/pki/')


def pki_edit(request, object_id=None):

    x509_model = None
    if object_id:
        try:
            x509_model = X509Certificate.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseNotFound(_("Object not found"))

    """ Default form is External Certificate """
    form = X509ExternalCertificateForm(request.POST or None, instance=x509_model, error_class=DivErrorList)

    """ Internal Vulture Certificate """
    if request.method == "POST" and request.POST.get('type') in ("internal", "letsencrypt"):
        form = X509InternalCertificateForm(request.POST or None, instance=x509_model, error_class=DivErrorList)
        if form.is_valid():
            cn = form.cleaned_data.get('cn')
            name = form.cleaned_data.get('name')

            if form.cleaned_data.get("type") == "letsencrypt":
                X509Certificate().gen_letsencrypt(cn, name)
            elif form.cleaned_data.get("type") == "internal":
                X509Certificate().gen_cert(cn, name)

            return HttpResponseRedirect('/system/pki/')
        else:
            form = X509InternalCertificateForm(request.POST or None, instance=x509_model, error_class=DivErrorList)

    elif request.method == "POST" and form.is_valid() and request.POST.get("type") == "external":

        """ External certificate """
        pki = form.save(commit=False)
        pki.is_external = True
        pki.is_vulture_ca = False
        pki.save()

        """ Reload HAProxy on certificate change """
        if X509Certificate.objects.filter(certificate_of__listener__isnull=False, id=pki.id).exists() or X509Certificate.objects.filter(certificate_of__server__isnull=False, id=pki.id).exists():
            Cluster.api_request("services.haproxy.haproxy.reload_service")
            return HttpResponseRedirect('/system/pki/')

        return HttpResponseRedirect('/system/pki/')

    return render(request, 'system/pki_edit.html', {
        'form': form,
        'is_external': request.POST.get('type') == 'external'
    })


def pki_delete(request, object_id, api=False):
    """ Delete certificate object and remove files """
    error = ""
    try:
        cert = X509Certificate.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    if ((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes")
            or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")):

        try:
            cert.delete_conf()
            # If api request succeed : Delete the object
            cert.delete()

            if api:
                return JsonResponse({
                    'status': True
                }, status=204)
            return HttpResponseRedirect(reverse('system.pki.list'))

        except Exception as e:
            # If API request failure, bring up the error
            logger.error("Error trying to delete certificate '{}': API|Database failure. Details:".format(cert.name))
            logger.exception(e)
            error = "API or Database request failure: {}".format(str(e))

            if api:
                return JsonResponse({'status': False,
                                     'error': error}, status=500)
    if api:
        return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)

    if tls_profiles := cert.certificate_of.all():
        for profile in tls_profiles:
            used_by = set(listener.frontend for listener in profile.listener_set.all()).union(set(server.backend for server in profile.server_set.all()))
    else:
        used_by = []

    # If GET request or POST request and API/Delete failure
    return render(request, 'generic_delete.html', {
        'menu_name': _("System -> X509 Certificate -> Delete"),
        'redirect_url': reverse("system.pki.list"),
        'delete_url': reverse("system.pki.delete", kwargs={'object_id': cert.id}),
        'obj_inst': "certificate '{}'".format(str(cert)),
        'used_by': used_by,
        'error': error
    })


def tls_profile_clone(request, object_id):
    """ Listener view used to clone a Listener object
    :param request: Django request object
    :param object_id: MongoDB object_id of a Listener object
    """
    if not object_id:
        return HttpResponseRedirect('/system/tls_profile/')
    """ Retrieve object from id in MongoDB """
    try:
        tls_profile = TLSProfile.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    """ CHange unique attributes and reset pk """
    tls_profile.pk = None
    tls_profile.name = 'Copy of ' + str(tls_profile.name)

    """ Save the new object """
    tls_profile.save()

    """ Redirect to the tls profiles visualisation page """
    return HttpResponseRedirect("/system/tls_profile/")


def tls_profile_edit(request, object_id=None, api=False):
    """ Django view used to edit a TLSProfile object """
    tls_profile = None
    if object_id:
        try:
            tls_profile = TLSProfile.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                return JsonResponse({
                    "error": _("Object not found")
                }, status=404)
            return HttpResponseNotFound(_("Object not found"))

    if hasattr(request, "JSON"):
        form = TLSProfileForm(request.JSON or None, instance=tls_profile, error_class=DivErrorList)
    else:
        form = TLSProfileForm(request.POST or None, instance=tls_profile, error_class=DivErrorList)

    def render_template(**kwargs):
        return render(request, 'system/tls_profile_edit.html', {'form': form, 'cipher_choices': CIPHER_SUITES,
                                                                'protocols_handler': PROTOCOLS_HANDLER, **kwargs})

    if request.method in ("POST", "PUT") and form.is_valid():
        tls_profile = form.save(commit=False)

        # Is that object already in Mongo
        first_save = not tls_profile.id
        try:
            """ First, save the certificate in Database, to get an id """
            tls_profile.save()
            logger.info("TLSProfile '{}' saved in database.".format(tls_profile.name))
            """ Then save certificates on disk """
            tls_profile.save_conf()
            logger.info("TLSProfile '{}' write on disk requested.".format(tls_profile.name))

            for frontend in set(listener.frontend for listener in tls_profile.listener_set.all()):
                frontend.reload_conf()
                logger.info("Frontend confs reloaded")

            for backend in set(server.backend for server in tls_profile.server_set.all()):
                backend.reload_conf()
                logger.info("Backend confs reloaded")

            if tls_profile.server_set.exists():
                Cluster.api_request("services.haproxy.haproxy.reload_service")

        except VultureSystemConfigError as e:
            """ If we get here, problem occurred during save_conf, after save """
            if first_save:
                tls_profile.delete()
            logger.exception(e)
            if api:
                return JsonResponse({
                    "error": str(e)
                }, status=400)
            return render_template(save_error=[str(e), e.traceback])

        except Exception as e:
            """ If we get here, a problem occurred during save() """
            """ Verify if the new object has been saved, if yes delete it """
            if first_save and tls_profile.id:
                tls_profile.delete()
            logger.exception(e)
            if api:
                return JsonResponse({
                    "error": str(e)
                }, status=400)
            return render_template(save_error=["Unknown error while saving object in database.",
                                               str.join('', format_exception(*exc_info()))])

        """ If all is OK, redirect to TLSProfile list view """
        if api:
            return build_response(tls_profile.pk, "api.system.tls_profile", [])
        return HttpResponseRedirect('/system/tls_profile/')

    if api:
        return JsonResponse({"errors": build_form_errors(form.errors)}, status=400)
    return render_template()
