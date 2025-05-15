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
__doc__ = 'LDAP Repository views'


# Django system imports
from django.conf import settings
from django.http import HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.http.response import HttpResponseNotFound
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

# Django project imports
from authentication.openid.models import OpenIDRepository
from authentication.user_portal.form import UserAuthenticationForm
from authentication.user_portal.models import UserAuthentication
from portal.system.sso_clients import SSOClient
from system.cluster.models  import Cluster
from system.pki.models import X509Certificate, PROTOCOLS_TO_INT
from toolkit.api.responses import build_response
from toolkit.http.utils import parse_html
from toolkit.system.hashes import random_sha256

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from gui.forms.form_utils import DivErrorList

# Extern modules imports
from traceback import format_exception
from sys import exc_info
from copy import deepcopy
import ssl

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def user_authentication_clone(request, object_id):
    """ UserAuthentication view used to clone an object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints
 
    :param request: Django request object
    :param object_id: MongoDB object_id of a UserAuthentication object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return user_authentication_edit(request)

    try:
        profile = UserAuthentication.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseNotFound("Object not found")

    profile.pk = None
    profile.oauth_client_id = random_sha256
    profile.oauth_client_secret = random_sha256
    profile.name = "Copy_of_" + str(profile.name)

    form = UserAuthenticationForm(None, instance=profile, error_class=DivErrorList)
    return render(request, 'authentication/user_authentication_edit.html', {
                      'form': form
                  })


def user_authentication_edit(request, object_id=None, api=False):
    profile = None
    if object_id:
        try:
            profile = UserAuthentication.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseNotFound(_("Object not found"))

    """ Create form with object if exists, and request.POST (or JSON) if exists """
    # Do NOT remove this line
    empty = {} if api else None
    if hasattr(request, "JSON") and api:
        form = UserAuthenticationForm(request.JSON or {}, instance=profile, error_class=DivErrorList)
    else:
        form = UserAuthenticationForm(request.POST or empty, instance=profile, error_class=DivErrorList)

    def render_form(profile, **kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                return JsonResponse({'error': save_error[0]}, status=500)

        return render(request, 'authentication/user_authentication_edit.html',
                      {'form': form,
                       **kwargs})


    if request.method in ("POST", "PUT"):
        # External portal is not compatible with Workflow
        # If enable_external has been enabled but a workflow uses this Portal, add error in form
        if form.data.get('enable_external') and profile and profile.workflow_set.count() > 0:
            form.add_error('enable_external', "This portal is used by a Workflow, you can't enable IDP. Please create another Portal or disable this one in Workflow.")

        old_external_frontend = deepcopy(profile.external_listener) if profile and profile.enable_external else None

        if form.is_valid():
            # Check changed attributes before form.save
            repo_changed = "repositories" in form.changed_data
            disconnect_url_changed = "disconnect_url" in form.changed_data
            timeout_changed = "auth_timeout" in form.changed_data or "enable_timeout_restart" in form.changed_data
            external_listener_changed = "external_listener" in form.changed_data and profile and profile.enable_external
            # Save the form to get an id if there is not already one
            profile = form.save(commit=False)
            profile.save()

            try:
                if (repo_changed or disconnect_url_changed or timeout_changed) and profile.workflow_set.count() > 0:
                    for workflow in profile.workflow_set.all():
                        nodes = workflow.frontend.reload_conf()

                if profile.enable_external:
                    # Automatically create OpenID repo
                    openid_repo, _ = OpenIDRepository.objects.get_or_create( client_id=profile.oauth_client_id,
                                                            client_secret=profile.oauth_client_secret,
                                                            provider="openid",
                                                            defaults={
                                                                'provider_url': f"https://{profile.external_fqdn}",
                                                                'name': "Connector_{}".format(profile.name)
                                                            })
                    openid_repo.provider_url = f"https://{profile.external_fqdn}"
                    openid_repo.save()
                    # Reload old external_listener conf if has changed
                    if external_listener_changed:
                        old_external_frontend.reload_conf()
                    profile.external_listener.reload_conf()

                Cluster.api_request("authentication.user_portal.api.write_templates", profile.id)
                profile.save_conf()
                Cluster.api_request("services.haproxy.haproxy.reload_service", run_delay=settings.SERVICE_RESTART_DELAY)

            except Exception as e:
                if api:
                    return JsonResponse({
                        "error": "".join(format_exception(*exc_info()))
                    }, status=400)

                return render_form(profile, save_error=["Cannot write configuration: {}".format(e),
                                                                                   str.join('', format_exception(*exc_info()))])

            # If everything succeed, redirect to list view
            if api:
                return build_response(profile.id, "api.portal.user_authentication", [])
            return HttpResponseRedirect(reverse("portal.user_authentication.list"))

    return render_form(profile)


# TODO @group_required('administrator', 'system_manager')
#@group_required('administrator', 'application_manager', 'security_manager')
def sso_wizard(request):
    """ View dedicated to create a JSON structure for SSO Forward
    ;param uri: URL where the login form is
    ;param sso_vulture_agent: If set to "true", use internal Vulture user-agent instead of the one send by the user browser
    """
    if request.method == 'POST':
        try:
            tls_proto = request.POST.get('sso_forward_tls_proto')
            tls_cert = request.POST.get('sso_forward_tls_cert')
            tls_check = request.POST.get('sso_forward_tls_check') == "on"
            url = request.POST['sso_forward_url']
            user_agent = request.POST.get('sso_forward_user_agent') or request.headers.get('user-agent')
            redirect_before = request.POST.get('sso_forward_follow_redirect_before')
            sso_timeout = int(request.POST.get('sso_forward_timeout', '10'))

        except KeyError as e:
            return JsonResponse({'status': False, 'reason': "Missing field : {}".format(str(e))})

    else:
        return HttpResponseForbidden()

    ssl_context = None
    ssl_client_certificate = None
    if url[:5] == "https" and tls_proto not in ('', 'None', None):
        ssl_context = ssl.SSLContext()
        ssl_context.minimum_version = PROTOCOLS_TO_INT[tls_proto]
        if tls_cert:
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_client_certificate = X509Certificate.objects.get(pk=tls_cert).bundle_filename
        else:
            ssl_context.verify_mode = ssl.CERT_NONE

    """ Transform uri as list - to test multiple uris in case of balanced app """
    uris = [url]
    # if type != "balanced":
    #     if "[]" in uri:
    #         uri = uri.replace("[]", private_uri).replace("\[", '[').replace("\]", ']')
    #     else:
    #         uri = uri.replace("\[", '[').replace("\]", ']')
    #     uris.append(uri)
    # else:
    #     if "[]" not in uri:
    #         uris.append(uri.replace("\[", '[').replace("\]", ']'))
    #     else:
    #         for proxybalancer_member in proxy_balancer.members:
    #             # Concatenate scheme and uri, and remove public dir but keep port
    #             backend_uri = "{}://{}".format(proxybalancer_member.uri_type, proxybalancer_member.uri.split('/')[0])
    #             uri_tmp = uri.replace('[]', backend_uri)
    #             uri_tmp = uri_tmp.replace('\[', "[").replace('\]', ']')
    #             uris.append(uri_tmp)

    try:
        # Directly use portal classes
        sso_client = SSOClient(user_agent, [], request.headers.get('referer'), ssl_client_certificate, ssl_context,
                               verify_certificate=tls_check, timeout=sso_timeout)
        url, response = sso_client.get(url, redirect_before)
        forms = parse_html(response.text, url)

        # forms, final_uri, response, response_body = fetch_forms(logger, uris, request, user_agent,
        #                                                         ssl_context=ssl_context,
        #                                                         proxy_client_side_certificate=ssl_client_certificate)
        form_list = list()
        i = 0
        # Retrieve attributes from robobrowser.Form objects
        for f in forms:
            if str(f.method).upper() == "POST":
                control_list = list()
                for field_name, field in f.fields.items():
                    if isinstance(field._parsed, list):
                        tag = field._parsed[0]
                    else:
                        tag = field._parsed
                    # field is a robobrowser.forms.fields.Input object
                    # field._parsed is a bs4.element.Tag object
                    control_list.append({'name': tag.attrs.get('name', ""), 'id': tag.attrs.get('id', ""),
                                         'type': tag.attrs.get('type'), 'value': tag.attrs.get('value', "")})
                form_list.append({'name': f.parsed.get('name', ""), 'id': i, 'controls': control_list})
                i += 1
        response = {'status': True, 'forms': form_list}
    except TypeError as error:
        logger.exception(error)
        response = {'status': False, 'reason': "No form detected in uri(s) {} : {}".format(uris, error)}
    except Exception as error:
        logger.exception(error)
        response = {'status': False, 'reason': str(error)}

    return JsonResponse(response)



def idp_view(request, object_id):
    return render(request, 'authentication/idp_view.html', {"object_id": object_id})
