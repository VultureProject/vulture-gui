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
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.http.response import HttpResponseNotFound
from django.shortcuts import render
from django.urls import reverse

# Django project imports
from gui.forms.form_utils import DivErrorList
from toolkit.api.responses import build_response

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from authentication.user_portal.form import UserAuthenticationForm
from authentication.user_portal.models import UserAuthentication, RepoAttributesForm, RepoAttributes
from services.frontend.models import Listener
from services.frontend.form import ListenerForm
from system.cluster.models  import Cluster
from system.pki.models import X509Certificate, PROTOCOLS_TO_INT
from portal.system.sso_clients import SSOClient
from toolkit.http.utils import parse_html
from authentication.openid.models import OpenIDRepository

# Extern modules imports
from json import loads as json_loads
from traceback import format_exception
from sys import exc_info
import ssl
import json

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
    profile.name = "Copy_of_" + str(profile.name)

    form = UserAuthenticationForm(None, instance=profile, error_class=DivErrorList)

    return render(request, 'authentication/user_authentication_edit.html', {'form': form})


def user_authentication_edit(request, object_id=None, api=False):
    profile = None
    repo_attrs_form_list = []
    repo_attrs_objs = []
    if object_id:
        try:
            profile = UserAuthentication.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseNotFound("Object not found")

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

        if not repo_attrs_form_list and profile:
            for p in profile.get_repo_attributes():
                repo_attrs_form_list.append(RepoAttributesForm(instance=p))

        return render(request, 'authentication/user_authentication_edit.html',
                      {'form': form,
                       'repo_attributes': repo_attrs_form_list,
                       'repo_attribute_form': RepoAttributesForm(),
                       **kwargs})


    if request.method in ("POST", "PUT"):
        """ Handle repo attributes (user scope) """
        try:
            if api and hasattr(request, "JSON"):
                repo_attrs = request.JSON.get('repo_attributes', [])
                assert isinstance(repo_attrs, list), "Repo attributes field must be a list."
            else:
                repo_attrs = json_loads(request.POST.get('repo_attributes', "[]"))
        except Exception as e:
            if api:
                return JsonResponse({
                    "error": "".join(format_exception(*exc_info()))
                }, status=400)
            return render_form(profile, save_error=["Error in Repo_Attributes field : {}".format(e),
                                                           str.join('', format_exception(*exc_info()))])

        """ For each Health check header in list """
        for repo_attr in repo_attrs:
            repoattrform = RepoAttributesForm(repo_attr, error_class=DivErrorList)
            if not repoattrform.is_valid():
                if api:
                    form.add_error(None, repoattrform.errors.get_json_data())
                else:
                    form.add_error('repo_attributes', repoattrform.errors.as_ul())
                continue
            # Save forms in case we re-print the page
            repo_attrs_form_list.append(repoattrform)
            repo_attrs_objs.append(repoattrform.save(commit=False))

        if form.is_valid():
            # Check changed attributes before form.save
            repo_changed = "repositories" in form.changed_data
            external_fqdn_changed = "external_fqdn" in form.changed_data
            # Save the form to get an id if there is not already one
            profile = form.save(commit=False)
            for repo_attr in repo_attrs_objs:
                repo_attr.save()
            profile.repo_attributes = repo_attrs_objs
            profile.save()

            # If standalone IDP portal (enable_external)
            if profile.enable_external:
                # Automatically create OpenID repo
                openid_repo, created = OpenIDRepository.objects.get_or_create(client_id=profile.oauth_client_id,
                                                                              client_secret=profile.oauth_client_secret,
                                                                              provider="openid")
                openid_repo.provider_url = "https" if profile.external_listener.has_tls else "http" + "://" + profile.external_fqdn
                openid_repo.name = "Connector {}".format(profile.name)
                openid_repo.save()

            try:
                if repo_changed and profile.workflow_set.count() > 0:
                    for workflow in profile.workflow_set.all():
                        workflow.frontend.reload_conf()
                if profile.enable_external:
                    profile.external_listener.reload_conf()
                Cluster.api_request("authentication.user_portal.api.write_templates", profile.id)
                profile.save_conf()
                Cluster.api_request("services.haproxy.haproxy.reload_service")
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
            tls_check = request.POST.get('sso_forward_tls_check')
            url = request.POST['sso_forward_url']
            user_agent = request.POST.get('sso_forward_user_agent') or request.META.get('HTTP_USER_AGENT')
            redirect_before = request.POST.get('sso_forward_follow_redirect_before')

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
        sso_client = SSOClient(user_agent, [], request.META.get('HTTP_REFERER'), ssl_client_certificate, ssl_context,
                               verify_certificate=tls_check)
        url, response = sso_client.get(url, redirect_before)
        forms = parse_html(response.content, url)

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
