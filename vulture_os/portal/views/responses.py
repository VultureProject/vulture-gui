#!/usr/bin/python
#-*- coding: utf-8 -*-
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
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "3.0.0"
__maintainer__ =\
    "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Django views used to render authentication responses'


# Django system imports
from django.http                  import HttpResponse, HttpResponseRedirect, HttpResponseServerError
from django.shortcuts             import render
from django.template              import RequestContext
from django.views.decorators.gzip import gzip_page

# Extern modules imports
from base64 import b64encode
from io import StringIO
from os.path import dirname
from qrcode import make as qrcode_make

# Global variables
BASE_DIR = dirname(dirname(__file__))




def split_domain(url):
	""" Split an url and return the 2 last domains
	Example : for http://vulture.testing.tr/index.html it will return .testing.tr
	          for http://moodle.lan:81 it will return .moodle.lan
	"""
	tmp = url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
	if tmp.count('.') == 1:
		return '.'+tmp
	return '.'+'.'.join(tmp.split('.')[-tmp.count('.'):])


def set_portal_cookie(response, portal_cookie_name, portal_cookie, url):
	response.set_cookie(portal_cookie_name, portal_cookie, domain=split_domain(url), httponly=True, secure=url.startswith('https'))
	return response


@gzip_page
def create_gzip_response(request, content):
	return HttpResponse(content)


def response_redirect_with_portal_cookie(url, portal_cookie_name, portal_cookie, cookie_secure, kerberos_resp=None):
	response = HttpResponseRedirect(url)
	if not portal_cookie:
		return HttpResponseServerError()

	if kerberos_resp:
		response['WWW-Authenticate'] = 'Negotiate '+str(kerberos_resp)
	response.set_cookie(portal_cookie_name, portal_cookie, domain=split_domain(url), httponly=True, secure=cookie_secure)
	return response


def basic_authentication_response(app_name):
	response                     = HttpResponse()
	response.status_code         = 401
	response.reason_phrase       = "Unauthorized"
	response['WWW-Authenticate'] = 'Basic realm="{}"'.format(app_name)
	with open(BASE_DIR+'/templates/portal/401.html', 'r') as fd:
		response.write(fd.read())
	return response


def kerberos_authentication_response():
	response = basic_authentication_response('None')
	response['WWW-Authenticate'] = 'Negotiate'
	return response


def render_input(i_type, name, i_class=None, placeholder=None, value=None, required=False):
	result      = '<input type="{}" name="{}"'.format(i_type, name)
	if i_class:
		result += ' class="{}"'.format(i_class)
	if placeholder:
		result += ' placeholder="{}"'.format(placeholder)
	if value:
		result += ' value="{}"'.format(value)
	if required:
		result += ' required'
	result     += ' />'
	return result

def render_stylesheet(href):
	return "<link rel='stylesheet' type='text/css' href='{}'/>".format(href)

def render_form(action, method="POST"):
	return "<form action='{}' method='{}' autocomplete='off' class='form-signin'>".format(action, method)

def render_button(b_class, text, type="submit", name="", value=""):
	return '<button class="{}" type="{}" name="{}" value="{}">{}</button>'.format(b_class, type, name, value, text)


#def post_authentication_response(request, template, action_url, public_dir, token_name, b64_generated_captcha, error=""):
def post_authentication_response(request, portal, public_dir, catpcha=None, error="", **kwargs):
	lostPassword   = '{}/self/lost'.format(public_dir.rstrip("/"))
	return HttpResponse(portal.render_template("html_login",
												 lostPassword=lostPassword,
												 catpcha=catpcha,
												 error_message=error,
												 **kwargs))


def error_response(portal, error):
	return HttpResponse(portal.render_template("html_error", message=error))


def disconnect_response(request, portal, app_url):
	return HttpResponse(portal.render_template("html_logout", app_url=app_url))


def otp_authentication_response(request, template_id, app_id, action_url, token_name, token, otp_type, qrcode, error=""):
	style 		  = render_stylesheet('{}/{}/templates/portal_{}.css'.format(str(action_url), str(token_name), str(template_id)))
	form_begin	  = render_form('{}{}/{}'.format(str(action_url), str(token_name), str(token)))
	form_begin   += render_input('hidden', 'token', value='')
	form_end      = '</form>'
	input_submit  = render_button('btn btn-lg btn-warning btn-block btn-signin', 'Sign in')
	input_submit += render_input('hidden', 'vulture_two_factors_authentication', value=str(app_id))
	input_key     = render_input('text', 'vltprtlkey', i_class='form-control', placeholder='Key', required=True)

	otp_item_sent = {'onetouch': 'OneTouch request', 'phone': 'sms', 'email': 'mail'}
	resend_button = render_button("btn btn-lg btn-warning btn-block btn-signin",
								  'Resend ' + otp_item_sent[str(otp_type)], name="vltotpresend",
								  value="yes") \
					+ render_input('hidden', 'vulture_two_factors_authentication', value=str(app_id)) \
					if otp_item_sent.get(str(otp_type)) else ""

	if otp_type == 'onetouch':
		input_key  = render_input('hidden', 'vltprtlkey', i_class='form-control', placeholder='Key', value="Key", required=True)
		input_key += "<p>Please approve the OneTouch request on your phone, and click on 'Sign in'</p>"

	qrcode_img = ""
	if qrcode:
		qrcode_pil = qrcode_make(qrcode)
		buf = StringIO()
		qrcode_pil.save(buf, format="JPEG")
		qrcode_base64 = b64encode(buf.getvalue())
		qrcode_img = 'src="data:image/jpeg;base64, {}"'.format(qrcode_base64)

	error_message = error or ""
	return render_to_response("portal_%s_html_otp.conf" % (str(template_id)),
	                          {'style':style, 'form_begin':form_begin, 'input_key':input_key,
	                          'form_end':form_end, 'input_submit':input_submit, 'resend_button':resend_button,
	                          'qrcode': qrcode_img,'error_message':error_message},
	                          context_instance=RequestContext(request))


def learning_authentication_response(request, template_id, action_url, token, fields_to_learn, error=None):
	style      = render_stylesheet('{}/{}/templates/portal_{}.css'.format(str(action_url), str(token_name), str(template_id)))
	form_begin = render_form('{}{}/{}'.format(str(action_url), str(token_name), str(token)))
	form_end   = '</form>'

	input_submit = ""
	for field_name, field_type in fields_to_learn.items():
		input_submit += render_input(field_type, field_name, i_class='form-control', placeholder=field_name)

	input_submit  += render_button('btn btn-lg btn-warning btn-block btn-signin', 'Sign in')
	error_message = error or ""

	return render_to_response ("portal_%s_html_learning.conf" % (str(template_id)),
	                               {'style':style, 'form_begin':form_begin,
	                                'form_end':form_end, 'input_submit':input_submit, 'error_message':error_message},
	                               context_instance=RequestContext(request))


def self_ask_passwords(request, application, token_name, rdm, action, error_msg):
	if rdm:
		input_password_old = render_input('text', 'rdm', value=rdm, i_class='form-control')
	else:
		input_password_old = render_input('password', 'password_old', placeholder='Old password', i_class='form-control', required=True)

	input_password_1 = render_input('password', 'password_1', placeholder='New password', i_class='form-control', required=True)
	input_password_2 = render_input('password', 'password_2', placeholder='Confirmation', i_class='form-control', required=True)
	input_email      = render_input('email', 'email', placeholder='Email', i_class='form-control', required=True)

	input_submit = render_button('btn btn-lg btn-warning btn-block btn-signin', text="Ok")
	style 		 = render_stylesheet('/{}/templates/portal_{}.css'.format(str(token_name), str(application.template.id)))
	form_begin   = render_form('{}{}/self/{}'.format(str(application.public_dir), str(token_name), action))
	form_end     = '</form>'
	error_mess   = error_msg or ""

	return render_to_response("portal_%s_html_password.conf" % (str(application.template.id)),
							  {'style': style, 'dialog_change': action=="change", 'dialog_lost': action=="lost",
							   'dialog_lost_sent': False, 'form_begin': form_begin, 'form_end': form_end, # dialog_lost_sent ???
							   'input_password_old': input_password_old, 'input_password_1': input_password_1,
							   'input_password_2': input_password_2, 'input_submit': input_submit,
							   'input_email': input_email, 'error_message': error_mess},
							  context_instance=RequestContext(request))


def self_message_response(application, token_name, message):
	style = render_stylesheet('/{}/templates/portal_{}.css'.format(str(token_name), str(application.template.id)))
	link_redirect = application.get_redirect_uri()
	return render_to_response("portal_%s_html_message.conf" % str(application.template.id),
							  {'style': style, 'link_redirect': link_redirect, 'message': message})


def self_message_main(request, application, token_name, app_list, username, error=None):
	"""  """
	""" Build the URL to change password """
	changePassword = str(application.get_redirect_uri()) + str(token_name) + '/self/change'
	""" Build the URL to general logout """
	general_logout = str(application.get_redirect_uri()) + str(token_name) + '/self/logout'
	style = '<link rel="stylesheet" type="text/css" href="/' + str(token_name) + '/templates/portal_%s.css">' % (str(application.template.id))
	form_begin = '<form action="' + str(application.public_dir) + str(token_name) + '/self' + '/' + str(application.id) + '" method="post" autocomplete="off">'
	form_end = '</form>'

	error_messages = {
		"change_ok"  : application.template.error_password_change_ok,
		"change_ko"  : application.template.error_password_change_ko,
		"email_sent" : application.template.error_email_sent
	}

	error_msg = error_messages.get(error, "")

	return render_to_response("portal_%s_html_self.conf" % (str(application.template.id)),
							  {'style': style, 'form_begin': form_begin, 'application_list': app_list,
							   'form_end': form_end, 'changePassword': changePassword, 'error_message': error_msg,
							   'logout': general_logout, 'username': username},
							  context_instance=RequestContext(request))


def register_ask1(request, application, token_name, captcha_key, captcha, error=None):
	"""  """
	style 		  = render_stylesheet('/{}/templates/portal_{}.css'.format(str(token_name), str(application.template.id)))
	form_begin    = render_form('{}{}/register'.format(str(application.public_dir), str(token_name)))
	input_email   = render_input('text', 'vltrgstremail', i_class='form-control', placeholder='Email')
	input_email  += render_input('hidden', 'captcha_token', value=captcha_key)
	input_captcha = render_input('text', 'captcha', i_class='form-control', placeholder='Captcha', required=True)
	captcha       = "<img id='captcha' src='data:image/png;base64,{}' alt='captcha'/>".format(captcha)
	input_submit  = render_button('btn btn-lg btn-warning btn-block btn-signin', text='Ok')
	form_end      = '</form>'
	error_msg = error or ""

	return render_to_response("portal_%s_html_registration.conf" % (str(application.template.id)),
							  {'style': style, 'form_begin': form_begin, 'step1': True, 'step2': False,
							   'input_email': input_email, 'input_submit': input_submit, 'input_captcha': input_captcha,
							   'captcha': captcha, 'form_end': form_end, 'error_message': error_msg},
							  context_instance=RequestContext(request))


def register_ask2(request, application, token_name, register_token, ask_phone, captcha_key, captcha, error=None):
	"""  """
	style 			= render_stylesheet('/{}/templates/portal_{}.css'.format(str(token_name), str(application.template.id)))
	form_begin      = render_form('{}{}/register?registrk={}'.format(str(application.public_dir), str(token_name), register_token))
	captcha         = "<img id='captcha' src='data:image/png;base64,{}' alt='captcha'/>".format(captcha)
	input_captcha   = render_input('text', 'captcha', i_class='form-control', placeholder='Captcha',  required=True)
	input_username  = render_input('text', 'username', i_class='form-control', placeholder='Username', required=True)
	input_username  += render_input('hidden', 'captcha_token', value=captcha_key)
	input_phone     = render_input('text', 'phone', i_class='form-control', placeholder='Phone number')
	input_password1 = render_input('password', 'password1', i_class='form-control', placeholder='Password', required=True)
	input_password2 = render_input('password', 'password2', i_class='form-control', placeholder='Password confirmation', required=True)
	input_submit    = render_button('btn btn-lg btn-warning btn-block btn-signin', text='OK')
	form_end        = '</form>'
	error_msg       = error or ""

	return render_to_response("portal_%s_html_registration.conf" % (str(application.template.id)),
							  {'style': style, 'form_begin': form_begin, 'step1': False, 'step2': True,
							   'input_username': input_username, 'input_phone': input_phone,
							   'input_password_1': input_password1, 'input_password_2': input_password2,
							   'input_submit': input_submit, 'ask_phone': ask_phone, 'input_captcha': input_captcha,
							   'captcha': captcha, 'form_end': form_end, 'error_message': error_msg},
							  context_instance=RequestContext(request))


