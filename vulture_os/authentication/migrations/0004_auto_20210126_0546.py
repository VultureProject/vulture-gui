# Generated by Django 2.1.3 on 2021-01-26 05:46

import authentication.user_portal.models
from django.db import migrations, models
import django.db.models.deletion
import djongo.models.fields
import toolkit.system.hashes


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0015_auto_20210305_1048'),
        ('authentication', '0003_auto_20200915_1600'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='ldaprepository',
            name='enable_oauth2',
        ),
        migrations.RemoveField(
            model_name='ldaprepository',
            name='oauth2_attributes',
        ),
        migrations.RemoveField(
            model_name='ldaprepository',
            name='oauth2_token_return',
        ),
        migrations.RemoveField(
            model_name='ldaprepository',
            name='oauth2_token_ttl',
        ),
        migrations.RemoveField(
            model_name='ldaprepository',
            name='oauth2_type_return',
        ),
        migrations.AddField(
            model_name='ldaprepository',
            name='user_smartcardid_attr',
            field=models.TextField(default='', help_text="Attribute which contains user's SmartCard ID",
                                   verbose_name='Smart Card ID attribute'),
        ),
        migrations.CreateModel(
            name='AuthAccessControl',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enabled', models.BooleanField(default=True)),
                ('name', models.TextField(help_text='Friendly name', unique=True, verbose_name='Friendly name')),
                ('rules', djongo.models.fields.ListField(default=[])),
            ],
        ),
        migrations.CreateModel(
            name='PortalTemplate',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.TextField(default='Portal template', help_text='Friendly name to reference the template')),
                ('css', models.TextField(default='/*\n * Specific styles of signin component\n */\n/*\n * General styles\n */\nbody, html {\n    height: 100%;\n    background: #FBFBF0 linear-gradient(135deg, #70848D, #21282E) repeat scroll 0% 0%;\n}\n\n.card-container.card {\n    max-width: 350px;\n    padding: 40px 40px;\n}\n\n#self_service {\n    max-width: 450px;\n    padding: 40px 40px;\n}\n\n.list-group-item {\n    text-align: left;\n}\n\n.btn {\n    font-weight: 700;\n    height: 36px;\n    -moz-user-select: none;\n    -webkit-user-select: none;\n    user-select: none;\n    cursor: default;\n}\n\n/*\n * Card component\n */\n.card {\n    text-align:center;\n    background-color: #F7F7F7;\n    /* just in case there no content*/\n    padding: 20px 25px 30px;\n    margin: 0 auto 25px;\n    margin-top: 50px;\n    /* shadows and rounded borders */\n    -moz-border-radius: 2px;\n    -webkit-border-radius: 2px;\n    border-radius: 2px;\n    -moz-box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);\n    -webkit-box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);\n    box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);\n}\n\n#vulture_img{\n    width:150px;\n}\n\n.form-signin{\n    text-align: center;\n}\n\n#captcha{\n    border:1px solid #c5c5c5;\n    margin-bottom: 10px;\n}\n\n.alert{\n    margin-bottom: 0px;\n    margin-top:15px;\n}\n\n.reauth-email {\n    display: block;\n    color: #404040;\n    line-height: 2;\n    margin-bottom: 10px;\n    font-size: 14px;\n    text-align: center;\n    overflow: hidden;\n    text-overflow: ellipsis;\n    white-space: nowrap;\n    -moz-box-sizing: border-box;\n    -webkit-box-sizing: border-box;\n    box-sizing: border-box;\n}\n\n.form-signin #inputEmail,\n.form-signin #inputPassword {\n    direction: ltr;\n    height: 44px;\n    font-size: 16px;\n}\n\ninput[type=email],\ninput[type=password],\ninput[type=text],\nbutton {\n    width: 100%;\n    display: block;\n    margin-bottom: 10px;\n    z-index: 1;\n    position: relative;\n    -moz-box-sizing: border-box;\n    -webkit-box-sizing: border-box;\n    box-sizing: border-box;\n}\n\n.form-signin .form-control:focus {\n    border-color: rgb(104, 145, 162);\n    outline: 0;\n    -webkit-box-shadow: inset 0 1px 1px rgba(0,0,0,.075),0 0 8px rgb(104, 145, 162);\n    box-shadow: inset 0 1px 1px rgba(0,0,0,.075),0 0 8px rgb(104, 145, 162);\n}\n\n.btn.btn-signin {\n    background-color: #F1A14C;\n    padding: 0px;\n    font-weight: 700;\n    font-size: 14px;\n    height: 36px;\n    -moz-border-radius: 3px;\n    -webkit-border-radius: 3px;\n    border-radius: 3px;\n    border: none;\n    -o-transition: all 0.218s;\n    -moz-transition: all 0.218s;\n    -webkit-transition: all 0.218s;\n    transition: all 0.218s;\n}\n\n.btn.btn-signin:hover{\n    cursor: pointer;\n}\n\n.forgot-password {\n    color: rgb(104, 145, 162);\n}\n\n.forgot-password:hover,\n.forgot-password:active,\n.forgot-password:focus{\n    color: rgb(12, 97, 33);\n}\n', help_text='Cascading Style Sheet for template')),
                ('html_login', models.TextField(default='<!DOCTYPE html>\n<html>\n<head>\n    <meta charset="utf-8"/>\n    <title>Vulture Login</title>\n    <link rel="stylesheet" href="/templates/static/html/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class="container">\n        <div class="card card-container">\n            <form action=\'\' method=\'POST\' autocomplete=\'off\' class=\'form-signin\'>\n                <img id="vulture_img" src="/templates/static/img/vulture-logo-small.png"/>\n                {% if error_message != "" %}\n                  <div class="alert alert-danger" role="alert">{{error_message}}</div>\n                {% endif %}\n                <span id="reauth-email" class="reauth-email"></span>\n                <input type="text" name="{{input_login}}" class="form-control" placeholder="Login" required/>\n                <input type="password" name="{{input_password}}" class="form-control" placeholder="Password" required/>\n                {% if captcha %}\n                    {{captcha}}\n                    <input type="text" name="{{input_captcha}}" class="form-control" placeholder="Captcha" required/>\n\n                {% endif %}\n                <button class="btn btn-lg btn-warning btn-block btn-signin" type="submit">{{login_submit_field}}</button>\n                {% for repo in openid_repos %}\n                <a href="{{repo.start_url}}">Login with {{repo.provider}}</a>\n                {% endfor %}\n                <a href="{{lostPassword}}">Forgotten password ?</a>\n            </form>\n        </div>\n    </div>\n </body>\n</html>', help_text='HTML Content for the login page')),
                ('html_learning', models.TextField(default='<!DOCTYPE html>\n<html>\n <head>\n    <meta charset="utf-8" />\n    <title>Vulture Learning</title>\n    <link rel="stylesheet" href="/templates/static/html/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">\n    {{style}}\n </head>\n <body>\n    <div class="container">\n        <div class="card card-container" style="text-align:center;">\n            <p>Learning form</p>\n            {{form_begin}}\n                {{input_submit}}\n            {{form_end}}\n        </div>\n    </div>\n </body>\n</html>', help_text='HTML Content for the learning page')),
                ('html_logout', models.TextField(default='<!DOCTYPE html>\n<html>\n <head>\n    <meta charset="utf-8" />\n    <title>Vulture Logout</title>\n     <link rel="stylesheet" href="//templates/static/html/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">\n     {{style}}\n </head>\n <body>\n    <div class="container">\n        <div class="card card-container" style="text-align:center;">\n            <p style="font-size:15px;font-weight:bold;">You have been successfully disconnected</p>\n            <a href="{{app_url}}">Return to the application</a>\n        </div>\n    </div>\n </body>\n</html>', help_text='HTML Content for the logout page')),
                ('html_self', models.TextField(default='<!DOCTYPE html>\n<html>\n <head>\n    <meta charset="utf-8" />\n    <title>Vulture Self-Service</title>\n    <link rel="stylesheet" href="/templates/static/html/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">\n    {{style}}\n </head>\n <body>\n    <div class="container">\n        <div class="card card-container" style="text-align:center;" id="self_service">\n            <img id="vulture_img" src="/templates/static/img/vulture-logo-small.png"/>\n            <br><br>\n            {% if error_message != "" %}\n                <div class="alert alert-danger">{{error_message}}</div>\n            {% endif %}\n            <p>Hello <b>{{username}}</b>!</p>\n            <p>You currently have access to the following apps:</p>\n            <ul class="list-group">\n                {% for app in application_list %}\n                  <li class="list-group-item"><b>{{app.name}}</b> - <a href="{{app.url}}">{{app.url}}</a>{% if app.status %}<span class="badge">Logged</span>{% endif %}</li>\n                {% endfor %}\n            </ul>\n            <a href="{{changePassword}}">Change password</a>\n            <br><a href="{{logout}}">Logout</a>\n        </div>\n    </div>\n </body>\n</html>', help_text='HTML Content for the self-service page')),
                ('html_password', models.TextField(default='<!DOCTYPE html>\n<html>\n <head>\n    <meta charset="utf-8" />\n    <title>Vulture Change Password</title>\n    <link rel="stylesheet" href="..//templates/static/html/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">\n    {{style}}\n </head>\n <body>\n    <div class="container">\n        <div class="card card-container" style="text-align:center;">\n            {{form_begin}}\n                <img id="vulture_img" src="/templates/static/img/vulture-logo-small.png"/>\n                {% if error_message %}\n                    <div class="alert alert-danger">{{error_message}}</div>\n                {% endif %}\n                {% if dialog_change %}\n                    <p>Please fill the form to change your current password :</p>\n                    {{input_password_old}}\n                    {{input_password_1}}\n                    {{input_password_2}}\n                    {{input_submit}}\n\n                {% elif dialog_lost %}\n                    <p>Please enter an email address to reset your password:</p>\n\n                    {{input_email}}\n                    {{input_submit}}\n\n                {% endif %}\n            {{form_end}}\n        </div>\n    </div>\n </body>\n</html>\n', help_text='HTML Content for the password change page')),
                ('html_otp', models.TextField(default='<!DOCTYPE html>\n<html>\n <head>\n    <meta charset="utf-8" />\n    <title>Vulture OTP Authentication</title>\n    <link rel="stylesheet" href="/templates/static/html/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">\n    {{style}}\n </head>\n <body> \n    <div class="container">\n        <div class="card card-container" style="text-align:center;">\n            {% if error_message != "" %}\n                  <div class="alert alert-danger" role="alert">{{error_message}}</div>\n            {% endif %}\n            <p>OTP Form</p>\n            {{form_begin}}\n                {{input_key}}\n                {{input_submit}}\n            {{form_end}}\n            {{form_begin}}\n                {% if resend_button %}\n                    {{resend_button}}\n                {% endif %}\n                {% if qrcode %}\n                    <p>Register the following QRcode on your phone :\n                    <img {{qrcode}} alt="Failed to display QRcode" height="270" width="270" />\n                    </p>\n                {% endif %}\n            {{form_end}}\n        </div>\n    </div>\n </body>\n</html>\n', help_text='HTML Content for the otp page')),
                ('html_message', models.TextField(default='<!DOCTYPE html>\n<html>\n <head>\n    <meta charset="utf-8" />\n    <title>Vulture Info</title>\n    <link rel="stylesheet" href="/templates/static/html/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">\n    {{style}}\n </head>\n <body>\n    <div class="container">\n        <div class="card card-container">\n            <img id="vulture_img" src="/templates/static/img/vulture-logo-small.png"/>\n            <p>{{message}}</p>\n            {% if link_redirect %}<a href="{{link_redirect}}">Go back</a>{% endif %}\n        </div>\n    </div>\n </body>\n</html>', help_text='HTML Content for the message page')),
                ('html_error', models.TextField(default='<!DOCTYPE html>\n<html>\n <head>\n    <meta charset="utf-8" />\n    <title>Vulture Error</title>\n    <link rel="stylesheet" href="/templates/static/html/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">\n    <style>\n        {{style}}\n    </style>\n </head>\n <body>\n    <div class="container">\n        <div class="card card-container">\n            <img id="vulture_img" src="https://www.vultureproject.org/assets/images/logo_mini.png"/>\n            <p>{{message}}</p>\n        </div>\n    </div>\n </body>\n</html>', help_text='HTML General content for error pages')),
                ('html_registration', models.TextField(default='<!DOCTYPE html>\n<html>\n <head>\n    <meta charset="utf-8" />\n    <title>Titre</title>\n    <link rel="stylesheet" href="/templates/static/html/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">\n    {{style}}\n </head>\n <body>\n    <div class="container">\n        <div class="card card-container" style="text-align:center;">\n            {{form_begin}}\n                <img id="vulture_img" src="/templates/static/img/vulture-logo-small.png"/>\n                {% if error_message %}\n                    <div class="alert alert-danger">{{error_message}}</div>\n                {% endif %}\n                {{captcha}}\n                {{input_captcha}}\n                {% if step2 %}\n                    <p>Please fill the form to register your account :</p>\n                    {{input_username}}\n                    {% if ask_phone %}\n                    {{input_phone}}\n                    {% endif %}\n                    {{input_password_1}}\n                    {{input_password_2}}\n                    {{input_submit}}\n\n                {% elif step1 %}\n                    <p>Please enter your email address to receive the registration mail :</p>\n                    {{input_email}}\n                    {{input_submit}}\n                {% endif %}\n            {{form_end}}\n        </div>\n    </div>\n </body>\n</html>', help_text='HTML Content for registration pages')),
                ('html_error_403', models.TextField(default='403 Forbidden', help_text='HTML message for 403 Forbidden error')),
                ('html_error_404', models.TextField(default='404 Not Found', help_text='HTML message for 404 Not Found error')),
                ('html_error_405', models.TextField(default='405 Method Not Allowed', help_text='HTML message for 405 Method Not Allowed error')),
                ('html_error_406', models.TextField(default='406 Not Acceptable', help_text='HTML message for 406 Not Acceptable error')),
                ('html_error_500', models.TextField(default='500 Server Error', help_text='HTML message for 500 Server Error error')),
                ('html_error_501', models.TextField(default='501 Not Implemented', help_text='HTML message for 501 Not Implemented error')),
                ('html_error_502', models.TextField(default='502 Bad Gateway', help_text='HTML message for 502 Bad Gateway / Proxy error')),
                ('html_error_503', models.TextField(default='503 Service Unavailable', help_text='HTML message for 503 Service Unavailable error')),
                ('html_error_504', models.TextField(default='504 Gateway Time-out', help_text='HTML message for 504 Gateway Time-out error')),
                ('email_subject', models.TextField(default='Password reset request for {{ app.name }}', help_text='Email subject for password reset')),
                ('email_body', models.TextField(default='<html>\n<head>\n</head>\n<body>\n<p>Dear Sir or Madam, <br><br>\n\nWe got a request to reset your account on {{ app.url }}.<br><br>\n\nClick here to reset your password: <a href="{{resetLink}}">Reset password</a><br><br>\n\nIf you ignore this message, your password won"t be changed.<br>\nIf you didn"t request a password reset, <a href="mailto:abuse@vulture">let us know</a><br>\n</body>\n</html>', help_text='Email content for password reset')),
                ('email_from', models.TextField(default='no-reply@vulture', help_text='Email "From" for password reset')),
                ('error_password_change_ok', models.TextField(default='Your password has been changed', help_text='Your password has been changed')),
                ('error_password_change_ko', models.TextField(default='Error when trying to change your password', help_text='Error when trying to change your password')),
                ('error_email_sent', models.TextField(default='An email has been sent to you with instructions to reset your password', help_text='An email has been sent to you with instruction to reset your password')),
                ('email_register_subject', models.TextField(default='Registration request for {{ app.name }}', help_text='Email subject for registration')),
                ('email_register_from', models.TextField(default='no-reply@vulture', help_text='Email address for registration')),
                ('email_register_body', models.TextField(default='<html>\n    <head>\n        <title>Vulture registration</title>\n    </head>\n    <body>\n        <p>Dear Sir or Madam, <br><br>\n\n        We got a request to register your account on {{ app.url }}.<br><br>\n\n        Click here to validate the registration : <a href="{{registerLink}}">Register account</a><br><br>\n\n        If you ignore this message, your account won"t be confirmed.<br>\n        If you didn"t request a registration, <a href="mailto:abuse@vulture">let us know</a><br>\n    </body>\n</html>', help_text='Email sender for registration')),
                ('login_login_field', models.TextField(default='Login', help_text='Login field for the log-in page')),
                ('login_password_field', models.TextField(default='Password', help_text='Password field for the log-in page')),
                ('login_captcha_field', models.TextField(default='Captcha', help_text='Captcha field for the log-in page')),
                ('login_submit_field', models.TextField(default='Sign in', help_text='Submit field for the log-in page')),
                ('learning_submit_field', models.TextField(default='Save', help_text='Submit field for the learning page')),
                ('password_old_field', models.TextField(default='Old password', help_text='Old password field for the password page')),
                ('password_new1_field', models.TextField(default='New password', help_text='New password field for the password page')),
                ('password_new2_field', models.TextField(default='Confirmation', help_text='Confirmation password field for the password page')),
                ('password_email_field', models.TextField(default='Email', help_text='Email field for the password page')),
                ('password_submit_field', models.TextField(default='OK', help_text='Submit field for the password page')),
                ('otp_key_field', models.TextField(default='Key', help_text='OTP Key field for the OTP page')),
                ('otp_submit_field', models.TextField(default='Sign in', help_text='Submit field for the OTP page')),
                ('otp_resend_field', models.TextField(default='Resend', help_text='Resend field for the OTP page')),
                ('otp_onetouch_field', models.TextField(default="<p>Please approve the OneTouch request on your phone, and click on 'Sign in'</p>", help_text='Onetouch message for the OTP page')),
                ('register_captcha_field', models.TextField(default='Captcha', help_text='Captcha field for the registration page')),
                ('register_username_field', models.TextField(default='Username', help_text='Username field for the registration page')),
                ('register_phone_field', models.TextField(default='Phone number', help_text='Phone field for the registration page')),
                ('register_password1_field', models.TextField(default='Password', help_text='Password field for the registration page')),
                ('register_password2_field', models.TextField(default='Password confirmation', help_text='Password confirmation field for the registration page')),
                ('register_email_field', models.TextField(default='Email', help_text='Email field for the registration page')),
                ('register_submit_field', models.TextField(default='Register', help_text='Password confirmation field for the registration page')),
            ],
        ),
        migrations.CreateModel(
            name='RepoAttributes',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key', models.TextField(default='username', help_text='Attribute key to keep in scope', verbose_name='Attribute key name')),
                ('source_attr', models.TextField(choices=[('claim', 'Claim attribute'), ('repo', 'Repository attribute'), ('merge', 'Merge attribute as list'), ('claim_pref', 'Use claim, or repo attr if not present'), ('repo_pref', 'Use repo attr, or claim if not present')], default='claim', help_text='Attribute key to keep in scope', verbose_name='Attribute name')),
            ],
        ),
        migrations.CreateModel(
            name='TemplateImage',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.TextField(help_text='The name of the image')),
                ('uid', models.TextField(help_text='A unique identifier to get the image from portal', null=True)),
            ],
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='enable_sso_forward',
            field=models.BooleanField(default=False, help_text='Forward credentials to backend'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='lookup_claim_attr',
            field=models.TextField(default='username', help_text='Claim name used to map user to ldap attribute', verbose_name='Lookup claim key name'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='lookup_ldap_attr',
            field=models.TextField(default='cn', help_text='Attribute name in ldap to map user claim', verbose_name='Lookup ldap attribute'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='lookup_ldap_repo',
            field=models.ForeignKey(default=None, help_text='Used for federation to retrieve user attributes from LDAP repository', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='lookup_ldap_repo_set', to='authentication.LDAPRepository', verbose_name='Lookup ldap repository'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='repo_attributes',
            field=djongo.models.fields.ArrayModelField(default=[], help_text='Repo attributes whitelist, for re-use in SSO and ACLs', model_container=authentication.user_portal.models.RepoAttributes, model_form_class=authentication.user_portal.models.RepoAttributesForm, verbose_name='Create user scope'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_additional_url',
            field=models.TextField(default='http://My_Responsive_App.com/Default.aspx', help_text='URL of additionnal request'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_capture_content',
            field=models.TextField(default='^REGEX to capture (content.*) in SSO Forward Response$', help_text=''),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_content',
            field=models.TextField(default='', help_text=''),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_content_type',
            field=models.TextField(choices=[('urlencoded', 'application/x-www-form-urlencoded'), ('multipart', 'multipart/form-data'), ('json', 'application/json')], default='urlencoded', help_text='Content-Type of the SSO Forward request'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_direct_post',
            field=models.BooleanField(default=False, help_text='Enable direct POST'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_enable_additionnal',
            field=models.BooleanField(default=False, help_text='Make an additionnal request after SSO'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_enable_capture',
            field=models.BooleanField(default=False, help_text='Capture content in SSO response'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_enable_replace',
            field=models.BooleanField(default=False, help_text='Enable content rewrite of SSO response'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_follow_redirect',
            field=models.BooleanField(default=False, help_text='After posting the login form, follow the redirection'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_follow_redirect_before',
            field=models.BooleanField(default=False, help_text='Before posting the login form, follow metaredirect'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_get_method',
            field=models.BooleanField(default=False, help_text='Make a GET instead of a POST'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_replace_content',
            field=models.TextField(default="By previously captured '$1'/", help_text='Replace content in SSO response'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_replace_pattern',
            field=models.TextField(default='^To Be Replaced$', help_text='Replace pattern in SSO response'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_return_post',
            field=models.BooleanField(default=False, help_text="Return the application's response immediately after the SSO Forward Request"),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_tls_cert',
            field=models.ForeignKey(help_text='Client certificate used to connect to SSO url.', null=True, on_delete=django.db.models.deletion.PROTECT, to='system.X509Certificate'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_tls_check',
            field=models.BooleanField(default=True, help_text='Enable certificate verification (date, subject, CA), disable if self-signed certificate'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_tls_proto',
            field=models.TextField(choices=[('tlsv13', 'TLSv1.3'), ('tlsv12', 'TLSv1.2'), ('tlsv11', 'TLSv1.1'), ('tlsv10', 'TLSv1.0')], default=('tlsv10', 'TLSv1.0'), help_text='Minimal TLS protocol used to connect to SSO url'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_type',
            field=models.TextField(choices=[('form', 'HTML Form'), ('basic', 'Basic Authentication'), ('kerberos', 'Kerberos Authentication')], default='form', help_text='Select the way to propagate authentication'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_url',
            field=models.TextField(default='http://your_internal_app/action.do?what=login', help_text='URL of the login form'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='sso_forward_user_agent',
            field=models.TextField(default='Vulture/4 (BSD; Vulture OS)', help_text="Override 'User-Agent' header for SSO forward requests", verbose_name='Override User-Agent (set empty if not)'),
        ),
        migrations.AlterField(
            model_name='userauthentication',
            name='portal_template',
            field=models.ForeignKey(help_text='Select the template to use for user authentication portal', null=True, on_delete=django.db.models.deletion.PROTECT, to='authentication.PortalTemplate', verbose_name='Portal template'),
        ),
        migrations.AddField(
            model_name='userauthentication',
            name='oauth_timeout',
            field=models.PositiveIntegerField(default=600,
                                              help_text='Time in seconds after which oauth2 tokens will expire',
                                              verbose_name='OAuth2 tokens timeout'),
        ),
        migrations.AlterField(
            model_name='userauthentication',
            name='enable_external',
            field=models.BooleanField(default=False, help_text='Listen portal on dedicated host - required for ',
                                      verbose_name='Enable Identity Provider'),
        ),
        migrations.AddField(
            model_name='openidrepository',
            name='id_alea',
            field=models.TextField(default=toolkit.system.hashes.random_sha1),
        ),
    ]
