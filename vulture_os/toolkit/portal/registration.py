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
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Users registration toolkit'

from toolkit.redis.redis_base import RedisBase
from system.cluster.models import Cluster
from email.mime.multipart            import MIMEMultipart
from email.mime.text                 import MIMEText
from smtplib import SMTP
from smtplib import SMTPException
from uuid import uuid4


def perform_email_registration(logger, base_url, app_name, template, user_email, user_name, expire=72*3600, repo_id=None):
    # """ Generate an UUID64 and store it in redis """
    reset_key = create_redis_reset(user_email, user_name, expire, repo_id)

    """ Get Cluster configuration """
    config = Cluster.get_global_config()
    portal_token = config.public_token
    smtp_server = config.smtp_server
    assert smtp_server, "SMTP server is not configured in global configuration"

    """ Send the email with the link """
    reset_link = base_url + str(portal_token) + '/self/change?rdm=' + reset_key

    obj = {'name': app_name, 'url': base_url}

    try:
        send_email(smtp_server,
                   template.email_register_from,
                   user_email,
                   template.render_template("email_register_subject", app=obj),
                   template.render_template("email_register_body", registerLink=reset_link, app=obj, username=user_name))
        return True
    except Exception as e:
        logger.error("")
        logger.exception(e)
        return False


def perform_email_reset(logger, base_url, app_name, template, user_email, user_name, expire=3600, repo_id=None):
    # """ Generate an UUID64 and store it in redis """
    reset_key = create_redis_reset(user_email, user_name, expire, repo_id)

    """ Get Cluster configuration """
    config = Cluster.get_global_config()
    portal_token = config.public_token
    smtp_server = config.smtp_server
    if not smtp_server:
        raise SMTPException("SMTP server is not configured in global configuration")

    """ Send the email with the link """
    reset_link = base_url.rstrip("/") + "/" + str(portal_token) + '/self/change?rdm=' + reset_key

    obj = {'name': app_name, 'url': base_url}

    try:
        send_email(smtp_server,
                   template.email_register_from,
                   user_email,
                   template.render_template("email_subject", app=obj),
                   template.render_template("email_body", resetLink=reset_link, app=obj, username=user_name))
        return True
    except Exception as e:
        logger.error(f"perform_email_reset: Could not send the reset email to '{user_email} ({user_name})'")
        logger.exception(e)
        return False


def create_redis_reset(user_email, user_name, expire, repo_id=None):
    reset_key = str(uuid4())

    redis_key = 'password_reset_' + reset_key

    redis_base = RedisBase(password=Cluster.get_global_config().redis_password)

    """ Store the reset-key in Redis """
    # The 'a' is for Redis stats, to make a distinction with Token entries
    redis_key_content = {
        'email': user_email,
        'a': 1,
        'username': user_name
    }
    if repo_id:
        redis_key_content['repo'] = repo_id

    redis_base.hmset(redis_key, redis_key_content)
    """ The key will expire after 'expire' seconds """
    redis_base.expire(redis_key, expire)

    return reset_key


def send_email(smtp_server, email_from, email_to, subject, body):
    msg = MIMEMultipart('alternative')

    msg['From'] = email_from
    msg['To'] = email_to
    msg['subject'] = subject

    msg.attach(MIMEText(body, "html"))

    # Following lines can raise
    with SMTP(smtp_server, timeout=5) as smtp_obj:
        smtp_obj.sendmail(email_from, email_to, msg.as_string())

