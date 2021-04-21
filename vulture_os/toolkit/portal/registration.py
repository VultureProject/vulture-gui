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
from oauth2.tokengenerator import Uuid4
from system.cluster.models import Cluster
from email.mime.multipart            import MIMEMultipart
from email.mime.text                 import MIMEText
from smtplib import SMTP
from smtplib import SMTPException


def perform_email_registration(logger, base_url, app_name, template, user_email, expire=72*3600):
    # """ Generate an UUID64 and store it in redis """
    reset_key = create_redis_reset(user_email, expire)

    """ Get Cluster configuration """
    config = Cluster.get_global_config()
    portal_token = config.public_token
    smtp_server = config.smtp_server

    """ Send the email with the link """
    reset_link = base_url + str(portal_token) + '/self/change?rdm=' + reset_key

    obj = {'name': app_name, 'url': base_url}

    try:
        send_email(smtp_server,
                   template.email_register_from,
                   user_email,
                   template.render_template("email_subject", **obj),
                   template.render_template("email_body", resetLink=reset_link, app=obj))
        return True
    except Exception as e:
        logger.error("")
        logger.exception(e)
        return False


def perform_email_reset(logger, base_url, app_name, template, user_email, expire=3600):
    # """ Generate an UUID64 and store it in redis """
    reset_key = create_redis_reset(user_email, expire)

    """ Get Cluster configuration """
    config = Cluster.get_global_config()
    portal_token = config.public_token
    smtp_server = config.smtp_server

    """ Send the email with the link """
    reset_link = base_url + str(portal_token) + '/self/change?rdm=' + reset_key

    obj = {'name': app_name, 'url': base_url}

    try:
        send_email(smtp_server,
                   template.email_register_from,
                   user_email,
                   template.render_template("email_register_subject", **obj),
                   template.render_template("email_register_body", registerLink=reset_link, app=obj))
        return True
    except Exception as e:
        logger.error("")
        logger.exception(e)
        return False



def create_redis_reset(user_email, expire):
    reset_key = Uuid4().generate()

    redis_key = 'password_reset_' + reset_key

    redis_base = RedisBase()

    """ Store the reset-key in Redis """
    # The 'a' is for Redis stats, to make a distinction with Token entries
    redis_base.hmset(redis_key, {'email': user_email, 'a': 1})
    """ The key will expire in 10 minutes """
    redis_base.expire(redis_key, expire)

    return redis_key


def send_email(smtp_server, email_from, email_to, subject, body):
    msg = MIMEMultipart('alternative')

    msg['From'] = email_from
    msg['To'] = email_to
    msg['subject'] = subject

    msg.attach(MIMEText(body, "html"))

    # Following lines can raise
    smtp_obj = SMTP(smtp_server)
    smtp_obj.sendmail(email_from, email_to, msg.as_string())
