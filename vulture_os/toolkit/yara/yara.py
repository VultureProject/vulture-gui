#!/home/vlt-os/env/bin/python
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
__author__ = "Théo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'System Utils Yara Toolkit'

# Django project imports
from darwin.inspection.models import InspectionPolicy, InspectionRule, PACKET_INSPECTION_TECHNO, DEFAULT_YARA_CATEGORIES
from django.core.exceptions import ObjectDoesNotExist
from system.exceptions import VultureSystemConfigError

import subprocess
from toolkit.network.network import get_proxy
import requests
import logging
import os
import re
import zipfile

logger = logging.getLogger('system')


def fetch_yara_rules(logger):
    logger.info("getting updated yara rules...")

    # proxy = get_proxy()
    try:
        doc_uri = "https://github.com/Yara-Rules/rules/archive/master.zip"
        # doc = requests.get(doc_uri, proxies=proxy, timeout=10)
        doc = requests.get(doc_uri, timeout=10)
    except requests.Timeout:
        logger.error("Yara::fetch_yara_rules:: timed out while trying to connect")
        raise
    except Exception as e:
        logger.error("Yara::fetch_yara_rules:: {}".format(e), exc_info=1)
        raise

    logger.info("Yara::fetch_yara_rules:: extracting them...")
    try:
        with open("/var/tmp/yara_rules.zip", "wb") as f:
            f.write(doc.content)
        with zipfile.ZipFile("/var/tmp/yara_rules.zip") as z:
            z.extractall("/var/tmp/yara_rules/")
    except Exception as e:
        logger.error("Yara::fetch_yara_rules:: {}".format(e), exc_info=1)
        raise

    rule_regex = re.compile(r'^\s*rule .*$')

    for (baseRoot, baseDirs, baseFiles) in os.walk("/var/tmp/yara_rules/rules-master/"):
        for baseDir in baseDirs:
            for (root, dirs, files) in os.walk(os.path.join(baseRoot, baseDir)):
                for filename in files:
                    contains_rules = False
                    fullpath = os.path.join(root, filename)
                    name, extension = os.path.splitext(filename)
                    with open(fullpath, 'r', encoding='utf-8') as f:
                        for line in f:
                            if rule_regex.search(line):
                                contains_rules = True
                                continue
                    if contains_rules:
                        try:
                            subprocess.check_output(["/usr/local/bin/yara", fullpath, fullpath], stderr=subprocess.PIPE)
                            with open(fullpath, 'r', encoding='utf-8') as content_file:
                                filtered_lines = [line for line in content_file if "import " not in line]
                                rule, created = InspectionRule.objects.get_or_create(
                                    name=name,
                                    techno="yara",
                                    defaults={
                                        "category": baseDir.lower(),
                                        "content": ''.join(filtered_lines),
                                        "source": "github"
                                    }
                                )
                                rule.save()
                        except subprocess.CalledProcessError:
                            pass
                        except Exception as e:
                            logger.error(e)

    logger.info("Yara::fetch_yara_rules:: finished importing new rules")

    for category in DEFAULT_YARA_CATEGORIES:
        create_or_update_policy_with_category(logger, category)


def create_or_update_policy_with_category(logger, category):
    logger.info("Yara::create_or_update_policy:: trying to create/update policy with category '{}'".format(category))

    if category == "":
        description_category = "(all rules)"
    else:
        description_category = "(only {})".format(category)

    policy, created = InspectionPolicy.objects.get_or_create(
        name="github_policy" + "_" + category if category else "github_policy",
        defaults={
            "techno": "yara",
            "description": "automatic policy created from github rules " + description_category
        })

    if not created:
        logger.info("Yara::create_or_update_policy:: using existing policy")
    else:
        logger.info("Yara::create_or_update_policy:: created new policy")

    if category:
        rules = InspectionRule.objects.filter(category=category, source="github")
    else:
        rules = InspectionRule.objects.filter(source="github")

    logger.info("Yara::create_or_update_policy:: found {} rules".format(rules.count()))
    logger.debug("Yara::create_or_update_policy:: found rules {}".format(rules))

    policy.rules.clear()

    for rule in rules:
        policy.rules.add(rule)

    policy.save()
    policy.try_compile()


def try_compile_yara_rules(logger, policy_id):
    logger.info("Yara::try_compile_yara_rules:: trying to compile yara rules for policy {}".format(policy_id))
    try:
        policy = InspectionPolicy.objects.get(pk=policy_id)
        filepath = policy.get_full_test_filename()

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(policy.generate_content())

        subprocess.check_output(["/usr/local/bin/yara", filepath, filepath], stderr=subprocess.STDOUT)
    except ObjectDoesNotExist:
        logger.error("Yara::try_compile_yara_rules:: could not find inspection policy {} to check conf")
        return
    except subprocess.CalledProcessError as e:
        logger.error("Yara::try_compile_yara_rules:: could not compile rules !")
        policy.compilable = "KO"
        policy.compile_status = e.output.decode('utf-8')
        policy.save()
        return
    except Exception as e:
        logger.error(e)
        return

    logger.info("Yara::try_compile_yara_rules:: yara rule successfully compiled rules, saving rule file...")
    policy.compilable = "OK"
    policy.compile_status = ''
    policy.save_policy_file()
    policy.save()


def compile_all_rules(logger):
    logger.info("Yara::compile_all_rules:: trying to compile all rules")
    for policy in InspectionPolicy.objects.all():
        try:
            filepath = policy.get_full_test_filename()

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(policy.generate_content())

            subprocess.check_output(["/usr/local/bin/yara", filepath, filepath], stderr=subprocess.STDOUT)
            logger.info("Yara::compile_all_rules:: inspection policy {} successfuly compiled, writing file".format(policy))
            policy.compilable = "OK"
            policy.compile_status = ''
            policy.save()
            policy.save_policy_file()
        except VultureSystemConfigError as e:
            logger.error("Yara::try_compile_yara_rules:: error while saving file: {}".format(e))
        except subprocess.CalledProcessError as e:
            logger.error("Yara::try_compile_yara_rules:: could not compile rules !")
            policy.compilable = "KO"
            policy.compile_status = e.output.decode('utf-8')
            policy.save()
        except Exception as e:
            logger.error("Yara::try_compile_yara_rules:: {}".format(e))