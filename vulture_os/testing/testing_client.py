#!/home/vlt-gui/env/bin/python

import json
import sys

from config import (CLEANUP_MODULES, CLEANUP_MODULES_DIRECTORY, SETUP_MODULES, SETUP_MODULES_DIRECTORY, TESTING_MODULES,
                    TESTING_MODULES_DIRECTORY)
from core.command_parse import command_parse
from core.modules_utils import launch_testing, launch_setup, launch_cleanup, get_methods, get_modules_list
from core.print_results import print_detailed_results, print_summarized_results

sys.path.append("/home/vlt-gui/vulture")

from gui.models.system_settings import Cluster
from vulture_toolkit.log.settings import LOG_SETTINGS, LOG_SETTINGS_FALLBACK

import logging

try:
    logging.config.dictConfig(LOG_SETTINGS)
except:
    logging.config.dictConfig(LOG_SETTINGS_FALLBACK)


logger = logging.getLogger('diagnostic')


if __name__ == '__main__':

    parsing_result = command_parse()
    node           = Cluster.get_current_node()
    node_name      = node.name

    summary = {
        'global_status': True
    }

    with get_modules_list(SETUP_MODULES, SETUP_MODULES_DIRECTORY) as modules:
        setup_modules = get_methods(modules)
        failed_setup = launch_setup(setup_modules, parsing_result.save, node_name, summary)

    with get_modules_list(TESTING_MODULES, TESTING_MODULES_DIRECTORY) as modules:
        test_modules = get_methods(modules)
        launch_testing(test_modules, parsing_result.output_level, parsing_result.save, failed_setup, node_name, summary)

    with get_modules_list(CLEANUP_MODULES, CLEANUP_MODULES_DIRECTORY) as modules:
        cleanup_modules = get_methods(modules)
        launch_cleanup(cleanup_modules, failed_setup, parsing_result.save, node_name, summary)

    if parsing_result.save:
        try:
            node.diagnostic = json.dumps(summary)
        except:
            node.diagnostic = "ERROR: Unable to store diagnostic summary properly"

        """ Don't dispatch signal to not affect performance """
        node.save(bootstrap=True)

    if parsing_result.output_level != 'no':
        print_summarized_results(test_modules)
        if parsing_result.output_level != 'overview':
            print_detailed_results(test_modules)
