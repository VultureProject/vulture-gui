import importlib
import sys
import traceback
from contextlib import contextmanager
from time import time

from testing_module import TestingModule

sys.path.append("/home/vlt-gui/vulture")

import logging
import logging.config

logger = logging.getLogger('diagnostic')


@contextmanager
def get_modules_list(modules_files, modules_directory):
    """
    Get all the modules and return them as a list
    :return: The list of all testing modules
    """

    try:
        modules_list = []
        for mod in modules_files:
            modules_list.append(getattr(importlib.import_module(modules_directory + '.' + mod), "Module")())
        yield modules_list
    finally:
        pass


def get_methods(modules_list):
    """
    Get all the test methods from the modules
    :param modules_list: List containing the loaded modules
    :return: Dict containing the loaded modules as keys and their test methods as values
    """

    test_modules = {}
    for module in modules_list:
        test_modules[module] = [method for method in dir(module)
                                if method not in dir(TestingModule) and callable(getattr(module, method))]
        module.nb_test = len(test_modules[module])

    return test_modules


def launch_setup(setup_modules, save, node_name, summary):
    """
    Execute the setups of all the loaded setup modules
    :param setup_modules: Dict containing the loaded modules as keys and their setup methods as values
    :param save: Boolean determining if the logging is activated
    :param node_name: The name of the node the tests are executed on
    :param summary: A dict summarizing the tests results
    :return failed_setup: Dict containing the failed setup method for every setup module
    """

    failed_setup = {}
    for mod, methods in setup_modules.items():
        failed_methods = []
        for method in methods:
            try:
                getattr(mod, method)()
            except:
                failed_methods.append(method)
                if save:
                    logger.critical("Test failure out of testing scope, please contact the Vulture project team.",
                                    extra={
                                        'test_module': str(mod),
                                        'test_name': method,
                                        'traceback': traceback.format_exc(),
                                        'node_name': node_name
                                    })
                else:
                    print "[ERROR] <{}> {}:: Test failure out of testing scope, " \
                          "please check the code twice.\n{}".format(str(mod), method, traceback.format_exc())
        if failed_methods:
            failed_setup[str(mod)] = failed_methods

    if failed_setup:
        summary['setup'] = False
        summary['global_status'] = False
    else:
        summary['setup'] = True
    return failed_setup


def launch_cleanup(cleanup_modules, failed_setup, save, node_name, summary):
    """
    Execute the cleanups of all the loaded cleanup modules
    :param cleanup_modules: Dict containing the loaded modules as keys and their cleanup methods as values
    :param failed_setup: Dict containing the failed setup method for every setup module
    :param save: Boolean determining if the logging is activated
    :param node_name: The name of the node the tests are executed on
    :param summary: A dict summarizing the tests results
    """

    summary['cleanup'] = True
    for mod, methods in cleanup_modules.items():
        for method in methods:
            try:
                getattr(mod, method)()
            except:
                summary['cleanup'] = False
                summary['global_status'] = False
                if save:
                    logger.critical("Test failure out of testing scope, please contact the Vulture project team.",
                                    extra={
                                        'test_module': str(mod),
                                        'test_name': method,
                                        'traceback': traceback.format_exc(),
                                        'node_name': node_name
                                    })
                else:
                    print "[ERROR] <{}> {}:: Test failure out of testing scope, " \
                          "please check the code twice.\n{}".format(str(mod), method, traceback.format_exc())


def launch_testing(test_modules, output_level, save, failed_setup, node_name, summary):
    """
    Execute the tests of all the loaded modules
    :param test_modules: Dict containing the loaded modules as keys and their test methods as values
    :param output_level: The verbosity of the tests output
    :param save: Boolean determining if the logging is activated
    :param failed_setup: Dict containing the failed setup method for every setup module
    :param node_name: The name of the node the tests are executed on
    :param summary: A dict summarizing the tests results
    """

    tmp_modules = test_modules.copy()
    for mod, methods in tmp_modules.items():

        if set(mod.setup_modules).intersection(failed_setup):
            test_modules.pop(mod)
            continue

        summary[str(mod)] = {}
        start = time()

        for method in methods:
            try:
                mod.set_up()
            except:
                pass

            try:
                getattr(mod, method)()
                summary[str(mod)][method] = True

            except AssertionError as e:
                mod.test_failure_handler(method, e, traceback.format_exc(), output_level, save, node_name, summary)

            except:
                summary[str(mod)][method] = False
                summary['global_status'] = False
                mod.nb_failed += 1
                if save:
                    logger.critical("Test failure out of testing scope, please contact the Vulture project team.",
                                    extra={
                                        'test_module': str(mod),
                                        'test_name': method,
                                        'traceback': traceback.format_exc(),
                                        'node_name': node_name
                                    })
                else:
                    print "[ERROR] <{}> {}:: Test failure out of testing scope, " \
                          "please check the code twice.\n{}".format(str(mod), method, traceback.format_exc())

            try:
                mod.tear_down()
            except:
                pass

        mod.time = time() - start

        if not mod.nb_failed and save:
            logger.info("Test ended successfully",
                        extra={'test_module': str(mod), 'test_name': 'All', 'traceback': '-No Traceback-', 'node_name': node_name})
