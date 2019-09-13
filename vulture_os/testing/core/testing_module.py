import sys

sys.path.append("/home/vlt-gui/vulture")

import logging
import logging.config

logger = logging.getLogger('diagnostic')


class TestingModule(object):

    def __init__(self):
        self.nb_test = 0
        self.nb_failed = 0
        self.time = 0
        self.log_level = 'error'
        self.buffer = ""
        self.setup_modules = []

    def __str__(self):
        return "TestingModule"

    def test_failure_handler(self, test_name, exception, traceback_str, output_level, save, node_name, summary):
        """
        Had the information about the test failed in the print buffer
        :param test_name: Name of the failed test
        :param exception: The AssertException raised by the test
        :param traceback_str: The traceback text as a string
        :param output_level: The verbosity of the tests output
        :param save: Boolean determining if the logging is activated
        :param node_name: The name of the node the tests are executed on
        :param summary: A dict summarizing the tests results
        """

        self.nb_failed += 1
        summary[str(self)][test_name] = False
        summary['global_status'] = False
        if save:
            level_logger = getattr(logger, self.log_level, logger.error)
            level_logger(str(exception),
                         extra={
                             'test_module': str(self),
                             'test_name': test_name,
                             'traceback': traceback_str,
                             'node_name': node_name
                         })

        if output_level != 'overview' and output_level != 'no':
            self.buffer += "{} : \"{}\"\n".format(test_name.strip(), exception)
            
            try:
                self.buffer += "DESCRIPTION: '" + getattr(self, test_name).__doc__.strip() + "'\n"
            except AttributeError:
                self.buffer += "DESCRIPTION: '" + test_name + "'\n"

            if output_level == 'detailed' or output_level == 'full':
                self.buffer += "{}".format(traceback_str)
            self.buffer += "--------------------------------------------------\n\n"

    @staticmethod
    def set_up():
        """
        This method is executed before every test of the module
        """
        pass

    @staticmethod
    def tear_down():
        """
        This method is executed after every test of the module
        """
        pass
