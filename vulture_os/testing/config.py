############################################
#    AUTOMATED TEST CONFIGURATION FILE     #
############################################

# Setup modules used before any test is launched, executed one time befoer testing
SETUP_MODULES_DIRECTORY = 'modules.setup_modules'

SETUP_MODULES = [

]


# Cleanup modules used after all tests are finished, executed one time after all the tests
CLEANUP_MODULES_DIRECTORY = 'modules.cleanup_modules'

CLEANUP_MODULES = [

]


# Testing modules are the tests you want to execute, every test is executed one time
TESTING_MODULES_DIRECTORY = 'modules.testing_modules'

TESTING_MODULES = [
    'connection_tests',
    'cluster_connection',
    'node_system_status',
    'repository_status',
]
