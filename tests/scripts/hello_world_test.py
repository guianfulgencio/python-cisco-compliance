import logging
from pyats import aetest

logger = logging.getLogger(__name__)

class HelloWorld(aetest.CommonSetup):

    uid = 'Devices Common Setup'
    @aetest.subsection
    def hello_world(self):
        logger.info('Hello World!')

    @aetest.subsection
    def check_script_arguments(self):
        logger.info('Check script arguments')

    @aetest.subsection
    def connect_to_devices(self):
        logger.info('connect to device')

    @aetest.subsection
    def configure_interfaces(self):
        logger.info('configure interfaces')

class SimpleTestcase(aetest.Testcase):

    uid = 'Simple Testcase'
    @aetest.test
    def trivial_test(self):
        assert 1 + 1 == 2

    @aetest.test
    def check_devices(self, devices):
        for device, ip in devices.items():
            logger.info(device)
            logger.info(ip)

# testcases could also have its own setup/cleanups
class SlightlyMoreComplexTestcase(aetest.Testcase):

    # providing this testcase a user-defined uid
    uid = 'Test case new name'

    @aetest.setup
    def setup(self):
        self.value = 1

    @aetest.test
    def another_trivial_test(self):
        self.value += -1
        assert self.value == 0

    @aetest.cleanup
    def cleanup(self):
        del self.value

class ScriptCommonCleanup(aetest.CommonCleanup):

    @aetest.subsection
    def remove_testbed_configurations(self):
        logger.error('remote testbed configuration')

    @aetest.subsection
    def disconnect_from_devices(self):
        logger.info('disconnect from devices')

# main()
if __name__ == '__main__':
    import os
    import sys
    import json
    import argparse

    # Change working directory
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)

    # creating our own parser to parse script arguments
    parser = argparse.ArgumentParser(description = "Test script")
    parser.add_argument('--environment', dest = 'environment', type= str)
    args, sys.argv[1:] = parser.parse_known_args(sys.argv[1:])

    inventory_file = '../../inventory/phhq_dev.json'
    if args.environment.upper() == 'PROD':
        inventory_file = '../../inventory/phhq_prod.json'

    with open(inventory_file, 'r') as inv_file:
        inventory_dict = json.load(inv_file)

    # set logger level
    logger.setLevel(logging.INFO)

    aetest.main(devices=inventory_dict)
