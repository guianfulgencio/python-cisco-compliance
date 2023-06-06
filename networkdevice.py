from asyncio.subprocess import DEVNULL
# from lib2to3.pytree import Base
import re
from netmiko import ConnectHandler
import logging
from datetime import datetime

#logging.basicConfig(filename='network_device.log',
#                    level=logging.ERROR, format='%(asctime)s %(message)s')

#logger = logging.getLogger(__name__)

class Network_device(object):
    """Class to represent network switches and routers"""
    def __init__(self, ip, username, password, secret, device_os):
        self.username = username
        self.password = password
        self.secret = secret
        self.ip = ip
        self.device_os = device_os
        self.is_alive = False
        self.good_ssh_connection = False
        self.connection = None
        self.sw_version_major = '0'
        self.sw_version_minor = '0'
        self.sw_version_patch = '0'
        self.sw_version = '0'
        self.BIOS_version = '0'
        self.BIOS_version_major = '0'
        self.BIOS_version_minor = '0'
        self.BIOS_version_patch = '0'
        self.is_alive = self.ping_device()
        self.createconnection()

        

    def ping_device(self):
        """
        Returns True if host responds to a ping request
        """
        import subprocess
        try:
            x = subprocess.call(f"ping -c 3 {self.ip}",
                                shell=True, stdout=DEVNULL
                                ) == 0
            return x
        except BaseException as e:
            return False

    def createconnection(self):
        """Creates a new SSH / Netmiko connection to the network device
        at ip using username and password to login.
        Returns the new connection object."""
        log_file = 'FETCH_log_' + self.ip.replace('.','_') + '.log'
        connection_dict = {
                "ip": self.ip,
                "username": self.username,
                "password": self.password,
                "secret": self.secret,
                "device_type": self.device_os,
                "global_delay_factor": 20,
                "banner_timeout": 20,
                "auth_timeout": 60,
                "session_log": log_file,
                "session_log_file_mode": "append"
            }
        try:
            self.connection = ConnectHandler(**connection_dict)
            self.good_ssh_connection = True
        except BaseException as e:
            self.connection = None
            self.good_ssh_connection = False
            raise

    def sendcommand(self, x_command_string: str,
                    x_expect_string='#',
                    x_strip_prompt=False,
                    x_strip_command=True):
        """Formats and sends a Netmiko 'send_command()' using the
        connection and command passed in. The return is the output
        from the device after executing the command. Command is
        passed as x_command. If the expected response is something
        other than the standard prompt then you can specify a
        unique string in the argument x_expect_string. x_strip_prompt
        controls if the device prompts are included in what is returned."""
        try:
            output = self.connection.send_command(
                command_string=x_command_string,
                expect_string=x_expect_string,
                strip_prompt=x_strip_prompt,)
            return output
        except BaseException as e:
            raise


class NXOS_device(Network_device):
    already_got_running_config = False
    already_got_version = False
    running_config = ''
    startup_config = ''
    version_config = ''

    def __init__(self, ip, username, password, secret=''):
        super().__init__(ip, username, password, secret, 'cisco_nxos')

    def simple_time(self):
            now = datetime.now()
            current_time = now.strftime("%H:%M:%S")
            return current_time.replace(':', '')
            
    def get_running_config(self):
        try:
            output = self.sendcommand('show running-config')
            self.running_config = output
            self.already_got_running_config = True
        except BaseException as e:
            logging.exception(
                f'NXOS_device - get_running_config\
                failed for device {self.ip} Error: {e}')
            self.running_config = f'show running-config Exception Occured: {e}'
            raise

    def get_startup_config(self):
        try:
            output = self.sendcommand('show startup-config')
            self.startup_config = output
        except BaseException as e:
            logging.exception(
                f'NXOS_device - get_startup_config\
                failed for device {self.ip} Error: {e}')
            raise

    def get_version(self):
        if self.already_got_version is False:
            output = self.sendcommand('show version')
            self.version_config = output
        try:
            version_pattern = re.compile(
                r'NXOS:\s+version\s+(\d+)\D?(\d*)\D?(\d*)')
            x = re.search(version_pattern, self.version_config)
            if x is None:
                version_pattern = re.compile(
                    r'system:\s+version\s+(\d+)\D?(\d*)\D?(\d*)')
                x = re.search(version_pattern, self.version_config)
            self.sw_version_major = x.group(1)
            self.sw_version_minor = x.group(2)
            self.sw_version_patch = x.group(3)
        except BaseException as e:
            logging.exception(
                f'NXOS_device - get_version failed for device \
                {self.ip} Error: {e}')
            raise
            

    def get_BIOS_version(self):
        if self.already_got_version is False:
            output = self.sendcommand('show version')
            self.version_config = output
        try:
            version_pattern = re.compile(
                r'BIOS:\s+version\s+(\d+)\D?(\d*)\D?(\d*)')
            x = re.search(version_pattern, self.version_config)
            self.BIOS_version_major = x.group(1)
            self.BIOS_version_minor = x.group(2)
            self.BIOS_version_patch = x.group(3)
        except BaseException as e:
            logging.exception(
                f'NXOS_device - get_BIOS_version failed for device \
                {self.ip} Error: {e}')
            raise

    def good_checkpoint(self):
        try:
            # output = self.sendcommand('clear checkpoint database')
            output = self.sendcommand('no checkpoint kctl')
            output += self.sendcommand('checkpoint kctl')
            return True
        except BaseException as e:
            logging.exception(
                f'NXOS_device - good_checkpoint failed for device \
                {self.ip} Error: {e}')
            raise

    def sw_version_is_good(self):
        if int(self.sw_version_major) >= 9 and int(self.sw_version_minor) >= 3:
            return True
        else:
            logging.error(
                f'NXOS_device - sw_version_is_good Error sw version is \
                {self.version} but requires 9.3 or higher for rollback. \
                Device:{self.ip}')
            return False

    def set_rollback_nxos(self, sleeptime: str):
        """Saves the running config and configures a scheduler job to
        revert to the saved configuration after sleeptime (minutes). \
        Success returns screen output."""
        # Rollback using Scheduler requires 9.3 or higher os.
        self.get_version()
        if not self.sw_version_is_good():
            raise Exception('Software version not compatible with Rollback Feature.')
        if not self.good_checkpoint():
            raise Exception('Checkpoint creation error.')
        try:
            print(f"scheduler aaa-authentication password 0 {self.connection.password}")
            output = self.connection.send_config_set([
                "clear scheduler logfile",
                "no feature scheduler",
                "feature scheduler",
                "scheduler logfile size 512",
                f"scheduler aaa-authentication password 7 {self.connection.password}",
                "no scheduler job name kctl",
                "no scheduler schedule name ROLLBACK",
                "scheduler job name kctl",
                "rollback running-config checkpoint kctl",
                "scheduler schedule name ROLLBACK",
                "job name kctl",
                "time start +" + sleeptime,
                "end"])
            if '\n%' in output:
                raise Exception('Rollback failed')
            output = self.sendcommand('show scheduler schedule')
            if "Yet to be executed" in output and "ROLLBACK" in output:
                return True
            else:
                raise Exception('Rollback error Success Pattern not found.') 
        except BaseException as e:
            raise
                    
    def clear_rollback(self):
        try:
            output = self.connection.send_config_set(['no scheduler schedule name ROLLBACK'])
            if '\n%' in output:
                raise Exception('Cancel Rollback failed')
        except BaseException as e:
            raise


class IOS_device(Network_device):
    already_got_running_config = False
    already_got_version = False
    running_config = ''
    startup_config = ''
    version_config = ''

    def __init__(self, ip, username, password, secret):
        super().__init__(ip, username, password, secret, 'cisco_ios')

    def get_config(self):
        try:
            output = self.sendcommand('show running-config')
            self.running_config = output
        except BaseException as e:
            self.running_config = ''
            raise

    def get_value(self, search_pattern):
        pattern = re.compile(search_pattern)
        output = re.search(pattern, self.running_config)
        if output is not None:
            return output
        else:
            return 'NA'

    def get_version(self):
        if self.already_got_running_config is False:
            output = self.sendcommand('show running-config')
            self.running_config = output
        try:
            version_pattern = re.compile('\nversion (\d+).(\d+)')
            x = re.search(version_pattern, self.running_config)
            if x is not None:
                self.sw_version_major = x.group(1)
                self.sw_version_minor = x.group(2)
            else:
                self.sw_version_major = 'NA'
                self.sw_version_minor = 'NA'
        except BaseException as e:
            self.sw_version_major = 'NA'
            self.sw_version_minor = 'NA'

    def cancel_rollback(self):
        try:
            output = self.sendcommand('configure confirm')
            if '\n%' in output:
                raise Exception('Cisco command error:' + output)
            if "No Rollback Confirmed" in output:
                raise Exception('Cisco cannot cancel rollback:' + output)
            else:
                return True
        except BaseException as e:
            raise

    def get_file_system(self):
        try:
            output = self.sendcommand('show file systems')
            file_system_data = re.search(
                '\n\*\s*(\d*)\s*(\d*)\s*\S*\s*\S*\s*(\S*):', output)
            if file_system_data is not None:
                free_space = int(file_system_data.group(2))
                drive = file_system_data.group(3)
                return free_space, drive
            else:
                raise Exception('get_file_system failed')
        except BaseException as e:
            raise

    def simple_time(self):
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        return current_time.replace(':', '')


    def set_rollback_ios(self, sleeptime: str):
        """Saves the running config to flash memory and configures a timer to
    revert to the saved configuration after sleeptime. Success returns True
    + screen output. Failure returns False + screen output"""
        free_space, drive = self.get_file_system()
        unique_num = self.simple_time()
        if free_space > 1000:
            try:
                output = self.connection.send_config_set([
                    "archive",
                    f"path {drive}:cvx_{unique_num}",
                    "maximum 5",
                    "exit"])
                if '\n%' in output: raise Exception('Cisco error during archive config for rollback timer')
                output = self.sendcommand(f"configure terminal revert timer {sleeptime}")
                output += self.sendcommand('exit')
                if '\n%' in output: raise Exception('Cisco error during revert timer')
                output = self.sendcommand('show archive')
                if f'cvx_{unique_num}' in output:
                    return True
                else:
                    raise Exception('Cisco error during rollback timer')
            except BaseException as e:
                raise
        else:
            raise


if __name__ == "__main__":
    print('This should only print during testing of this class \
            *****************************************************')
