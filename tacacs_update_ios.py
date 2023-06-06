import argparse
from ipaddress import ip_address
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import partial
import pandas as pd
from networkdevice import IOS_device

result_list = []

def is_sdwan(str_in):
    try:
        version_pattern = re.compile('\n(vmanage.*)')
        x = re.search(version_pattern, str_in)
        if x is not None:
            if ' up ' in x.group(1):
                return True
            else:
                return False
        else:
            return False
    except BaseException as e:
        return False

def verify_tacacs_americas(str_in):
    if "139.65.136.58" in str_in and\
            "139.65.143.4" in str_in:
        return True
    else:
        raise Exception('Tacacs servers not found in "show tacacs" ')

def verify_tacacs_emea(str_in):
    if "139.65.136.58" in str_in and\
            "139.65.138.26" in str_in:
        return True
    else:
        raise Exception('Tacacs servers not found in "show tacacs" ')

def verify_tacacs_apac(str_in):
    if "139.65.136.58" in str_in and\
            "146.45.1.85" in str_in and\
            "139.65.139.143" in str_in:
        return True
    else:
        raise Exception('Tacacs servers not found in "show tacacs" ')

def get_tacacs_config(nd):
    try:
        output = nd.sendcommand('show running-config | section tacacs ')
        if '\n%' in output:
            raise
        else:
            return output
    except BaseException as e:
        raise


'''def parseArgs():
    parser = argparse.ArgumentParser(
        description="passwords from ADO library")
    parser.add_argument(
        '--device_list', dest='device_list', action='store',
        nargs='+', help="List of devices ")
    parser.add_argument(
        '--enable', dest='enable', action='store',
        help="password for enable authentication on a device")
    parser.add_argument(
        '--before_username', dest='before_username',
        action='store', help="BeforeUsername")
    parser.add_argument(
        '--before_password', dest='before_password',
        action='store', help="Before Password")
    parser.add_argument(
        '--after_username', dest='after_username',
        action='store', help="After Username")
    parser.add_argument(
        '--after_password', dest='after_password',
        action='store', help="After Password")
    parser.add_argument(
        '--local_username', dest='local_username',
        action='store', help="local Username")
    parser.add_argument(
        '--local_secret', dest='local_secret',
        action='store', help="local user Secret")
    parser.add_argument(
        '--local_password', dest='local_password',
        action='store', help="local Password")
    parser.add_argument(
        '--region', dest='region',
        action='store', help="region")
    parser.add_argument(
        '--tacacs_password', dest='tacacs_password',
        action='store', help="tacacs Password")
    args, unknown = parser.parse_known_args()
    return args'''

ise_username = 'svc-voy-ansible'
ise_password = "88g?Xx1b50MPq?C?6L2u7v"
local_secret = "88g?Xx1b50MPq?C?6L2u7v"
login_name = 'svc-voy-ansible'

def single_device_operations(before_username, before_password, local_secret, device):
    run = True
    result = {
            'IP address': device['IP Address'],
            'Device Name': device['Device Name'],
            'Is Alive': False,
            'First Login Name': '',
            'Good SSH Connection': False,
            'Is SDWAN': False,
            'Running-Config': False,
            'Initial tacacs config': 'NA',
            'Good Rollback': False,
            'local admin': False,
            'Good SSH connection for second login': False,
            'Good SSH connection for third login': False,
            'Tacacs Verified': False,
            'Post tacacs config': 'None',
            'Copied_run_to_start': False,
            'Succesfully Cancelled Rollback': False
        }
    running_config = ''
    print(device['IP Address'])
    login_name = ''
    while run:
        run = False
        try:
            step = 'Attempt to login using CVX svc account'
            nd = IOS_device(device['IP Address'], before_username,before_password, local_secret)
            result['First Login Name'] = login_name
        except BaseException as e:
            # logging.error(device['IP Address'] + ':' + step + e.args[0])
            logging.error(device['IP Address'] + ':' + step + e.args[0])
            break
        result['Is Alive'] = nd.is_alive
        result['Good SSH Connection'] = nd.good_ssh_connection
        if nd.good_ssh_connection:
            try:
                step = 'Determine if SDWAN device'
                output = nd.sendcommand('show sdwan control connections')
                result['Is SDWAN'] = is_sdwan(output)
                if result['Is SDWAN']: raise Exception('SDWAN device = TRUE')
            except BaseException as e:
                logging.error(device['IP Address'] + ':' + step + e.args[0])
                break
            try:
                step = 'get_config'
                nd.get_config()
                running_config = nd.running_config
                result['Running-Config'] = True
            except BaseException as e:
                logging.error(device['IP Address'] + ':' + step + e.args[0])
                break
            try:
                step = 'get initial tacacs config'
                output = get_tacacs_config(nd)
                result["Initial tacacs config"] = output
            except BaseException as e:
                logging.error(device['IP Address'] + ':' + step + e.args[0])
                break
            try:
                step = 'Set rollback timer'
                good_rollback = nd.set_rollback_ios('10')
                result['Good Rollback'] = good_rollback
            except BaseException as e:
                logging.error(device['IP Address'] + ':' + step + e.args[0])
                break
            try:  # Search for vrf forwarding
                # x = re.search(r'(ip vrf forwarding.*)', nd.running_config)
                x = re.search(r'(ip vrf forwarding.*)', result["Initial tacacs config"])
                if x is not None:
                    vrf = x.group(1)
                else:
                    vrf = ''
            except BaseException as e:
                pass  # Not a problem if it does not exist
            try:  # Search for a global source interface
                x = re.search(
                    r"\n(ip.tacacs.source.interface.*)", nd.running_config)
                if x is not None:
                    source_interface = x.group(1)
                    global_interface = True
                    # Remove global tacacs source interface
                    # output = nd.connection.send_config_set(['no ' + source_interface])
                else:
                    global_interface = False
                    source_interface = ''
            except BaseException as e:
                global_interface = False
                source_interface = ''
            if global_interface is False:
                try:  # If no global source interface is found,
                    # search for source interface that is
                    # part of aaa group
                    x = re.search(
                        r"( ip.tacacs.source.interface.*)",
                        nd.running_config)
                    if x is not None:
                        source_interface = x.group(1)
                    else:
                        source_interface = ''
                except BaseException as e:
                    source_interface = ''
            try:  # Search for aaa group tacacs
                step = 'Remove any aaa group server tacacs'
                remove_list = []
                output_list = re.findall(r'(aaa group server tacacs.*)',nd.running_config)
                if output_list is not None:
                    for x in output_list:
                        remove_list.append('no ' + x)
                    # Remove all aaa tacacs groups
                    output = nd.connection.send_config_set(remove_list)
                    del output_list
            except BaseException as e:
                logging.error(device['IP Address'] + ':' + step + e.args[0])
                break
            add_aaa_group = {
                "americas": [
                    "tacacs server HOU_ACS",
                    "address ipv4 139.65.136.58",
                    "key 7 06031D344F4B1A1606041B08",
                    "timeout 10",
                    "exit",
                    "tacacs server HOU2_ACS",
                    "address ipv4 139.65.143.4",
                    "key 7 06031D344F4B1A1606041B08",
                    "timeout 10",
                    "exit",
                    "aaa group server tacacs+ ACS",
                    "server name HOU_ACS",
                    "server name HOU2_ACS"
                ]
            if len(source_interface) > 0:
                add_aaa_group['americas'].append(source_interface)
            if len(vrf) > 0:
                add_aaa_group['americas'].append(vrf)
            add_aaa_group['americas'].append("exit")
            verify_tacacs = {
                    'americas': verify_tacacs_americas
            }
        
            try:
                step = 'Attempt to login using local user'
                nd1 = IOS_device(device['IP Address'], ise_username, ise_password, local_secret)
            except BaseException as e:
                logging.error(device['IP Address'] + ':' + step + e.args[0])
                break
            if nd1.good_ssh_connection:
                output = nd1.sendcommand('show running-config | section aaa')
                result["Good SSH connection for second login"] = True
                #device_enabled = False
                try:
                    step = 'Enable the device (if it is not enabled) after login using loacl user'
                    if nd1.connection.check_enable_mode() is False:
                        nd1.connection.enable()
                    if nd1.connection.check_enable_mode() is False:
                        raise Exception('Device Enable Failed')
                except BaseException as e:
                    logging.error(device['IP Address'] + ':' + step + e.args[0])
                    break
                pattern = re.compile(r'(tacacs.server.*)')
                tacacs_list = re.findall(pattern, running_config)
                if tacacs_list is not None:
                    no_tacacs_list = []
                    for tacacs_line in tacacs_list:
                        no_tacacs_list.append('no ' + tacacs_line)
                    if len(source_interface)>0:
                        no_tacacs_list.append('no ' + source_interface )
                    try:
                        step = 'Send config command to remove original tacacs servers'
                        output = nd1.connection.send_config_set(no_tacacs_list)
                        if '\n%' in output:
                            raise Exception('Cisco error ')
                    except BaseException as e:
                        logging.error(device['IP Address'] + ':' + step + e.args[0])
                        break
                # Next add ISE settings
                try:
                    step = 'Adding golden template aaa tacacs group'
                    output = nd1.connection.send_config_set(add_aaa_group[region])
                    if '\n%' in output:
                        raise Exception('Cisco error ')
                except BaseException as e:
                    logging.error(device['IP Address'] + ':' + step + e.args[0])
                    break
                try:
                    step = 'Add aaa commands to standard and switch auth to group ACS local'
                    output = nd1.connection.send_config_set([
                        'aaa authentication login default group ACS local',
                        'aaa authentication enable default group ACS enable',
                        'aaa authorization config-commands',
                        'aaa authorization exec default group ACS if-authenticated',
                        'aaa authorization commands 0 default group ACS if-authenticated',
                        'aaa authorization commands 1 default group ACS if-authenticated',
                        'aaa authorization reverse-access default group ACS if-authenticated',
                        'aaa accounting update newinfo',
                        'aaa accounting exec default start-stop group ACS',
                        'aaa accounting commands 0 default start-stop group ACS',
                        'aaa accounting commands 1 default start-stop group ACS',
                        'aaa accounting commands 15 default start-stop group ACS',
                        'aaa accounting connection default start-stop group ACS',
                        'aaa accounting system default start-stop group ACS',
                        'aaa authorization commands 15 default group ACS if-authenticated'
                    ])
                    if '\n%' in output:
                        raise Exception('Cisco error ')
                except BaseException as e:
                    if 'Failed to exit configuration mode' not in e.args[0]:
                        logging.error(device['IP Address'] + ':' + step + e.args[0])
                        break
                nd1.connection.disconnect()
                # Re-connect using CVX / ISE login
                try:
                    step = 'Attempt login to verify new tacacs config works'
                    nd2 = IOS_device(device['IP Address'], after_username,after_password, '')
                    result["Good SSH connection for third login"] = nd2.good_ssh_connection
                except BaseException as e:
                    result["Good SSH connection for third login"] = False
                    logging.error(device['IP Address'] + ':' + step + e.args[0])
                    break
                try:
                    result["Tacacs Verified"] = False
                    step = 'Verify tacacs is correct'
                    output = nd2.connection.send_command('show tacacs')
                    if '\n%' in output:
                        raise Exception('Cisco error ')
                    result['Tacacs Verified'] = verify_tacacs[region](output)
                except BaseException as e:
                    logging.error(device['IP Address'] + ':' + step + e.args[0])
                    break
                try:
                    step = 'Fetch post tacacs config'
                    result["Post tacacs config"] =\
                        get_tacacs_config(nd2)
                except BaseException as e:
                    result["Post tacacs config"] = 'NA'
                    logging.error(device['IP Address'] + ':' + step + e.args[0])
                    break
                try:
                    step = 'Execute copy run start'
                    output = \
                        nd2.connection.send_command_timing('copy run start')
                    if '\n%' in output:
                        raise Exception('Cisco error ')
                    if 'Destination filename' in output:
                        output =\
                            nd2.connection.send_command_timing("\n")
                        if '\n%' in output:
                            raise Exception('Cisco error ')
                    if 'Building configuration' in output:
                        result['Copied_run_to_start'] = True
                    else:
                        result['Copied_run_to_start'] = False
                        raise Exception('Cisco error ')
                except BaseException as e:
                    logging.error(device['IP Address'] + ':' + step + e.args[0])
                    break
                try:
                    step = 'Cancel the rollback'
                    output = nd2.cancel_rollback()
                    result["Succesfully Cancelled Rollback"]\
                        = True
                except BaseException as e:
                    logging.error(device['IP Address'] + ':' + step + e.args[0])
                    break
                nd2.connection.disconnect()
    return result


def Main():
    logging.basicConfig(
        filename=f'Error_Log_APAC_NADC_tacacs_switch-{datetime.today().strftime("%Y-%m-%d %H_%M_%S")}.log',
        level=logging.WARNING, format='%(asctime)s-%(levelname)s-%(name)s-::%(module)s|%(lineno)s::%(message)s')
    logging.error('Start of Run *')
    args = parseArgs()
    #before_username = args.before_username
    #before_password = args.before_password
    #after_username = args.after_username
    #after_password = args.after_password
    #local_username = args.local_username
    #local_password = args.local_password
    local_secret = args.local_secret
    #region = args.region
    #tacacs_password = args.tacacs_password
    with open('./NADC/APAC.json') as file:
        device_list = json.load(file)
    print(f'Total Devices : {len(device_list)}')
    testing = False  # True = No MultiThreading for easier debug
    if not testing:
        single_device_operations_map = partial(
            single_device_operations, before_username,
            before_password, after_username, after_password,
            local_username, local_password,
            local_secret, region, tacacs_password)
        with ThreadPoolExecutor(max_workers=50) as executor:
            for result in executor.map(
                    single_device_operations_map, device_list):
                result_list.append(result)
    else:  # No multi thread
        for device in device_list:
            result = single_device_operations(
                before_username, before_password,
                after_username, after_password, local_username, local_password,
                local_secret, region, tacacs_password, device)
            result_list.append(result)
    df = pd.DataFrame(result_list)
    df.index += 1
    df.to_csv(f'./NADC/IOS-APAC-NADC_TACACS_Switch_Report-\
        {datetime.today().strftime("%Y-%m-%d %H_%M_%S")}.csv')


if __name__ == "__main__":
    Main()
