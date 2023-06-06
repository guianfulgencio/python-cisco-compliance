import argparse
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import partial
import pandas as pd
from networkdevice import IOS_device

result_list = []

def show_tacacs(nd):
    try:
        output = nd.sendcommand('show tacacs')
        return output
    except Exception as e:
        return 'Error'


def get_tacacs(nd):
    try:
        output = nd.sendcommand('show runn | section tacacs')
        return output
    except Exception as e:
        return 'Error'

def get_aaa(nd):
    try:
        output = nd.sendcommand('show runn | section aaa')
        return output
    except Exception as e:
        return 'Error'


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

before_username = 'svc-spectrum'
before_password = "2(8Br4qceJW3m8')>e8lT"
secret = "2(8Br4qceJW3m8')>e8lT"
login_name = 'svc-spectrum'

def single_device_operations(before_username, before_password, secret, device):
    run = True
    result = {
            'IP address': device['IP Address'],
            'Hostname': device['Device Name'],
            'Is Alive': False,
            'Good SSH Connection': False,
            'Show tacacs': 'NA',
            'Show runn - section tacacs' : 'NA',
            'Show runn - section aaa' : 'NA'
        }
    running_config = ''
    print(device['IP Address'])
    #login_name = ''
    while run:
        run = False
        try:
            step = 'Attempt to login using CVX svc account'
            nd = IOS_device(
                device['IP Address'], before_username,
                before_password, secret)
            #login_name = after_username
            result['First Login Name'] = login_name
        except BaseException as e:
            logging.error(device['IP Address'] + ':' + step + e.args[0])
            break
        result['Is Alive'] = nd.is_alive
        result['Good SSH Connection'] = nd.good_ssh_connection
        if nd.good_ssh_connection:
            try:
                step = 'show tacacs '
                output = show_tacacs(nd)
                result["Show tacacs"] = output
            except BaseException as e:
                logging.error(device['IP Address'] + ':' + step + e.args[0])
                break
            try:
                step = 'Show runn - section tacacs" '
                output = get_tacacs(nd)
                result["Show runn - section tacacs"] = output
            except BaseException as e:
                logging.error(device['IP Address'] + ':' + step + e.args[0])
                break
            try:
                step = 'Show runn - section aaa '
                output = get_aaa(nd)
                result["Show runn - section aaa"] = output
            except BaseException as e:
                logging.error(device['IP Address'] + ':' + step + e.args[0])
                break
    return result


def Main():
    logging.basicConfig(
        filename=f'Error_Log_First10_NADC_tacacs_switch-{datetime.today().strftime("%Y-%m-%d %H_%M_%S")}.log',
        level=logging.WARNING, format='%(asctime)s %(message)s')
    logging.error('Start of Run *')
    with open('./inventory/host_dev.json') as file:
        device_list = json.load(file)
    print(f'Total Devices : {len(device_list)}')

    testing = True  # True = No MultiThreading for easier debug
    if not testing:
        single_device_operations_map = partial(
            single_device_operations, before_username,
            before_password)
        with ThreadPoolExecutor(max_workers=50) as executor:
            for result in executor.map(
                    single_device_operations_map, device_list):
                result_list.append(result)
    else:  # No multi thread
        for device in device_list:
            result = single_device_operations(
                before_username, before_password, secret, device)
            result_list.append(result)
    df = pd.DataFrame(result_list)
    df.index += 1
    df.to_csv(f'Tacacs_Report-{datetime.today().strftime("%Y-%m-%d %H_%M_%S")}.csv')


if __name__ == "__main__":
    Main()
