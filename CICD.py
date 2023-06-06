"""
Main script
This main script will tie all the config methods defined in
restconf_methods.py
It takes below arguments

environment => 'DEV/PROD'
username => tacacs username
password => tacacs password
"""
import json
import argparse
import yaml
import time
from rich import print as rprint
from restconf_methods import Restconf

parser = argparse.ArgumentParser(description="configuration via Restconf")
parser.add_argument('-e', '--environment', type=str, metavar='',\
    help='Infrastructure environment [PROD/DEV]', required=True)
parser.add_argument('-u', '--username', type=str, metavar='',\
    help='Tacacs username', required=True)
parser.add_argument('-s', '--password', type=str, metavar='',\
    help='Tacacs password', required=True)
args = parser.parse_args()

def main():
    '''
    Main script
    '''
    # Initialize variables
    environment = args.environment
    username = args.username
    password = args.password
    inventory_file = f'inventory/phhq_{environment.lower()}.json'

    # Gather inventory device ip address details
    with open(inventory_file, 'r') as inventory:
        devices = json.load(inventory)

    # Loop through each device in devices inventory
    for host, ip_address in devices.items():
        rprint(f"\n[cyan]********** {host} **********[/cyan]")
        device = Restconf(username, password, ip_address, host)

        # Open device specific property
        device_filename = f"properties/{environment.lower()}/{host}.yml"
        with open(device_filename, 'r') as dev_prop_file:
            device_properties = yaml.safe_load(dev_prop_file)

            # Location properties
            region = device_properties['location']['Region']
            site_code = device_properties['location']['Facility']
            #mgmt_interface = device_properties['management']['interface']

            # Vlan properties
            vlan_property = None
            if 'vlan' in device_properties.keys():
                vlan_property = device_properties['vlan']['vlan-list']

            # Routing properties
            l3_property = 'default-gateway'
            if 'route' in device_properties.keys():
                l3_property = 'route'

        # Check device compliance config features
        # Make config change if actual device is non-compliant
        # Base compliance configurations
        device.service()
        device.host(device_properties['hostname'])
        device.user()
        #device.enable()
        #device.call_home()
        #device.domain(site_code, mgmt_interface)
        #device.name_server(region)
        #device.ip_config()
        #device.ftp_tftp_tacacs(mgmt_interface, environment.upper())

        # Layer 2 configuration
        #device.vtp(site_code, environment.upper())
        #device.vlan(environment.upper(), vlan_property)
        #device.spanning_tree()

        # Access-list dependent configurations
        #device.access_list(region)
        #device.logging(region, mgmt_interface)
        #device.ntp(region, mgmt_interface)
        #time.sleep(20)
        #device.line(environment.upper())
        #device.policy()

        # SNMP configurations
        #device.snmp_server(environment.upper(),device_properties['location'], mgmt_interface)
        #device.snmp()

        # Interface configurations
        #device.interface(device_properties['interface'])

        # Routing configurations
        #device.gateway(l3_property, device_properties)

        # AAA configurations
        #device.aaa(region, environment.upper())

        # save device configuration
        #device.save_config()

if __name__ == "__main__":
    main()
