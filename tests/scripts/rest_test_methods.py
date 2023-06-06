"""
RESTconf methods that will be integrated to PyATS test cases
"""
import json
import yaml
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Restconf_test():
    '''
    Restconf object for PyATS test case integrations
    '''
    def __init__(self, ip_address, hostname, username, password, environment):
        # self.ip_address = ip_address
        self.hostname = hostname
        self.auth = (username, password)
        self.environment = environment
        self.url = f'https://{ip_address}/restconf/data/Cisco-IOS-XE-native:native'
        self.headers = {
            "Content-Type": "application/yang-data+json",
            "Accept": "application/yang-data+json"
        }
        self.compliance = '../../properties/compliance_test'
        # self.compliance = 'properties/compliance_test'

    def service(self):
        '''
        Test device service configuration via restconf
        '''
        result = False
        config_file = f"{self.compliance}/service.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)

        try:
            url = f"{self.url}/service"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            content = resp.text.replace("Cisco-IOS-XE-native:", "")
            # import ipdb; ipdb.set_trace()
            if json.loads(content) == config_script:
                result = True

            return result

        except Exception:
            return result

    def device_name(self):
        '''
        Test device hostname configuration via restconf
        name => hostname from device yaml property
        '''

        # hostname configuration file
        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"
        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            deviceName = device_prop['hostname']

        # Default return value
        result = False

        try:
            url = f"{self.url}/hostname"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if resp.json()['Cisco-IOS-XE-native:hostname'] == deviceName:
                result = True

            return result

        except Exception:
            return result

    def user_name(self):
        '''
        Test device username configuration via restconf
        '''
        result = False
        config_file = f"{self.compliance}/username.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)

        try:
            url = f"{self.url}/username"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            content = resp.text.replace("Cisco-IOS-XE-native:", "")
            # import ipdb; ipdb.set_trace()
            if json.loads(content) == config_script:
                result = True

            return result

        except Exception:
            return result

    def enable(self):
        '''
        Test device enable configuration via restconf
        '''
        result = False
        config_file = f"{self.compliance}/enable.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)

        try:
            url = f"{self.url}/enable"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            content = resp.text.replace("Cisco-IOS-XE-native:", "")
            # import ipdb; ipdb.set_trace()
            if json.loads(content) == config_script:
                result = True

            return result

        except Exception:
            return result

    def call_home(self):
        '''
        Test device call_home configuration via restconf
        '''
        result = False
        config_file = f"{self.compliance}/call-home.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)

        try:
            url = f"{self.url}/call-home"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            content = resp.text.replace("Cisco-IOS-XE-native:", "").replace("Cisco-IOS-XE-call-home:", "")
            if json.loads(content) == config_script:
                result = True

            return result

        except Exception:
            return result

    def domain(self):
        '''
        Test device domain configuration via restconf
        '''
        # Default result value
        result = False

        # hostname configuration file
        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"

        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            deviceMgmt = device_prop['management']
            location = device_prop['location']
            int_number = deviceMgmt['interface']['number']
            if self.environment.upper() == 'DEV':
                int_number = str(int_number)
        # domain payload
        payload = {
            "Cisco-IOS-XE-native:domain": {
                "lookup-settings": {
                    "lookup": {
                        "source-interface": {
                            deviceMgmt['interface']['name']: int_number
                        }
                    }
                },
                "name": f"{location['Facility'].lower()}.chevrontexaco.net"
            }
        }

        try:
            url = f"{self.url}/ip/domain"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def name_server(self):
        '''
        Test device ip domain name-server configuration via restconf
        '''
        # Default result value
        result = False

        # hostname configuration file
        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"
        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            region = device_prop['location']['Region']

        config_file = f"{self.compliance}/ip.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            domain_server_script = config_script['ip']['name-server'].pop(region.upper())
            domain_server_script['no-vrf'] = sorted(domain_server_script['no-vrf'])

        # Ip domain name-server payload
        payload = {
            "Cisco-IOS-XE-native:name-server": domain_server_script 
        }

        try:
            url = f"{self.url}/ip/name-server"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def ftp(self):
        '''
        Test device ftp configuration via restconf
        '''
        # Default result value
        result = False

        # hostname configuration file
        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"
        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            deviceMgmt = device_prop['management']
            int_number = deviceMgmt['interface']['number']
            if self.environment.upper() == 'DEV':
                int_number = str(int_number)

        # payload
        payload = {
            f"Cisco-IOS-XE-native:ftp": {
                "source-interface": {
                    deviceMgmt['interface']['name']: int_number
                }
            }
        }

        try:
            url = f"{self.url}/ip/ftp"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def tftp(self):
        '''
        Test device tftp configuration via restconf
        '''
        # Default result value
        result = False

        # hostname configuration file
        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"
        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            deviceMgmt = device_prop['management']
            int_number = deviceMgmt['interface']['number']
            if self.environment.upper() == 'DEV':
                int_number = str(int_number)

        # payload
        payload = {
            f"Cisco-IOS-XE-native:tftp": {
                "source-interface": {
                    deviceMgmt['interface']['name']: int_number
                }
            }
        }

        try:
            url = f"{self.url}/ip/tftp"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def tacacs(self):
        '''
        Test device tacacs configuration via restconf
        '''
        # Default result value
        result = False

        # hostname configuration file
        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"
        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            deviceMgmt = device_prop['management']
            int_number = deviceMgmt['interface']['number']
            if self.environment.upper() == 'DEV':
                int_number = str(int_number)

        # payload
        payload = {
            f"Cisco-IOS-XE-aaa:tacacs": {
                "source-interface": {
                    deviceMgmt['interface']['name']: int_number
                }
            }
        }

        try:
            url = f"{self.url}/ip/tacacs"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def source_route(self):
        '''
        Test device ip source_route configuration via restconf
        '''
        # Default result value
        result = False

        with open(f"{self.compliance}/ip.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)
            source_route_config = config_script['ip']['source-route']

        # payload
        payload = {
            "Cisco-IOS-XE-native:source-route": source_route_config
        }

        try:
            url = f"{self.url}/ip/source-route"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            #resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if resp.status_code == 404:
                result = True

            elif payload == resp.json():
                result = True
                
            return result

        except Exception:
            return result

    def ssh(self):
        '''
        Test device ip SSH configuration via restconf
        '''
        # Default result value
        result = False

        with open(f"{self.compliance}/ip.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)
            ssh_config = config_script['ip']['ssh']

        # payload
        payload = {
            "Cisco-IOS-XE-native:ssh": ssh_config
        }

        try:
            url = f"{self.url}/ip/ssh"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def tcp(self):
        '''
        Test device ip TCP configuration via restconf
        '''
        # Default result value
        result = False

        with open(f"{self.compliance}/ip.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)
            tcp_config = config_script['ip']['tcp']

        # payload
        payload = {
            "Cisco-IOS-XE-native:tcp": tcp_config
        }

        try:
            url = f"{self.url}/ip/tcp"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def forward_protocol(self):
        '''
        Test device ip forward-protocol configuration via restconf
        '''
        # Default result value
        result = False

        with open(f"{self.compliance}/ip.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)
            forward_protocol_config = config_script['ip']['forward-protocol']

        # payload
        payload = {
            "Cisco-IOS-XE-native:forward-protocol": forward_protocol_config
        }

        try:
            url = f"{self.url}/ip/forward-protocol"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def http(self):
        '''
        Test device ip http configuration via restconf
        '''
        # Default result value
        result = False

        with open(f"{self.compliance}/ip.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)
            http_config = config_script['ip']['http']

        # payload
        payload = {
            "Cisco-IOS-XE-http:http": http_config
        }

        try:
            url = f"{self.url}/ip/http"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def vtp(self):
        '''
        Test device VTP configuration via restconf
        '''
        # Default result value
        result = False
        # hostname configuration file
        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"

        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            location = device_prop['location']

        with open(f"{self.compliance}/vtp.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)

        # vtp payload
        payload = {
            "Cisco-IOS-XE-native:vtp": {
                "Cisco-IOS-XE-vtp:domain": location['Facility'].upper(),
                "Cisco-IOS-XE-vtp:mode": config_script['vtp']['mode']
            }
        }

        try:
            url = f"{self.url}/vtp"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def vlan(self):
        '''
        Test device VLAN configuration via restconf
        '''
        # Default result value
        result = False
        # hostname configuration file
        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"

        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            device_vlans = device_prop['vlan']['vlan-list']


        # VLAN payload
        payload = {
            "Cisco-IOS-XE-native:vlan": {
                "Cisco-IOS-XE-vlan:vlan-list": device_vlans
            }
        }

        try:
            url = f"{self.url}/vlan"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def spanning_tree(self):
        '''
        Test device spanning tree configuration via restconf
        '''
        # Default result value
        result = False

        with open(f"{self.compliance}/spanning-tree.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)

        # Spanning-tree payload
        payload = {
            "Cisco-IOS-XE-native:spanning-tree": {
                "Cisco-IOS-XE-spanning-tree:extend": config_script['spanning-tree']['extend'],
                "Cisco-IOS-XE-spanning-tree:mode": config_script['spanning-tree']['mode']
            }
        }

        try:
            url = f"{self.url}/spanning-tree"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def access_list(self):
        '''
        Test device access_list configuration via restconf
        '''
        # Default result value
        result = False

        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"

        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            location = device_prop['location']
            region = location['Region']

        config_file = f"{self.compliance}/ip.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            access_list_script = config_script['ip']['access-list']
            standard_acl = access_list_script['standard']
            #extended_acl = access_list_script['extended']
            new_std_acl = []
            for acl in standard_acl:
                if acl['name'] == 40:
                    acl['access-list-seq-rule'] = acl['access-list-seq-rule'].pop(region.upper())
                new_std_acl.append(acl)

        payload = {
            "Cisco-IOS-XE-native:access-list": {
                "Cisco-IOS-XE-acl:standard": new_std_acl
                #"Cisco-IOS-XE-acl:extended": extended_acl
            }
        }

        try:
            url = f"{self.url}/ip/access-list"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result


    def logging(self):
        '''
        Test device logging configuration via restconf
        '''
        # Default result value
        result = False

        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"

        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            deviceMgmt = device_prop['management']
            location = device_prop['location']
            region = location['Region']

        with open(f"{self.compliance}/logging.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)

        # logging payload
        host_list = config_script['logging']['host']['ipv4-host-list'].pop(region.upper())
        host_list = sorted(host_list,key=lambda i:i['ipv4-host'])
        int_name = f"{deviceMgmt['interface']['name']}{deviceMgmt['interface']['number']}"
        payload = {
            "Cisco-IOS-XE-native:logging": {
                    "buffered": {
                        "size": {
                            "size-value": 128000
                        }
                    },
                    "host": {
                        "ipv4-host-list": host_list
                    },
                    "source-interface": [
                        {
                            "interface-name": int_name
                        }
                    ]
                }
            }

        try:
            url = f"{self.url}/logging"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result


    def ntp(self):
        '''
        Test device ntp configuration via restconf
        '''
        # Default result value
        result = False

        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"

        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            deviceMgmt = device_prop['management']
            int_number = deviceMgmt['interface']['number']
            if self.environment.upper() == 'DEV':
                int_number = str(deviceMgmt['interface']['number'])
            location = device_prop['location']
            region = location['Region']

        with open(f"{self.compliance}/ntp.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)

        # ntp payload
        server_list = config_script['ntp']['server'].pop(region.upper())
        server_list = sorted(server_list['server-list'],key=lambda i:i['ip-address'])
        payload = {
            "Cisco-IOS-XE-native:ntp": {
                "Cisco-IOS-XE-ntp:access-group": config_script['ntp']['access-group'],
                "Cisco-IOS-XE-ntp:server": {
                    "server-list": server_list
                },
                "Cisco-IOS-XE-ntp:source": {
                    deviceMgmt['interface']['name']: int_number
                }
            }
        }

        try:
            url = f"{self.url}/ntp"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def line(self):
        '''
        Test device line configuration via restconf
        '''

        with open(f"{self.compliance}/line.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)
            #if self.environment.upper() == 'DEV':
                #config_script['line'].pop('aux')

        # line payload
        payload = {
            "Cisco-IOS-XE-native:line": config_script['line']
        }
        # Default return value
        result = False

        try:
            url = f"{self.url}/line"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def policy(self):
        '''
        Test device policy configuration via restconf
        '''

        with open(f"{self.compliance}/policy.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)

        # policy payload
        payload = {
            "Cisco-IOS-XE-native:policy": {
                "Cisco-IOS-XE-policy:class-map": config_script['policy']['class-map'],
                "Cisco-IOS-XE-policy:policy-map": config_script['policy']['policy-map']
            }
        }
        # Default return value
        result = False

        try:
            url = f"{self.url}/policy"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def snmp(self):
        '''
        Test device snmp configuration via restconf
        '''
        result = False
        config_file = f"{self.compliance}/snmp.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)

        payload = {
            "Cisco-IOS-XE-native:snmp": {
                "Cisco-IOS-XE-snmp:ifmib": {
                    "ifindex": config_script['snmp']['ifmib']['ifindex']
                }
            }
        }

        try:
            url = f"{self.url}/snmp"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            # import ipdb; ipdb.set_trace()
            if payload == resp.json():
                result = True

            return result

        except Exception:
            return result

    def snmp_server(self):
        '''
        Test device snmp-server configuration via restconf
        '''
        result = False
        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"

        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)

        # Device Mgmt interface
        deviceMgmt = device_prop['management']
        int_number = deviceMgmt['interface']['number']

        # SNMP location details
        location = device_prop['location']
        facility = location['Facility']
        address = location['Address']
        country = location['Country']
        region = location['Region']
        iso = location['ISO-country-code']
        support_org = location['Support-Org']
        utility = location['Utility-name']
        criticality = location['Criticality']
        snmp_location = f"{facility} / {address} / {country} / {region} /{iso}-{support_org}-Utility-{utility}/{criticality}"

        config_file = f"{self.compliance}/snmp-server.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)

        # Update SNMP location field and sort the server list
        config_script['snmp-server']['location'] = snmp_location
        server_host_list = config_script['snmp-server']['host'].pop(region.upper())
        sorted_host_list = sorted(server_host_list,key=lambda i:i['ip-address'])
        if self.environment.upper() == 'DEV':
            int_number = str(deviceMgmt['interface']['number'])
            config_script['snmp-server']['enable']['enable-choice']['traps'].pop('envmon')

        payload = {
            "Cisco-IOS-XE-native:snmp-server": {
                "Cisco-IOS-XE-snmp:contact": config_script['snmp-server']['contact'],
                "Cisco-IOS-XE-snmp:enable": config_script['snmp-server']['enable'],
                "Cisco-IOS-XE-snmp:group": config_script['snmp-server']['group'],
                "Cisco-IOS-XE-snmp:host": sorted_host_list,
                "Cisco-IOS-XE-snmp:location": snmp_location,
                "Cisco-IOS-XE-snmp:trap": config_script['snmp-server']['trap'],
                "Cisco-IOS-XE-snmp:trap-source": {
                    deviceMgmt['interface']['name']: int_number
                },
                "Cisco-IOS-XE-snmp:view": config_script['snmp-server']['view']
                # "Cisco-IOS-XE-snmp:user": config_script['snmp-server']['user']
            }
        }

        try:
            url = f"{self.url}/snmp-server"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            content = resp.json()
            sorted_content_host = sorted(content['Cisco-IOS-XE-native:snmp-server']['Cisco-IOS-XE-snmp:host'],key=lambda i:i['ip-address'])
            content['Cisco-IOS-XE-native:snmp-server']['Cisco-IOS-XE-snmp:host'] = sorted_content_host
            # import ipdb; ipdb.set_trace()
            if payload == content:
                result = True

            return result

        except Exception:
            return result

    def aaa(self):
        '''
        Test device aaa configuration via restconf
        '''

        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"

        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            location = device_prop['location']
            region = location['Region']

        with open(f"{self.compliance}/aaa.yml", 'r') as config_file:
            config_script = yaml.safe_load(config_file)
            aaa_server = config_script['aaa']['group']['server']['tacacsplus'][0]['server-private'].pop(region.upper())
            aaa_server = sorted(aaa_server,key=lambda i:i['name'])
            config_script['aaa']['group']['server']['tacacsplus'][0]['server-private'] = aaa_server

        # AAA payload
        payload = {
            "Cisco-IOS-XE-native:aaa": {
                "Cisco-IOS-XE-aaa:new-model": config_script['aaa']['new-model'],
                "Cisco-IOS-XE-aaa:group": {
                    "server": {
                        "tacacsplus": [
                            {
                                "name": "acs",
                                "server-private": aaa_server,
                                "timeout": 10
                            }
                        ]
                    }
                },
                "Cisco-IOS-XE-aaa:authentication": config_script['aaa']['authentication'],
                "Cisco-IOS-XE-aaa:authorization": config_script['aaa']['authorization'],
                "Cisco-IOS-XE-aaa:accounting": config_script['aaa']['accounting'][self.environment.upper()],
                "Cisco-IOS-XE-aaa:session-id": config_script['aaa']['session-id']
            }
        }
        # Default return value
        result = False

        try:
            url = f"{self.url}/aaa"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            content = resp.json()
            # import ipdb; ipdb.set_trace()
            if payload == content:
                result = True

            return result

        except Exception:
            return result


    def route(self):
        '''
        Test device route configuration via restconf
        '''

        device_property_path = f"../../properties/{self.environment.lower()}/{self.hostname}.yml"

        # device_property_path = f"properties/{environment.lower()}/{self.hostname}.yml"
        with open(device_property_path, 'r') as device_prop_file:
            device_prop = yaml.safe_load(device_prop_file)
            l3_property = 'default-gateway'
            if 'route' in device_prop.keys():
                l3_property = 'route'

        # payload
        payload = {
            f"Cisco-IOS-XE-native:{l3_property}": device_prop[l3_property]
        }
        # Default return value
        result = False

        try:
            url = f"{self.url}/ip/{l3_property}"
            resp = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            resp.raise_for_status()
            content = resp.json()
            # import ipdb; ipdb.set_trace()
            if payload == content:
                result = True

            return result

        except Exception:
            return result
