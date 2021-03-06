# Copyright (c) Juniper Networks, Inc., 2020 - 2022. All rights reserved.

# Notice and Disclaimer: This code is licensed to you under the GNU General Public License v3.0.
# You may not use this code except in compliance with the License.
# This code is not an official Juniper product.
# You can obtain a copy of the License at https://www.gnu.org/licenses/gpl-3.0.txt

# SPDX-License-Identifier: GPL-3.0-or-later

# Third-Party Code: This code may depend on other components under separate copyright notice and license terms. Your use of the source code for those components is subject to the terms and conditions of the respective license as noted in the Third-Party source code file.

# Makes API calls to Junos Space Security Director for each
# step of a workflow.

import requests
import base64
import json
from pprint import pprint
from time import sleep
import uuid

sd_address_uri = "/api/juniper/sd/address-management/addresses"
sd_service_uri = "/api/juniper/sd/service-management/services"
sd_policy_uri = "/api/juniper/sd/policy-management/firewall/policies"
sd_application_uri = "/api/juniper/sd/app-sig-management/app-sigs"
sd_scheduler_uri = "/api/juniper/sd/scheduler-management/schedulers"

class ZTN_ELK_Server():
    def __init__(self, url, user, password, sslVerify=False):
       self.root_url = url
       self.user = user
       self.password = password
       self.sslVerify = sslVerify

    def login(self):
       session = requests.session()
       bstr = self.user + ':' + self.password
       auth = base64.b64encode(bytes(bstr,'utf-8'))
       auth = auth.decode('utf-8')
       #print(auth)
       URL = self.root_url + '/api/space/user-management/login'
       headers = {'Authorization': 'Basic ' + auth}
       response = session.post(url=URL, headers= headers, verify=self.sslVerify)
       if response.status_code == 200:
         self.session = session
         return self
       else:
         raise Exception("Error: code = %d, text = %s" % (response.status_code, response.text))

    def pretty_json(self, text):
        """
        Helper function to print JSON with nice indents on the CLI.

        :param text plain-text that can be converted to a JSON object
        """
        return json.dumps(json.loads(text), indent=2)


    def check_address_exists(self, address):
        """
        Checks whether an address matches the attributes of an address object
        already in Security Director.

        :return address ID if a matching object exists, None otherwise ; status code
        """

        url = self.root_url + sd_address_uri

        payload = {}

        headers = {
            'Accept': 'application/vnd.juniper.sd.address-management.address-refs+json;version=1;q=0.01'
        }

        req = requests.Request('GET', url, headers=headers, data=payload)
        prepped = self.session.prepare_request(req)
        response = self.session.send(prepped)

        if response.ok:
            addresses = json.loads(response.text)['addresses']['address']

            for addr in addresses:
                if 'ip-address' in addr and addr['ip-address'] == address:
                    return addr['id'], response.status_code

        return None, response.status_code


    def create_address(self, address):
        """
        Creates an address object in SD based on the given IP address.
        You can create a single host, range, or a subnet (network).

        :param address string in octet form or subnet form (x.x.x.x/x)
        :return
        """

        url = self.root_url + sd_address_uri

        headers = {
            'Content-Type': 'application/vnd.juniper.sd.address-management.address+json;version=1;charset=UTF-8',
            'Accept': 'application/vnd.juniper.sd.address-management.address+json;version=1;q=0.01'
        }

        if "/" in address:
            address_type = "NETWORK"
        else:
            address_type = "IPADDRESS"

        if address[-1] == "/":
            address += "24"

        payload = json.dumps({
            'address': {
                'definition-type': 'CUSTOM',
                'name': str(address),
                'description': "Address added by ZTN_ELK",
                'address-type': address_type,
                'address-version': 'IPV4',
                'host-name': '',
                'ip-address': str(address)
            }
        })

        req = requests.Request('POST', url, headers=headers, data=payload)
        prepped = self.session.prepare_request(req)
        response = self.session.send(prepped)

        addr_id = json.loads(response.text)['address']['id']

        return response.status_code, addr_id


    def find_existing_service(self, servicename):
        """
        Helper method to find the id of an existing service in SD
        """

        url = self.root_url + sd_service_uri

        payload = {}
        headers = {
            'Accept': 'application/vnd.juniper.sd.service-management.services+json;version=1;q=0.01'
        }

        req = requests.Request('GET', url, headers=headers, data=payload)
        prepped = self.session.prepare_request(req)
        response = self.session.send(prepped)

        services = json.loads(response.text)['services']['service']

        service = [service for service in services if service['name'] == servicename]

        if len(service) == 0:
            return None

        return service[0]['id']


    def create_service(self, servicename, dstport, srcport, protocol_id):
        """
        Attempt to create a service based on the name from the log.
        If a 'Duplicate key' response is received, grab the ID from the existing service.
        """

        url = self.root_url + sd_service_uri

        headers = {
            'Content-Type': 'application/vnd.juniper.sd.service-management.service+json;version=1;charset=UTF-8',
            'Accept': 'application/vnd.juniper.sd.service-management.service+json;version=1;q=0.01'
        }

        protocol_types = {
            'tcp': 'PROTOCOL_TCP',
            'udp': 'PROTOCOL_UDP',
            'icmp': 'PROTOCOL_ICMP',
            'sun_rpc': 'PROTOCOL_SUN_RPC',
            'ms_rpc': 'PROTOCOL_MS_RPC',
            'icmpv6': 'PROTOCOL_ICMPV6',
            'other': 'PROTOCOL_OTHER'
        }

        protocol_type = ""

        if servicename == "None" or servicename is None:
            return 204, None
        elif servicename in protocol_types.keys():
            protocol_type = protocol_types[servicename]
        else:
            protocol_type = protocol_types["other"]

        payload = json.dumps({
            "service": {
                "is-group": "false",
                "name": servicename,
                "description": "Service automatically created by ZTN_ELK",
                "application-services": "",
                "protocols": {
                    "protocol": [{
                        "name": "term1",
                        "description": "first term",
                        "protocol-type": protocol_type,
                        "dst-port": dstport,
                        "enable-timeout": "false",
                        "inactivity-timeout": "",
                        "inactivity-time-type": "",
                        "alg": "None",
                        "src-port": srcport,
                        "disable-timeout": "false",
                        "protocol-number": int(protocol_id),
                        "enable-alg": "false",
                        "icmp-code": "0",
                        "icmp-type": "0"
                    }]
                }
            }
        })

        req = requests.Request('POST', url, headers=headers, data=payload)
        prepped = self.session.prepare_request(req)
        response = self.session.send(prepped)

        if "Duplicated key" in response.text:
            service_id = self.find_existing_service(servicename)
            return 302, service_id
        else:
            service_id = json.loads(response.text)['service']['id']
            return response.status_code, service_id


    def find_application(self, appname):
        if appname == "UNKNOWN":
            return None

        url = self.root_url + sd_application_uri

        payload = {}
        headers = {
            'Accept': 'application/vnd.juniper.sd.app-sig-management.app-sig-refs+json;version=1;q=0.01'
        }

        req = requests.Request('GET', url, headers=headers, data=payload)
        prepped = self.session.prepare_request(req)
        response = self.session.send(prepped)

        applications = json.loads(response.text)['app-sigs']['app-sig']

        app_id = [app for app in applications if app['name'] == appname]

        if len(app_id) == 0:
            return None

        return app_id[0]['id']


    def create_policy(self, **kwargs):
        policy_name = kwargs.get("policyname", None)
        policy_schedule_id = kwargs.get("policyscheduleid", "")
        policy_schedule_name = kwargs.get("policyscheduleid", "")
        url = self.root_url + sd_policy_uri

        headers = {
            'Content-Type': 'application/vnd.juniper.sd.policy-management.firewall.policy+json;version=2;charset=UTF-8',
            'Accept': 'application/vnd.juniper.sd.policy-management.firewall.policy+json;version=2;q=0.02'
        }

        random_id = str(uuid.uuid4().fields[-1])[:5]
        payload = json.dumps({
            "policy": {
                "name": ("ZTN_ELK_POLICY_" + random_id) if policy_name is None or policy_name == "" else policy_name,
                "description": "Policy created using ZTN_ELK",
                "policy-type": "GROUP",
                "showDevicesWithoutPolicy": 'false',
                "policy-position": "PRE",
                "manage-zone-policy": 'true',
                "manage-global-policy": 'true',
                "ips-mode": "NONE",
                "fwPolicy-type": "UNIFIED",
                "scheduler" : {
                    "id": policy_schedule_id,
                    "name": policy_schedule_name
                }
            }
        })

        req = requests.Request('POST', url, headers=headers, data=payload)
        prepped = self.session.prepare_request(req)
        response = self.session.send(prepped)

        if "already exists" in response.text:
            return 409, None

        policy_id = json.loads(response.text)['policy']['id']

        return response.status_code, policy_id


    '''
    Currently unusable due to limitations of SD API.
    '''
    def find_existing_policy(self, name):
        url = self.root_url + sd_policy_uri + '?filter=(fwPolicy-type eq \'not-empty\')'

        print(url)
        payload = {}
        headers = {
            'Accept': 'application/vnd.juniper.sd.policy-management.firewall.policies+json;version=2;q=0.02',
            'Access-Control': 'managePolicies'
        }

        req = requests.Request('GET', url, headers=headers, data=payload)
        prepped = self.session.prepare_request(req)
        response = self.session.send(prepped)

        json_obj = json.loads(response.text)
        print("Existing policy: \n")
        print(self.pretty_json(response.text))
        all_policies = json_obj['policies']['policy']

        for policy in all_policies:
            if policy['name'] == name:
                return policy['id']


    def get_rule_groupid(self, policy_id):
        url = self.root_url + sd_policy_uri + "/" + str(policy_id) + "/rules"

        payload = {}
        headers = {
            'Accept': 'application/vnd.juniper.sd.policy-management.firewall.rules+json;version=2;q=0.02',
            'Access-Control': 'managePolicies'
        }

        req = requests.Request('GET', url, headers=headers, data=payload)
        prepped = self.session.prepare_request(req)
        response = self.session.send(prepped)

        json_obj = json.loads(response.text)
        zone_id = json_obj['rules']['rule'][0]['id']
        global_id = json_obj['rules']['rule'][1]['id']

        return zone_id, global_id


    def create_tradtl_rule(self, src_addr_id, dest_addr_id, service_id, app_name, app_id, policy_id, src_zone, dest_zone, **kwargs):
        rule_name = kwargs.get("rulename", None)
        url = self.root_url + sd_policy_uri + "/" + str(policy_id) + "/rules"

        headers = {
            'Content-Type': 'application/vnd.juniper.sd.policy-management.firewall.rule+json;version=2;charset=UTF-8',
            'Accept': 'application/vnd.juniper.sd.policy-management.firewall.rule+json;version=2;q=0.02',
            'Access-Control': 'ModifyPolicy'
        }

        random_id = str(uuid.uuid4().fields[-1])[:5]
        rule_group_id_zone, rule_group_id_global = self.get_rule_groupid(policy_id)

        if service_id is not None:
            services = {
                "service-reference": [{
                    "id": service_id,
                    "is-group": "false"
                }]
            }
        else:
            services = {}

        if app_id is not None:
            applications = {
                "reference": [{
                    "id": app_id,
                    "name": app_name
                }]
            }
        else:
            applications = {}

        payload = json.dumps({
            "rule": {
                "rule-group-type": "CUSTOM",
                "rule-profile": {
                    "profile-type": "INHERITED",
                    "user-defined-profile": {},
                    "custom-profile": {
                        "web-redirect": "false",
                        "tcp-syn-check": "false",
                        "infranet-redirect": "NONE",
                        "destination-address-translation": "NONE",
                        "redirect": "NONE",
                        "web-redirect-to-https": "false",
                        "authentication-type": "NONE",
                        "service-offload": "false",
                        "tcp-seq-check": "false"
                    }
                },
                "rule-order": 0,
                "ips-enabled": "false",
                "policy-id": policy_id,
                "destination-address": {
                    "exclude-list": "false",
                    "addresses": {
                        "address-reference": [{
                            "id": dest_addr_id
                        }]
                    }
                },
                "version": 2,
                "rule-type": "RULE",
                "vpn-tunnel-refs": {},
                "disabled": "false",
                "rule-group-id": rule_group_id_zone,
                "scheduler": {

                },
                "services": services,
                "applications": applications,
                "action": "DENY",
                "sec-intel-policy": {},
                "custom-column-data": "",
                "description": "created using ZTN_ELK automation",
                "sourceidentities": {},
                "destination-zone": {
                    "zone": [{
                        "zone-type": "ZONE",
                        "resolved": "false",
                        "name": dest_zone,
                        "variable-id": 0
                    }]
                },
                "name": ("ZTN_ELK_RULE_" + random_id) if rule_name is None or rule_name == "" else rule_name,
                "source-zone": {
                    "zone": [{
                        "zone-type": "ZONE",
                        "resolved": "false",
                        "name": src_zone,
                        "variable-id": 0
                    }]
                },
                "source-address": {
                    "exclude-list": "false",
                    "addresses": {
                        "address-reference": [{
                            "id": src_addr_id
                        }]
                    }
                },
                "condition-actions": {}
            }
        })

        req = requests.Request('POST', url, headers=headers, data=payload)
        prepped = self.session.prepare_request(req)
        response = self.session.send(prepped)

        return response.status_code


    def check_scheduler_exists(self, policy_schedule_name):
        """
        Check if a policy scheduler exists.
        If it does, return its id.
        Otherwise, return none

        :return scheduler ID if a matching object exists, None otherwise ; status code
        """
        url = self.root_url + sd_scheduler_uri + "/schedulers"
        payload = {}

        headers = {
            'Accept': 'application/vnd.juniper.sd.scheduler-management.schedulers+json;version=1;q=0.01',
            'Access-Control': 'sdManageScheduler'
        }

        req = requests.Request('GET', url, headers=headers, data=payload)
        prepped = self.session.prepare_request(req)
        response = self.session.send(prepped)

        json_obj = json.loads(response.text)
        print("Existing policy schedules: \n")
        print(self.pretty_json(response.text))
        all_schedules = json_obj['schedulers']

        for schedule in all_schedules:
            if schedule['name'] == policy_schedule_name:
                return schedule['id'], response.status_code

        return None

    # Create a policy scheduler and return its id + string
    def create_scheduler(self, name, **kwargs):
        """
        Create a policy scheduler

        :return scheduler ID, scheduler name ; status code
        """

        scheduler_name = kwargs.get("schedulername", "")
        if scheduler_name is None or scheduler_name == "":
            scheduler_name = "ZTN_ELK_SCHEDULER_" + str(uuid.uuid4().fields[-1])[:5]

        selected_days = kwargs.get("selected_days", [])
        start_time = kwargs.get("start_time", "")
        end_time = kwargs.get("end_time", "")
        start_date = kwargs.get("start_date", "")
        end_date = kwargs.get("end_date", "")

        print(selected_days)
        print(start_time)
        print(end_time)
        print(start_date)
        print(end_date)
        return 0,0

        url = self.root_url + sd_scheduler_uri

        headers = {
            'Accept': 'application/vnd.juniper.sd.scheduler-management.scheduler+json;version=1;q=0.01',
            'Access-Control': 'sdCreateScheduler',
            'Content-Type': 'application/vnd.juniper.sd.scheduler-management.scheduler+json;version=1;charset=UTF-8'
        }

        # payload = json.dumps({
        # {
        #     "scheduler" : {
        #     "name" : scheduler_name,
        #     "description" : "Scheduler created using ZTN_ELK",
        #     "start-date1" : start_date,
        #     "stop-date1" : end_date,
        #     "start-date2" : "",
        #     "stop-date2" : "",
        #     "schedules" : {
        #     "schedule" : [ {
        #     "day" : selected_days,
        #     "start-time1" : start_time,
        #     "stop-time1" : end_time,
        #     "start-time2" : "",
        #     "stop-time2" : "",
        #     "exclude" : False,
        #     "all-day" : False
        #     } ]
        #     },
        #     }
        #  })

        req = requests.Request('POST', url, headers=headers, data=payload)
        prepped = self.session.prepare_request(req)
        response = self.session.send(prepped)
        # policy_id = json.loads(response.text)['policy']['id']
        return response.text