"""
    Makes API calls to Junos Space Security Director for each
     qqqstep of a workflow.
"""

import requests
import json
from pprint import pprint
from time import sleep
import uuid

# API URLs + headers
ecs_base_url = "http://172.16.30.142:9200"  # elasticsearch ip

sd_base_url = "https://172.25.125.101"     # security director ip/port
sd_address_uri = "/api/juniper/sd/address-management/addresses"
sd_service_uri = "/api/juniper/sd/service-management/services"
sd_policy_uri = "/api/juniper/sd/policy-management/firewall/policies"


def pretty_json(text):
    """
    Helper function to print JSON with nice indents on the CLI.

    :param text plain-text that can be converted to a JSON object
    """
    return json.dumps(json.loads(text), indent=2)


def check_address_exists(address):
    """
    Checks whether an address matches the attributes of an address object
    already in Security Director.

    :return address ID if a matching object exists, None otherwise ; status code
    """

    url = sd_base_url + sd_address_uri

    payload = {}

    headers = {
        'Accept': 'application/vnd.juniper.sd.address-management.address-refs+json;version=1;q=0.01',
        'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg=='
    }

    response = requests.request(
        "GET", url, headers=headers, data=payload, verify=False)

    if response.ok:
        addresses = json.loads(response.text)['addresses']['address']

        for addr in addresses:
            if 'ip-address' in addr and addr['ip-address'] == address:
                return addr['id'], response.status_code

    return None, response.status_code


def create_address(address):
    """
    Creates an address object in SD based on the given IP address.
    You can create a single host, range, or a subnet (network).

    :param address string in octet form or subnet form (x.x.x.x/x)
    :return
    """

    url = sd_base_url + sd_address_uri

    headers = {
        'Content-Type': 'application/vnd.juniper.sd.address-management.address+json;version=1;charset=UTF-8',
        'Accept': 'application/vnd.juniper.sd.address-management.address+json;version=1;q=0.01',
        'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg=='
    }

    if "/" in address:
        address_type = "NETWORK"
    else:
        address_type = "IPADDRESS"

    print(address_type)

    # random_id = str(uuid.uuid4().fields[-1])[:5]
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

    response = requests.request(
        "POST", url, headers=headers, data=payload, verify=False)

    print(response.text)
    addr_id = json.loads(response.text)['address']['id']

    return response.status_code, addr_id


def find_existing_service(appname):
    url = sd_base_url + sd_service_uri

    payload = {}
    headers = {
        'Accept': 'application/vnd.juniper.sd.service-management.services+json;version=1;q=0.01',
        'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg=='
    }

    response = requests.request(
        "GET", url, headers=headers, data=payload, verify=False)

    services = json.loads(response.text)['services']['service']

    service = [service for service in services if service['name'] == appname]

    return service[0]['id']


def create_application(appname, servicename, dstport, srcport, protocol_id):
    url = sd_base_url + sd_service_uri

    headers = {
        'Content-Type': 'application/vnd.juniper.sd.service-management.service+json;version=1;charset=UTF-8',
        'Accept': 'application/vnd.juniper.sd.service-management.service+json;version=1;q=0.01',
        'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg=='
    }

    # random_id = str(uuid.uuid4().fields[-1])[:5]
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
            "name": appname,
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

    # payload = {}
    response = requests.request(
        "POST", url, headers=headers, data=payload, verify=False)

    if "Duplicated key" in response.text:
        service_id = find_existing_service(appname)
    else:
        service_id = json.loads(response.text)['service']['id']

    return response.status_code, service_id


def create_policy(**kwargs):
    policy_name = kwargs.get("policyname", None)
    url = sd_base_url + sd_policy_uri

    headers = {
        'Content-Type': 'application/vnd.juniper.sd.policy-management.firewall.policy+json;version=2;charset=UTF-8',
        'Accept': 'application/vnd.juniper.sd.policy-management.firewall.policy+json;version=2;q=0.02',
        'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg=='
    }

    random_id = str(uuid.uuid4().fields[-1])[:5]
    payload = json.dumps({
        "policy": {
            "name": ("ZTN_ELK_POLICY_" + random_id) if policy_name is None or policy_name == "" else policy_name,
            "description": "Policy crated using ZTN_ELK",
            "policy-type": "GROUP",
            "showDevicesWithoutPolicy": 'false',
            "policy-position": "PRE",
            "manage-zone-policy": 'true',
            "manage-global-policy": 'true',
            "ips-mode": "NONE",
            "fwPolicy-type": "TRADITIONAL"
        }
    })

    response = requests.request(
        "POST", url, headers=headers, data=payload, verify=False)

    if "already exists" in response.text:
        return 409, None

    policy_id = json.loads(response.text)['policy']['id']

    return response.status_code, policy_id


def get_rule_groupid(policy_id):
    url = sd_base_url + sd_policy_uri + "/" + str(policy_id) + "/rules"

    headers = {
        'Accept': 'application/vnd.juniper.sd.policy-management.firewall.rules+json;version=2;q=0.02',
        'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg==',
        'Access-Control': 'managePolicies'
    }

    response = requests.request(
        "GET", url, headers=headers, verify=False)

    json_obj = json.loads(response.text)
    zone_id = json_obj['rules']['rule'][0]['id']
    global_id = json_obj['rules']['rule'][1]['id']

    return zone_id, global_id


def create_tradtl_rule(src_addr_id, dest_addr_id, service_id, policy_id, src_zone, dest_zone, **kwargs):
    rule_name = kwargs.get("rulename", None)
    url = sd_base_url + sd_policy_uri + "/" + str(policy_id) + "/rules"

    headers = {
        'Content-Type': 'application/vnd.juniper.sd.policy-management.firewall.rule+json;version=2;charset=UTF-8',
        'Accept': 'application/vnd.juniper.sd.policy-management.firewall.rule+json;version=2;q=0.02',
        'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg==',
        'Access-Control': 'ModifyPolicy'
    }

    random_id = str(uuid.uuid4().fields[-1])[:5]
    rule_group_id_zone, rule_group_id_global = get_rule_groupid(policy_id)

    if service_id is not None:
        services = {
            "service-reference": [{
                "id": service_id,
                "is-group": "false"
            }]
        }
    else:
        services = {}

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
            "scheduler": {},
            "services": services,
            "action": "DENY",
            "sec-intel-policy": {},
            "custom-column-data": "",
            "description": "created using automation",
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

    response = requests.request(
        "POST", url, headers=headers, data=payload, verify=False)

    return response.status_code


def create_unified_rule():
    pass
