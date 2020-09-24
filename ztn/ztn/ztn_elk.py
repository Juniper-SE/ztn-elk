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
    return json.dumps(json.loads(text), indent=2)


def create_address(address):
    url = sd_base_url + sd_address_uri

    headers = {
        'Content-Type': 'application/vnd.juniper.sd.address-management.address+json;version=1;charset=UTF-8',
        'Accept': 'application/vnd.juniper.sd.address-management.address+json;version=1;q=0.01',
        'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg=='
    }

    random_id = str(uuid.uuid4().fields[-1])[:5]
    payload = json.dumps({
        'address': {
            'definition-type': 'CUSTOM',
            'name': "ZTN_ELK_addr_" + random_id,
            'description': "Address added by ZTN_ELK",
            'address-type': 'IPADDRESS',
            'address-version': 'IPV4',
            'host-name': '',
            'ip-address': str(address)
        }
    })

    # payload = {}
    response = requests.request(
        "POST", url, headers=headers, data=payload, verify=False)

    addr_id = json.loads(response.text)['address']['id']

    return response.ok, addr_id


def create_application(servicename, dstport, srcport):
    url = sd_base_url + sd_service_uri

    headers = {
        'Content-Type': 'application/vnd.juniper.sd.service-management.service+json;version=1;charset=UTF-8',
        'Accept': 'application/vnd.juniper.sd.service-management.service+json;version=1;q=0.01',
        'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg=='
    }

    random_id = str(uuid.uuid4().fields[-1])[:5]
    protocol_types = {
        'tcp': 'PROTOCOL_TCP',
        'udp': 'PROTOCOL_UDP',
        'icmp': 'PROTOCOL_ICMP',
        'sun_rpc': 'PROTOCOL_SUN_RPC',
        'ms_rpc': 'PROTOCOL_MS_RPC',
        'icmpv6': 'PROTOCOL_ICMPV6',
        'other': 'PROTOCOL_OTHER'
    }

    if servicename == "None":
        return
    elif servicename in protocol_types.keys():
        protocol_type = protocol_types[servicename]
    else:
        protocol_type = protocol_types["other"]

    payload = json.dumps({
        "service": {
            "is-group": 'false',
            "name": "SER_ZTN_ELK_" + random_id,
            "description": "service created by ZTN-ELK",
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
                    "rpc-program-number": "",
                    "sunrpc-program-tcp": "",
                    "sunrpc-program-type": "",
                    "uuid": "",
                    "msrpc-program-tcp": "",
                    "msrpc-program-type": "",
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

    return response.ok


def create_policy():
    url = sd_base_url + sd_policy_uri

    headers = {
        'Content-Type': 'application/vnd.juniper.sd.policy-management.firewall.policy+json;version=2;charset=UTF-8',
        'Accept': 'application/vnd.juniper.sd.policy-management.firewall.policy+json;version=2;q=0.02',
        'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg=='
    }

    random_id = str(uuid.uuid4().fields[-1])[:5]
    payload = json.dumps({
        "policy": {
            "name": "ZTN_ELK_POLICY_" + random_id,
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

    # payload = {}
    response = requests.request(
        "POST", url, headers=headers, data=payload, verify=False)

    policy_id = json.loads(response.text)['policy']['id']

    return response.ok, policy_id


def create_rule():
    pass

#     {
# 	"rule": {
# 		"rule-group-type": "CUSTOM",
# 		"rule-profile": {
# 			"profile-type": "INHERITED",
# 			"user-defined-profile": {},
# 			"custom-profile": {
# 				"web-redirect": false,
# 				"tcp-syn-check": false,
# 				"infranet-redirect": "NONE",
# 				"destination-address-translation": "NONE",
# 				"redirect": "NONE",
# 				"web-redirect-to-https": false,
# 				"authentication-type": "NONE",
# 				"service-offload": false,
# 				"tcp-seq-check": false
# 			}
# 		},
# 		"rule-order": 0,
# 		"ips-enabled": false,
# 		"policy-id": 229716,
# 		"destination-address": {
# 			"exclude-list": false,
# 			"addresses": {
# 				"address-reference": [{
# 					"id": 196608
# 				}]
# 			}
# 		},
# 		"version": 2,
# 		"rule-type": "RULE",
# 		"vpn-tunnel-refs": {},
# 		"disabled": false,
# 		"rule-group-id": 229715,
# 		"scheduler": {},
# 		"services": {
# 			"service-reference": [{
# 				"id": 163840,
# 				"is-group": false
# 			}]
# 		},
# 		"action": "PERMIT",
# 		"sec-intel-policy": {},
# 		"custom-column-data": "",
# 		"description": "created using automation",
# 		"sourceidentities": {},
# 		"destination-zone": {
# 			"zone": [{
# 				"zone-type": "ZONE",
# 				"resolved": false,
# 				"name": "untrust",
# 				"variable-id": 0
# 			}]
# 		},
# 		"name": "Rule-1",
# 		"source-zone": {
# 			"zone": [{
# 				"zone-type": "ZONE",
# 				"resolved": false,
# 				"name": "trust",
# 				"variable-id": 0
# 			}]
# 		},
# 		"source-address": {
# 			"exclude-list": false,
# 			"addresses": {
# 				"address-reference": [{
# 					"id": 196608
# 				}]
# 			}
# 		},
# 		"condition-actions": {}
# 	}
# }
