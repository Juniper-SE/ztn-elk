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

# Global variables
headers = {
    'Content-Type': 'application/vnd.juniper.sd.address-management.address+json;version=1;charset=UTF-8',
    'Accept': 'application/vnd.juniper.sd.address-management.address+json;version=1;q=0.01',
    'Authorization': 'Basic c3VwZXI6MTIzanVuaXBlcg=='
}


def pretty_json(text):
    return json.dumps(json.loads(text), indent=2)


def create_address(address):
    url = sd_base_url + sd_address_uri

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

    print(pretty_json(response.text))

    json_obj = json.loads(response.text)
    addr_id = json_obj['address']['id']
    print(addr_id)
    return response.ok, addr_id


def create_application(servicename, dstport, srcport):
    url = sd_base_url + sd_service_uri

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
            "is-group": False,
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

    random_id = str(uuid.uuid4().fields[-1])[:5]
    payload = json.dumps({
        "policy": {
            "name": "ZTN_ELK_POLICY_" + random_id,
            "description": "Policy crated using ZTN_ELK",
            "policy-type": "GROUP",
            "showDevicesWithoutPolicy": False,
            "policy-position": "PRE",
            "manage-zone-policy": True,
            "manage-global-policy": True,
            "ips-mode": "NONE",
            "fwPolicy-type": "TRADITIONAL"
        }
    })

    # payload = {}
    response = requests.request(
        "POST", url, headers=headers, data=payload, verify=False)

    return response.ok


def create_rule():
    pass
