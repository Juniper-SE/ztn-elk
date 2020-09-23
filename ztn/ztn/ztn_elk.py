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


def create_application():
    pass


def create_policy():
    pass


def create_rule():
    pass
