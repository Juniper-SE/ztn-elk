import requests
import json
from pprint import pprint
from time import sleep

# API URLs
elasticsearch_base_url = "http://172.16.30.142:9200"
securitydirector_base_url = "placeholder"

# Global variables
previous_num_hits = 0
hits = []


def pretty_json(text):
    return json.dumps(json.loads(text), indent=2)


def get_junos_syslog_index():
    idx_url = elasticsearch_base_url + "/junos-syslog-3/_search"
    print(idx_url)

    resp = requests.get(idx_url)

    # print(pretty_json(resp.text))
    resp_json = resp.json()
    print(resp_json['hits']['total']['value'])

    current_num_hits = resp_json['hits']['total']['value']
    global previous_num_hits
    if current_num_hits > previous_num_hits:
        previous_num_hits += int(current_num_hits)
        hits = resp_json['hits']


def create_SD_FW_policy(values):
    new_policy = {
        {
            "policy": {
                "policy-details": [{
                    "app-fw-policy": {
                        "id": "Integer",
                        "name": "String"
                    },
                    "rule-group-type": ["CUSTOM", "ZONE", "GLOBAL"]
                }]
            }
        }
    }
    pass


if __name__ == "__main__":
    while(True):
        get_junos_syslog_index()
        sleep(10)
