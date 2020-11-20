interface = {
    "untagged_vlan": {
        "id": 7,
        "url": "http://netbox.wiscnet.net/api/ipam/vlans/7/",
        "vid": 3000,
        "name": "3000",
        "display_name": "3000 (3000)"
    },
    "tagged_vlans": [
        {
            "id": 7,
            "url": "http://netbox.wiscnet.net/api/ipam/vlans/7/",
            "vid": 3000,
            "name": "3000",
            "display_name": "3000 (3000)"
        },
        {
            "id": 8,
            "url": "http://netbox.wiscnet.net/api/ipam/vlans/8/",
            "vid": 3417,
            "name": "3471",
            "display_name": "3417 (3471)"
        }
    ]
}

modes = [ 'untagged_vlan', 'tagged_vlan' ]
for mode in modes:
        if mode in interface:
            print(interface[mode])
