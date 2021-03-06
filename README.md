# ZTN - ELK
A zero-trust network implementation for Juniper SRXs using ELK stack and Junos Space Security Director.

Based off of zippy: https://github.com/dpresbit/zippy

The Build: The ELK docker "stack" consists of 3 images with the following image tags:

- Elasticsearch "E"
- Logstash "L"
- Kibana "K"

## DEPENDENCIES:

** Linux Deps listed below and instructions

- PIP Installer
    - pip for istalling python packages
- Major PIP Packages
    - flask (https://pypi.org/project/Flask/#files)
    - flask_restful (https://pypi.org/project/Flask-RESTful/#files)
    - netaddr (https://pypi.org/project/netaddr/#files)
    - requests (https://pypi.org/project/requests/)
- Requirements
    - `pip install -r requirements.txt`
    - Installs all the necessary pip requirements

Dependencies Note: To install packages while offline, download the wheel files from each link above, then use:

`pip install <wheel file name> --user`

## To deploy this stack (tested on Ubuntu 18.04.2 and Windows10 with 2/26 Docker)

Create a directory and place the included docker-compose.yml file and all yml and conf files inside of it. Change the IP address within logstash.conf on line 48 to your server IP. Change the variables in ztn.yml to reflect your environment. (TODO -- env variables)

You will also need to install docker-compose as a pre-requisite. See: https://docs.docker.com/compose/install/

Also, make sure your virtual memory is set per Elastisearch best practices: `sysctl -w vm.max_map_count=262144` Note: To make this setting persistent, do the following command then it will persist across reboots: `sudo echo vm.max_map_count=262144 >> /etc/sysctl.conf`

## Starting and Operating Zippy

CD to the zippy master directory and chmod 666 esdata directory, then issue the following command:

`docker-compose up -d`

restart a single container

`docker-compose restart <container name>`

use this command to ensure the three containers comprising the "stack" are running:

`docker ps`

NOTE: If you notice a single container is exiting or not running, restart the container with docker-compose command but without the -d option so it'll show interactive messages

Connect to the Kibana portal: (replace localhost with docker server IP if not on host):

http://localhost:5601

Attach to the shell of a container to get to the command line (you can replace batch with your favorite shell)

`docker-compose exec -u 0 elasticsearch bash`
`docker-compose exec -u 0 logstash bash`
`docker-compose exec -u 0 kibana bash`
** Detach from container using "exit" command

To stop the cluster (all containers), type

`docker-compose down -v`

** Pro-Tip:

`docker-compose down -v && docker-compose up -d`

Data volumes will persist, so it???s possible to start the cluster again with the same data using docker-compose up. To destroy the cluster and the data volumes, just type

`docker-compose down -v`

Check your Kibana interface by going to http://:5601. Make sure you have your incoming iptables/ufw entry in place so you can access the web interface. Also, enter incoming ports for receiving syslog (traffic logs by default will be received on port 5550 UDP)

`sudo iptables -A INPUT -p tcp --dport 5601 -j ACCEPT`
`sudo iptables -A INPUT -p udp --dport 5550 -j ACCEPT`

NOTE:

Once you have the ELK stack running (all three containers), go into the 'mappings' directory and do the following: `./create_ecs_junos_index` This command will publish data type mappings into elastic so that, say, your IP address fields show up as IPs...etc.

## TROUBLESHOOTING:

Send a test message to UDP port 5550 on logstash

`echo 'test message' | nc -v -u -w 0 localhost 5550`

You can also 'cat' the sample traffic logs to simulate PANOS syslog to logstash
Be aware that there is no timestamp in the first field b/c kibana would dedup the same messages coming in, so ensure you use this command to generate a UNIQUE log

`echo $(date +"%a %b %d %T %Y") $(cat traffic_log_hostname)`

If the netcat test is successful youll see a message: Connection to localhost 5550 port [udp/*] succeeded! If you don't see an output from the nc command it did not connect to the port on logstash - check that your container is up and running TCPdump from docker host machine to check for incoming syslog from NGFW

`tcpdump -v -i any -n port 5550`
`tcpdump -v -i any -n port 5551`

to see payload of packet and save to log

`tcpdump -nnvvXSs 1514 -i any -n port 5550 > capture.log`

Traffic Generator - For linux only

`genlog <traffic|threat|dataf|.....all>`

Note on genlog. NetCAT is used in the script and for some reason it sends two blank streams of data to logstash that result in dissect errors when viewing in kibana. So for everyone legit log that comes in you'll see two failures. This is only a result of using this script and the dissect failure entries in kibana can be disregarded.