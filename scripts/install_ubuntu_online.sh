#!/bin/sh

# Exit if any subcommand fails
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NO_COLOR='\033[0m'
CLEAR_LINE='\r\033[K'

printf "${CLEAR_LINE}[1/3]  Checking dependencies..."

if ! command -v pip > /dev/null && ! command -v pip3 > /dev/null; then
  printf "${CLEAR_LINE}${RED}   You must install pip on your system before setup can continue${NO_COLOR}\n"
  exit -1
fi

version=$(python -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
if [ "$version" -lt "30" ]; then
    printf "This script requires python 3.0 or greater"
    printf "This may require using python3 instead of python when running the app.\n"
    exit 1
fi

if ! command -v docker-compose > /dev/null; then
  printf "${CLEAR_LINE}${RED}   You must install docker-compose on your system before setup can continue${NO_COLOR}\n"
  exit -1
fi

printf "\n[2/3]  Installing pip requirements..."

if command -v pip > /dev/null; then
  pip install -r requirements.txt
  pip install docker-compose
elif command -v pip3 > /dev/null; then
  pip3 install -r requirements.txt
  pip3 install docker-compose
fi

printf "\n[3/3]  Setting virtual memory per ECS best practices. Will persist across reboots."
sysctl -w vm.max_map_count=262144
sudo echo vm.max_map_count=262144 >> /etc/sysctl.conf

printf "\nDependencies installation complete.\n"
printf "Please change these values:"
printf "\n\t - IP address within logstash.conf to your server's IP"
printf "\n\t - Junos Space Security Director base IP address within ztn/ztn_elk.py\n"
printf "\nOnce you have done these steps, you can start the ELK stack with ${GREEN}docker-compose -d${NO_COLOR}"
printf "\nTo start the actual ZTN application, run ${GREEN}python app.py${NO_COLOR} after changing into the folder.\n"
