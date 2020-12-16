#!/bin/sh

# Exit if any subcommand fails
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NO_COLOR='\033[0m'
CLEAR_LINE='\r\033[K'

printf "\n[1/5]  Making deps folder and unzipping deps.tar.gz"
cd ../installdeps
mkdir deps
tar -C deps -xzvf deps.tar.gz

printf "\n[2/5]  Installing deps."
cd deps
dpkg -i *.deb
pip install Werkzeug-1.0.0-py2.py3-none-any.whl \
pytz-2019.3-py2.py3-none-any.whl \
Babel-2.8.0-py2.py3-none-any.whl \
MarkupSafe-1.1.1-cp27-cp27mu-manylinux1_x86_64.whl \
Jinja2-2.11.1-py2.py3-none-any.whl \
click-7.1.1-py2.py3-none-any.whl \
itsdangerous-1.1.0-py2.py3-none-any.whl \
Flask-1.1.1-py2.py3-none-any.whl \
six-1.14.0-py2.py3-none-any.whl \
aniso8601-8.0.0-py2.py3-none-any \
Flask_RESTful-0.3.8-py2.py3-none-any.whl \
netaddr-0.7.19-py2.py3-none-any.whl

printf "\n[3/5]  Installing docker."
mkdir docker
tar -C docker -xzvf docker.tar.gz
cd docker
dpkg -i *.deb

printf "${CLEAR_LINE}[4/5]  Checking dependencies..."

if ! command -v pip > /dev/null && ! command -v pip3 > /dev/null; then
  printf "${CLEAR_LINE}${RED}   You must install pip on your system before setup can continue${NO_COLOR}\n"
  exit -1
fi

version1=$(python -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
if [ "$version" -lt "27" ]; then
    printf "This script requires python 2.7 or greater\n"
    printf "This may require using python3 instead of python when running the app.\n"
    exit 1
fi

if ! command -v docker-compose > /dev/null; then
  printf "${CLEAR_LINE}${RED}   You must install docker-compose on your system before setup can continue${NO_COLOR}\n"
  exit -1
fi

printf "\n[5/5]  Setting virtual memory per ECS best practices. Will persist across reboots."
sysctl -w vm.max_map_count=262144
sudo echo vm.max_map_count=262144 >> /etc/sysctl.conf

printf "\nDependencies installation complete.\n"
printf "Please change these values:"
printf "\n\t - IP address within logstash.conf to your server's IP"
printf "\n\t - Junos Space Security Director base IP address within ztn/ztn_elk.py\n"
printf "\nOnce you have done these steps, you can start the ELK stack with ${GREEN}docker-compose -d${NO_COLOR}"
printf "\nTo start the actual ZTN application, run ${GREEN}python app.py${NO_COLOR} after changing into the folder.\n"
