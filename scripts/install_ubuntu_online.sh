#!/bin/sh

# Copyright (c) Juniper Networks, Inc., 2020 - 2022. All rights reserved.

# Notice and Disclaimer: This code is licensed to you under the GNU General Public License v3.0.
# You may not use this code except in compliance with the License.
# This code is not an official Juniper product.
# You can obtain a copy of the License at https://www.gnu.org/licenses/gpl-3.0.txt

# SPDX-License-Identifier: GPL-3.0-or-later

# Third-Party Code: This code may depend on other components under separate copyright notice and license terms. Your use of the source code for those components is subject to the terms and conditions of the respective license as noted in the Third-Party source code file.

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

version=$(python3 -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
if [ "$version" -lt "30" ]; then
    printf "This script requires python 3.0 or greater"
    printf "This may require using python3 instead of python when running the app.\n"
    exit 1
fi

if ! command -v docker-compose > /dev/null; then
  printf "${CLEAR_LINE}${RED}   You must install docker-compose on your system before setup can continue${NO_COLOR}\n"
  exit -1
fi

printf "\n[2/4]  Installing pip requirements..."

if command -v pip > /dev/null; then
  cd ..
  pip install -r requirements.txt
elif command -v pip3 > /dev/null; then
  cd ..
  pip3 install -r requirements.txt
fi

printf "\n[3/4]  Installing docker-compose."
sudo curl -L https://github.com/docker/compose/releases/download/1.21.2/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

printf "\n[4/4]  Setting virtual memory per ECS best practices. Will persist across reboots."
sudo sysctl -w vm.max_map_count=262144
sudo echo vm.max_map_count=262144 >> /etc/sysctl.conf

printf "\nDependencies installation complete.\n"
printf "Please change these values:"
printf "\n\t - IP address within logstash.conf to your server's IP"
printf "\n\t - Junos Space Security Director base IP address within ztn/ztn_elk.py\n"
printf "\nOnce you have done these steps, you can start the ELK stack with ${GREEN}docker-compose -d${NO_COLOR}"
printf "\nTo start the actual ZTN application, run ${GREEN}python app.py${NO_COLOR} after changing into the folder.\n"
