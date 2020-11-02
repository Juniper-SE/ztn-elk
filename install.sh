#!/bin/sh

# Exit if any subcommand fails
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NO_COLOR='\033[0m'
CLEAR_LINE='\r\033[K'

printf "${CLEAR_LINE}[1/6]   checking dependencies"

if ! command -v pip > /dev/null; then
  printf "${CLEAR_LINE}${RED}   You must install pip on your system before setup can continue${NO_COLOR}\n"
  exit -1
fi

version=$(python -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
if [ "$version" -lt "30" ]; then
    printf "This script requires python 3.0 or greater"
    printf "This may require using python3 instead of python when running the app.\n"
    exit 1
fi

printf "${CLEAR_LINE}[2/6]⏳   Installing yarn packages"