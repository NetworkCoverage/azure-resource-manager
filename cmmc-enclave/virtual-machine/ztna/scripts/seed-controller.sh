#!/bin/bash

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <customer_shortname> <admin_password> <hostname>"
  exit 1
fi

customershortname="$1"
adminPass="$2"
hostname="$3"

cz-seed \
  --dhcp-ipv4 eth0 \
  --appliance-name "${customershortname}-controller" \
  --profile-hostname "$hostname" \
  --hostname "$hostname" \
  --admin-hostname $hostname \
  --admin-password "$adminPass" > /home/cz/seed.json
