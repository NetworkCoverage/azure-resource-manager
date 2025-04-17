#!/bin/bash

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <customer_shortname> <admin_password> <ctlprivateip> <gateway_dns_name>"
  exit 1
fi

customershortname="$1"
adminpass="$2"
ctlprivateip="$3"
gatewaydnsname="$4"
deviceid=$(cat /proc/sys/kernel/random/uuid)

read -r -d '' json_payload <<EOF
{
  "providerName": "local",
  "username": "admin",
  "password": "$adminpass",
  "deviceId": "$deviceid"
}
EOF

response=$(curl --insecure --location --request POST "https://$ctlprivateip:8443/admin/login" \
--header "Content-Type: application/json" \
--header "Accept: application/vnd.appgate.peer-v19+json" \
--data "$json_payload")

token=$(echo $response | jq -r '.token')

sites=$(curl --insecure --location --request GET "https://$ctlprivateip:8443/admin/sites" \
--header "Content-Type: application/json" \
--header "Accept: application/vnd.appgate.peer-v19+json" \
--header "Authorization: Bearer $token")

siteid=$(echo $sites | jq -r '.data[0].id')

read -r -d '' json_payload <<EOF
{
  "name": "$customershortname-gateway",
  "hostname": "$gatewaydnsname",
  "site": "$siteid",
  "clientInterface": {
    "proxyProtocol": false,
    "hostname": "automatic.hostname.assignment",
    "httpsPort": 443,
    "dtlsPort": 443,
    "allowSources": [
      {
        "address": "0.0.0.0",
        "netmask": 0
      },
      {
        "address": "::",
        "netmask": 0
      }
    ]
  },
  "networking": {
    "hosts": [],
    "nics": [
      {
        "enabled": true,
        "name": "eth0",
        "ipv4": {
          "dhcp": {
            "enabled": true,
            "dns": true,
            "routers": true
          }
        }
      }
    ],
    "routes": []
  },
  "ntp": {
    "servers": [
      {
        "hostname": "0.ubuntu.pool.ntp.org"
      },
      {
        "hostname": "1.ubuntu.pool.ntp.org"
      },
      {
        "hostname": "2.ubuntu.pool.ntp.org"
      },
      {
        "hostname": "3.ubuntu.pool.ntp.org"
      }
    ]
  },
  "gateway": {
    "enabled": true,
    "vpn": {
      "weight": 100,
      "allowDestinations": [
        {
          "address": "0.0.0.0",
          "netmask": 0,
          "nic": "eth0"
        }
      ]
    }
  }
}
EOF

gw=$(curl --insecure --location --request POST "https://$ctlprivateip:8443/admin/appliances" \
--header "Content-Type: application/json" \
--header "Accept: application/vnd.appgate.peer-v19+json" \
--header "Authorization: Bearer $token" \
--data "$json_payload")

gwid=$(echo $gw | jq -r '.id')

curl --insecure --location --request POST "https://$ctlprivateip:8443/admin/appliances/$gwid/export" \
--header "Content-Type: application/json" \
--header "Accept: application/vnd.appgate.peer-v19+json" \
--header "Authorization: Bearer $token" \
--data '{
  "provideCloudSSHKey": true,
  "allowCustomization": false,
  "validityDays": 1
}' > /home/cz/seed.json