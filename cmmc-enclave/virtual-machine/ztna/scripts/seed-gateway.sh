#!/bin/bash

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <customer_shortname> <admin_password> <ctl_private_ip> <gateway_dns_name>"
  exit 1
fi

customershortname="$1"
adminpass="$2"
ctlprivateip="$3"
gatewaydnsname="$4"
deviceid=$(cat /proc/sys/kernel/random/uuid)

echo "[1/8] Logging in to Appgate Controller at $ctlprivateip..."

read -r -d '' json_payload <<EOF
{
  "providerName": "local",
  "username": "admin",
  "password": "$adminpass",
  "deviceId": "$deviceid"
}
EOF

response=$(curl --silent --insecure --location --request POST "https://$ctlprivateip:8443/admin/login" \
--header "Content-Type: application/json" \
--header "Accept: application/vnd.appgate.peer-v19+json" \
--data "$json_payload")

token=$(echo "$response" | jq -r '.token')

if [ "$token" == "null" ] || [ -z "$token" ]; then
  echo "Failed to authenticate. Check admin password or controller IP."
  exit 1
fi

echo "Logged in. Token retrieved."

echo "[2/8] Getting site ID..."

sites=$(curl --silent --insecure --location --request GET "https://$ctlprivateip:8443/admin/sites" \
--header "Content-Type: application/json" \
--header "Accept: application/vnd.appgate.peer-v19+json" \
--header "Authorization: Bearer $token")

siteid=$(echo "$sites" | jq -r '.data[0].id')

if [ -z "$siteid" ] || [ "$siteid" == "null" ]; then
  echo "Failed to retrieve site ID."
  exit 1
fi

echo "Site ID: $siteid"

echo "[3/8] Registering new gateway: $customershortname-gateway..."

read -r -d '' json_payload <<EOF
{
  "name": "$customershortname-gateway",
  "notes": "",
  "hostname": "$gatewaydnsname",
  "site": "$siteid",
  "clientInterface": {
    "proxyProtocol": false,
    "hostname": "$gatewaydnsname",
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
            "routers": true,
            "ntp": false,
            "mtu": false
          },
          "static": []
        },
        "ipv6": {
          "dhcp": {
            "enabled": false,
            "dns": true,
            "routers": true,
            "ntp": false,
            "mtu": false
          },
          "static": []
        }
      }
    ],
    "dnsServers": [],
    "dnsDomains": [],
    "routes": []
  },
  "ntp": {
    "servers": [
      { "hostname": "0.ubuntu.pool.ntp.org" },
      { "hostname": "1.ubuntu.pool.ntp.org" },
      { "hostname": "2.ubuntu.pool.ntp.org" },
      { "hostname": "3.ubuntu.pool.ntp.org" }
    ]
  },
  "sshServer": {
    "enabled": true,
    "port": 22,
    "allowSources": [
      { "address": "0.0.0.0", "netmask": 0 },
      { "address": "::", "netmask": 0 }
    ],
    "passwordAuthentication": true
  },
  "gateway": {
    "enabled": true,
    "suspended": false,
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

gw=$(curl --silent --insecure --location --request POST "https://$ctlprivateip:8443/admin/appliances" \
--header "Content-Type: application/json" \
--header "Accept: application/vnd.appgate.peer-v19+json" \
--header "Authorization: Bearer $token" \
--data "$json_payload")

gwid=$(echo "$gw" | jq -r '.id')

if [ -z "$gwid" ] || [ "$gwid" == "null" ]; then
  echo "Failed to register gateway."
  exit 1
fi

echo "Gateway registered. Appliance ID: $gwid"

echo "[4/8] Exporting seed file to temporary location..."

tmpfile="/home/cz/seed.json.tmp"
finalfile="/home/cz/seed.json"

seed_payload='{
  "provideCloudSSHKey": true,
  "allowCustomization": false,
  "validityDays": 1
}'

curl --silent --insecure --location --request POST "https://$ctlprivateip:8443/admin/appliances/$gwid/export" \
--header "Content-Type: application/json" \
--header "Accept: application/vnd.appgate.peer-v19+json" \
--header "Authorization: Bearer $token" \
--data "$seed_payload" > "$tmpfile"

echo "[5/8] Verifying export success..."

if [ ! -s "$tmpfile" ]; then
  echo "Seed file export failed or empty."
  exit 1
fi

echo "Seed file export succeeded."

echo "[6/8] Moving completed seed file into place..."
mv "$tmpfile" "$finalfile"
echo "Moved to $finalfile"

echo "[7/8] Waiting briefly to ensure Appgate reads the file cleanly..."
sleep 1

echo "[8/8] Gateway seeding process completed successfully."