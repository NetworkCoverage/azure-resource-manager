#!/bin/bash

# Usage: ./create-client-profile.sh <admin_password> <controller_dns_or_ip>
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <admin_password> <controller_dns_or_ip>"
  exit 1
fi

adminpass="$1"
ctlhost="$2"
deviceid=$(cat /proc/sys/kernel/random/uuid)

echo "[1/2] Logging into Appgate controller..."

login_payload=$(cat <<EOF
{
  "providerName": "local",
  "username": "admin",
  "password": "$adminpass",
  "deviceId": "$deviceid"
}
EOF
)

response=$(curl -s --insecure -X POST "https://$ctlhost:8443/admin/login" \
  -H "Content-Type: application/json" \
  -H "Accept: application/vnd.appgate.peer-v19+json" \
  -d "$login_payload")

token=$(echo "$response" | jq -r '.token')

if [ -z "$token" ] || [ "$token" == "null" ]; then
  echo "Authentication failed."
  exit 1
fi

echo "Authenticated."

echo "[2/2] Creating client profile..."

client_profile_payload=$(cat <<EOF
{
  "name": "Full Tunnel Client Profile",
  "type": "Profile",
  "identityProviderName": "OIDC"
}
EOF
)

curl -s --insecure -X POST "https://$ctlhost:8443/admin/client-profiles" \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -H "Accept: application/vnd.appgate.peer-v19+json" \
  -d "$client_profile_payload" | jq .

echo "Client profile creation complete."
