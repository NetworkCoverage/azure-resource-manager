#!/bin/bash

set -euo pipefail

# Ensure correct number of arguments
if [ "$#" -ne 7 ]; then
  echo "Usage: $0 <customershortname> <adminpass> <controllerdnsname> <controllerprivateip> <gatewaydnsname> <tenant_id> <audience_client_id>"
  exit 1
fi

# Parameters
customershortname="$1"
adminpass="$2"
encoded_pass=$(printf "%s" "$adminpass" | base64)
controllerdnsname="$3"
controllerprivateip="$4"
gatewaydnsname="$5"
tenant_id="$6"
audience_client_id="$7"

# Log setup
timestamp=$(date +%Y%m%d-%H%M%S)
logfile="provision-log-$timestamp.log"
exec > >(tee -a "$logfile") 2>&1

# Check all required scripts exist
required_scripts=(
  seed-controller.sh
  seed-gateway.sh
  enable-full-tunnel-default-site.sh
  create-oidc-idp.sh
  create-full-tunnel-entitlement.sh
  create-tunnel-policy.sh
  create-client-profile.sh
)

for script in "${required_scripts[@]}"; do
  if [ ! -f "$script" ]; then
    echo "Required script missing: $script"
    exit 1
  fi
done

echo "Running from: $(hostname)"
echo "Target Controller: $controllerdnsname"
echo "Target Gateway: $gatewaydnsname"
echo "Logging to: $logfile"

echo "[1/7] Seeding controller..."
ssh -i ./ctl.pem cz@"$controllerdnsname" bash -s -- "$customershortname" "$encoded_pass" "$controllerdnsname" < ./seed-controller.sh
echo "Waiting 30s for controller to become healthy..."
sleep 30

echo "[2/7] Seeding gateway..."
ssh -i ./gw.pem cz@"$gatewaydnsname" bash -s -- "$customershortname" "$encoded_pass" "$controllerprivateip" "$gatewaydnsname" < ./seed-gateway.sh
sleep 5

echo "[3/7] Enabling full tunnel routing on default site..."
ssh -i ./ctl.pem cz@"$controllerdnsname" bash -s -- "$encoded_pass" "$controllerdnsname" < ./enable-full-tunnel-default-site.sh
sleep 5

echo "[4/7] Creating OIDC identity provider..."
ssh -i ./ctl.pem cz@"$controllerdnsname" bash -s -- "$encoded_pass" "$controllerdnsname" "$tenant_id" "$audience_client_id" < ./create-oidc-idp.sh
sleep 5

echo "[5/7] Creating full tunnel entitlement..."
ssh -i ./ctl.pem cz@"$controllerdnsname" bash -s -- "$encoded_pass" "$controllerdnsname" < ./create-full-tunnel-entitlement.sh
sleep 5

echo "[6/7] Creating policy for full tunnel entitlement..."
ssh -i ./ctl.pem cz@"$controllerdnsname" bash -s -- "$encoded_pass" "$controllerdnsname" < ./create-tunnel-policy.sh
sleep 5

echo "[7/7] Creating client profile..."
ssh -i ./ctl.pem cz@"$controllerdnsname" bash -s -- "$encoded_pass" "$controllerdnsname" < ./create-client-profile.sh

echo "All steps completed successfully."
