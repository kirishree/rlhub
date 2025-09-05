#!/bin/bash

COMMUNITY="reachlink"
HOST="$2"
INTERFACE_NAME="$1"

# Find the correct interface index
INTERFACE_INDEX=$(snmpwalk -v2c -c $COMMUNITY $HOST 1.3.6.1.2.1.2.2.1.2 | grep "$INTERFACE_NAME" | awk -F '.' '{print $2}' | awk '{print $1}')

# Ensure a numeric response for Zabbix
if [[ ! $INTERFACE_INDEX =~ ^[0-9]+$ ]]; then
    echo 0  # Return 0 instead of "Interface not found"
    exit 1
fi

# Get Inbound Traffic (bytes received)
TRAFFIC_IN=$(snmpget -v2c -c $COMMUNITY $HOST 1.3.6.1.2.1.2.2.1.10.$INTERFACE_INDEX | awk '{print $NF}')

# Ensure TRAFFIC_IN is a valid number
if [[ ! $TRAFFIC_IN =~ ^[0-9]+$ ]]; then
    echo 0
    exit 1
fi

echo "$TRAFFIC_IN"
