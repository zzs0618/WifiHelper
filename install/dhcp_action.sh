#!/bin/sh

# wpa_cli -a/sbin/wpa_action.sh -i wlan0

IFNAME=$1
CMD=$2

if [ "$CMD" = "CONNECTED" ]; then
   echo Start DHCP for $IFNAME # > /dev/console
   udhcpc -q -i $IFNAME -n
fi
if [ "$CMD" = "DISCONNECTED" ]; then
   echo Finish DHCP for $IFNAME # > /dev/console
   udhcpc -R -q -i $IFNAME -n
fi
