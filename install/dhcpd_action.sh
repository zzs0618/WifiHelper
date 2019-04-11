#!/bin/sh

IFNAME=$1
CMD=$2

kill_daemon() {
    NAME=$1
    PF=$2

    if [ ! -r $PF ]; then
        return
    fi

    PID=`cat $PF`
    if [ $PID -gt 0 ]; then
        if ps | grep "$PID\|$NAME" | grep -v grep; then
            kill $PID
        fi
    fi
    rm $PF
}

if [ "$CMD" = "P2P-GROUP-STARTED" ]; then
    GIFNAME=$3
    if [ "$4" = "GO" ]; then
        echo Start P2P DHCP Server for $GIFNAME # > /dev/console
        kill_daemon dnsmasq /var/run/dnsmasq.$GIFNAME.pid
        ifconfig $GIFNAME 192.168.0.1 up
        dnsmasq -x /var/run/dnsmasq.$GIFNAME.pid -i $GIFNAME
    fi
    if [ "$4" = "client" ]; then
        echo Start P2P DHCP Client for $GIFNAME # > /dev/console
        udhcpc -q -i $GIFNAME -n
    fi
fi

if [ "$CMD" = "P2P-GROUP-REMOVED" ]; then
    GIFNAME=$3
    if [ "$4" = "GO" ]; then
        echo Finish P2P DHCP Server for $GIFNAME # > /dev/console
        kill_daemon dnsmasq /var/run/dnsmasq.$GIFNAME.pid
        ifconfig $GIFNAME 0.0.0.0
    fi
    if [ "$4" = "client" ]; then
        echo Finish P2P DHCP Client for $GIFNAME # > /dev/console
        udhcpc -R -q -i $GIFNAME -n
        ifconfig $GIFNAME 0.0.0.0
    fi
fi

if [ "$CMD" = "P2P-CROSS-CONNECT-ENABLE" ]; then
    GIFNAME=$3
    UPLINK=$4
    # enable NAT/masquarade $GIFNAME -> $UPLINK
    iptables -P FORWARD DROP
    iptables -t nat -A POSTROUTING -o $UPLINK -j MASQUERADE
    iptables -A FORWARD -i $UPLINK -o $GIFNAME -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i $GIFNAME -o $UPLINK -j ACCEPT
    sysctl net.ipv4.ip_forward=1
fi

if [ "$CMD" = "P2P-CROSS-CONNECT-DISABLE" ]; then
    GIFNAME=$3
    UPLINK=$4
    # disable NAT/masquarade $GIFNAME -> $UPLINK
    sysctl net.ipv4.ip_forward=0
    iptables -t nat -D POSTROUTING -o $UPLINK -j MASQUERADE
    iptables -D FORWARD -i $UPLINK -o $GIFNAME -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -D FORWARD -i $GIFNAME -o $UPLINK -j ACCEPT
fi
