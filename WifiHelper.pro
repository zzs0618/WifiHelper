QT += core dbus
QT -= gui

QT_PRIVATE += core-private

CONFIG += c++11

TARGET = wifihelper
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

DBUS_ADAPTORS += wifi.helper.station.xml

DEFINES += CONFIG_CTRL_IFACE

win32 {
    LIBS += -lws2_32 -static
    DEFINES += CONFIG_NATIVE_WINDOWS CONFIG_CTRL_IFACE_NAMED_PIPE
    SOURCES += 3rdparty/wpa_supplicant/src/utils/os_win32.c
} else:win32-g++ {
    # cross compilation to win32
    LIBS += -lws2_32 -static -mwindows
    DEFINES += CONFIG_NATIVE_WINDOWS CONFIG_CTRL_IFACE_NAMED_PIPE
    SOURCES += 3rdparty/wpa_supplicant/src/utils/os_win32.c
} else:win32-x-g++ {
    # cross compilation to win32
    LIBS += -lws2_32 -static -mwindows
    DEFINES += CONFIG_NATIVE_WINDOWS CONFIG_CTRL_IFACE_NAMED_PIPE
    DEFINES += _X86_
    SOURCES += 3rdparty/wpa_supplicant/src/utils/os_win32.c
} else {
    DEFINES += CONFIG_CTRL_IFACE_UNIX
    SOURCES += 3rdparty/wpa_supplicant/src/utils/os_unix.c \
               3rdparty/wpa_supplicant/src/utils/common.c

    linux-oe-g++ {
        message(Build $$TARGET for Linux on Cross Platform)
        DEFINES +=CONFIG_CROSS_PLATFORM

        target.path += /usr/bin
        INSTALLS += target

        conf.path = /etc
        conf.files = $$PWD/install/wifihelper.conf
        INSTALLS += conf

        dnsmasq.path = /etc
        dnsmasq.files = $$PWD/install/dnsmasq.conf
        INSTALLS += dnsmasq

        udhcpc.path = /etc/udhcpc.d
        udhcpc.files = $$PWD/install/50default
        INSTALLS += udhcpc

        dhcpc_action.path = /sbin
        dhcpc_action.files = $$PWD/install/dhcpc_action.sh
        INSTALLS += dhcpc_action

        dhcpd_action.path = /sbin
        dhcpd_action.files = $$PWD/install/dhcpd_action.sh
        INSTALLS += dhcpd_action

        wpa_cli.path = /lib/systemd/system
        wpa_cli.files = $$PWD/install/wpa_cli.service
        INSTALLS += wpa_cli

        wpa.path = /lib/systemd/system
        wpa.files = $$PWD/install/wpa.service
        INSTALLS += wpa

        service.path = /lib/systemd/system
        service.files = $$PWD/install/wifihelper.service
        INSTALLS += service

        dbus_conf.path = /etc/dbus-1/system.d/
        dbus_conf.files = $$PWD/install/wifi.helper.service.conf
        INSTALLS += dbus_conf

#        wants.path  = /lib/systemd/system/basic.target.wants
#        wants.files = $$PWD/install/basic.target.wants/wifihelper.service
#        INSTALLS += wants
    }
}

INCLUDEPATH += 3rdparty/wpa_supplicant/src 3rdparty/wpa_supplicant/src/utils

HEADERS += \
    wifiwpaadapter.h \
    wifiaccesspoint.h \
    wifi.h \
    wifinetwork.h \
    wifidbusservice.h \
    wifidbusstationstub.h

SOURCES += main.cpp \
    3rdparty/wpa_supplicant/src/common/wpa_ctrl.c \
    wifiwpaadapter.cpp \
    wifiaccesspoint.cpp \
    wifi.cpp \
    wifinetwork.cpp \
    wifidbusservice.cpp \
    wifidbusstationstub.cpp

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0
