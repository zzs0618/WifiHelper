/**
 ** This file is part of the WifiHelper project.
 ** Copyright 2019 张作深 <zhangzuoshen@hangsheng.com.cn>.
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, either version 3 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include "wifiwpaadapter.h"

#include <QDir>

#include "common/wpa_ctrl.h"

// in one source file
Q_LOGGING_CATEGORY(wifiWPAAdapter, "wifi.wpaadapter")

const static QString WPACtrlIfaceDir = QLatin1String("/var/run/wpa_supplicant");

class WifiWPAAdapterPrivate
{
    Q_DECLARE_PUBLIC(WifiWPAAdapter)
public:
    WifiWPAAdapterPrivate();
    ~WifiWPAAdapterPrivate();
    bool select(const QString &iface);
    bool connect();
    bool disconnect();
    void saveConfig();
    void ping();
    void scan();

    QStringList interfaces;
    QString currentIface;

    struct wpa_ctrl *ctrl_conn = NULL;
    struct wpa_ctrl *monitor_conn = NULL;

    WifiWPAAdapter *q_ptr;

protected:
    int ctrlRequest(const char *cmd, char *buf, size_t *buflen);
};

WifiWPAAdapterPrivate::WifiWPAAdapterPrivate()
{
    // Get All interfaces from the path /var/run/wpa_supplicant
    QDir dir(WPACtrlIfaceDir);
    if(dir.exists()) {
        dir.setFilter(QDir::System);
        QFileInfoList list = dir.entryInfoList();
        interfaces.clear();
        for(const QFileInfo &iface : list) {
            interfaces << iface.filePath();
        }
        qCDebug(wifiWPAAdapter, "Get All interfaces from the path("
                "/var/run/wpa_supplicant) :\n%s",
                qUtf8Printable(interfaces.join("\n")));
    }
}

WifiWPAAdapterPrivate::~WifiWPAAdapterPrivate()
{
    if (monitor_conn) {
        wpa_ctrl_detach(monitor_conn);
        wpa_ctrl_close(monitor_conn);
        monitor_conn = NULL;
    }
    if (ctrl_conn) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
    }
}

int WifiWPAAdapterPrivate::ctrlRequest(const char *cmd, char *buf,
                                       size_t *buflen)
{
    int ret;
    if (ctrl_conn == NULL) {
        return -3;
    }
    ret = wpa_ctrl_request(ctrl_conn, cmd, strlen(cmd), buf, buflen, NULL);
    if (ret == -2) {
        qCDebug(wifiWPAAdapter, "'%s' command timed out.", cmd);
    } else if (ret < 0) {
        qCDebug(wifiWPAAdapter, "'%s' command failed.", cmd);
    }
    return ret;
}

bool WifiWPAAdapterPrivate::select(const QString &interface)
{
    QString iface;
    for(int i = 0; i < interfaces.length(); ++i) {
        iface = interfaces.at(i);
        if(iface.endsWith(interface)) {
            break;
        }
    }

    if(currentIface == iface) {
        return true;
    }

    if (ctrl_conn) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
    }

    if (monitor_conn) {
        //        delete msgNotifier;
        //        msgNotifier = NULL;
        wpa_ctrl_detach(monitor_conn);
        wpa_ctrl_close(monitor_conn);
        monitor_conn = NULL;
    }

    currentIface = iface;

    qCDebug(wifiWPAAdapter, "Trying to connect to '%s'",
            qUtf8Printable(currentIface));

    const char *ctrl_path = currentIface.toLocal8Bit().constData();
    ctrl_conn = wpa_ctrl_open(ctrl_path);
    if (ctrl_conn == NULL) {
        qCCritical(wifiWPAAdapter, "Failed to open connection!\n%s",
                   qUtf8Printable(currentIface));
        return false;
    }
    qCDebug(wifiWPAAdapter, "Successed to open connection.\n%s",
            qUtf8Printable(currentIface));

    monitor_conn = wpa_ctrl_open(ctrl_path);
    if (monitor_conn == NULL) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
        qCCritical(wifiWPAAdapter, "Failed to monitor connection!\n%s",
                   qUtf8Printable(currentIface));
        return false;
    }
    qCDebug(wifiWPAAdapter, "Successed to monitor connection.\n%s",
            qUtf8Printable(currentIface));

    if (wpa_ctrl_attach(monitor_conn)) {
        qCCritical(wifiWPAAdapter, "Failed to attach to wpa_supplicant!\n%s",
                   qUtf8Printable(currentIface));
        wpa_ctrl_close(monitor_conn);
        monitor_conn = NULL;
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
        return false;
    }
    qCDebug(wifiWPAAdapter, "Successed to attach to wpa_supplicant.\n%s",
            qUtf8Printable(currentIface));

    return true;
}

bool WifiWPAAdapterPrivate::connect()
{
    char reply[10];
    size_t reply_len = sizeof(reply);
    int ret = ctrlRequest("REASSOCIATE", reply, &reply_len);
    return ret >= 0;
}

bool WifiWPAAdapterPrivate::disconnect()
{
    char reply[10];
    size_t reply_len = sizeof(reply);
    int ret = ctrlRequest("DISCONNECT", reply, &reply_len);
    //TODO:    stopWpsRun(false);
    return ret >= 0;
}

WifiWPAAdapter::WifiWPAAdapter(QObject *parent) : QObject(parent)
    , d_ptr(new WifiWPAAdapterPrivate)
{
    Q_D(WifiWPAAdapter);
    d->q_ptr = this;
}

WifiWPAAdapter::~WifiWPAAdapter()
{
    delete d_ptr;
}

bool WifiWPAAdapter::select(const QString &interface)
{
    Q_D(WifiWPAAdapter);
    return d->select(interface);
}

bool WifiWPAAdapter::connect()
{
    Q_D(WifiWPAAdapter);
    return d->connect();
}

bool WifiWPAAdapter::disconnect()
{
    Q_D(WifiWPAAdapter);
    return d->disconnect();
}

void WifiWPAAdapter::saveConfig()
{

}

void WifiWPAAdapter::ping()
{

}

void WifiWPAAdapter::scan()
{

}
