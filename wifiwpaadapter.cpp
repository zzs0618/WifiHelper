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

#include <private/qobject_p.h>
#include <QSocketNotifier>
#include <QTimer>
#include <QDir>

#include "common/wpa_ctrl.h"

// in one source file
Q_LOGGING_CATEGORY(wifiWPAAdapter, "wifi.wpaadapter")

// The number of updates triggered by the PING
#define NUMBER_PING_UPDATE 20
// Signal strength refresh interval in milliseconds
#define INTERVAL_SIGNAL_UPDATE 10000

const static QString WPACtrlIfaceDir = QLatin1String("/var/run/wpa_supplicant");

static int str_match(const char *a, const char *b)
{
    return strncmp(a, b, strlen(b)) == 0;
}

class WifiWPAAdapterPrivate : public QObjectPrivate
{
    Q_DECLARE_PUBLIC(WifiWPAAdapter)
public:
    WifiWPAAdapterPrivate();
    ~WifiWPAAdapterPrivate();
    QString wpaStateTranslate(char *state);

    void signalMeterUpdate();
    void updateStatus();
    void updateNetworks();
    void receiveMsgs();
    void processMsg(char *msg);

    bool select(const QString &iface);
    bool connect();
    bool disconnect();
    void saveConfig();
    void ping();
    void scan();

    QStringList interfaces;
    QString currentIface;

    int pingsToStatusUpdate = NUMBER_PING_UPDATE;
    QSocketNotifier *msgNotifier = NULL;
    QTimer *timer = NULL;
    QTimer *signalMeterTimer = NULL;
    int signalMeterInterval = INTERVAL_SIGNAL_UPDATE;
    bool networkMayHaveChanged = false;

    struct wpa_ctrl *wpaConnection = NULL;
    struct wpa_ctrl *wpaMonitor = NULL;


    QString bssid;
    QString ssid;
    QString ipAddress;
    QString wpaMode;
    QString wpaState;
    QString wpaAuth;
    QString pairwiseCipher;
    QString groupCipher;

protected:
    int ctrlRequest(const char *cmd, char *buf, size_t *buflen);
};

WifiWPAAdapterPrivate::WifiWPAAdapterPrivate()
    : QObjectPrivate()
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

    timer = new QTimer;
    QObjectPrivate::connect(timer, &QTimer::timeout, this,
                            &WifiWPAAdapterPrivate::ping);
    timer->setSingleShot(false);
    timer->start(1000);

    signalMeterTimer = new QTimer;
    signalMeterTimer->setInterval(signalMeterInterval);
    QObjectPrivate::connect(signalMeterTimer, &QTimer::timeout, this,
                            &WifiWPAAdapterPrivate::signalMeterUpdate);


    updateStatus();
    networkMayHaveChanged = true;
    updateNetworks();
}

WifiWPAAdapterPrivate::~WifiWPAAdapterPrivate()
{
    delete timer;
    delete signalMeterTimer;

    if (wpaMonitor) {
        wpa_ctrl_detach(wpaMonitor);
        wpa_ctrl_close(wpaMonitor);
        wpaMonitor = NULL;
    }
    if (wpaConnection) {
        wpa_ctrl_close(wpaConnection);
        wpaConnection = NULL;
    }
}

QString WifiWPAAdapterPrivate::wpaStateTranslate(char *state)
{
    if (!strcmp(state, "DISCONNECTED")) {
        return QStringLiteral("Disconnected");
    } else if (!strcmp(state, "INACTIVE")) {
        return QStringLiteral("Inactive");
    } else if (!strcmp(state, "SCANNING")) {
        return QStringLiteral("Scanning");
    } else if (!strcmp(state, "AUTHENTICATING")) {
        return QStringLiteral("Authenticating");
    } else if (!strcmp(state, "ASSOCIATING")) {
        return QStringLiteral("Associating");
    } else if (!strcmp(state, "ASSOCIATED")) {
        return QStringLiteral("Associated");
    } else if (!strcmp(state, "4WAY_HANDSHAKE")) {
        return QStringLiteral("4-Way Handshake");
    } else if (!strcmp(state, "GROUP_HANDSHAKE")) {
        return QStringLiteral("Group Handshake");
    } else if (!strcmp(state, "COMPLETED")) {
        return QStringLiteral("Completed");
    } else {
        return QStringLiteral("Unknown");
    }
}

void WifiWPAAdapterPrivate::signalMeterUpdate()
{

}

void WifiWPAAdapterPrivate::updateStatus()
{
    char buf[2048], *start, *end, *pos;
    size_t len;

    pingsToStatusUpdate = NUMBER_PING_UPDATE;

    len = sizeof(buf) - 1;
    if (wpaConnection == NULL || ctrlRequest("STATUS", buf, &len) < 0) {
        qCDebug(wifiWPAAdapter, "Could not get status from wpa_supplicant.");

        signalMeterTimer->stop();
        return;
    }

    buf[len] = '\0';

    bool auth_updated = false, ssid_updated = false;
    bool bssid_updated = false, ipaddr_updated = false;
    bool status_updated = false;

    start = buf;
    while (*start) {
        bool last = false;
        end = strchr(start, '\n');
        if (end == NULL) {
            last = true;
            end = start;
            while (end[0] && end[1]) {
                end++;
            }
        }
        *end = '\0';

        pos = strchr(start, '=');
        if (pos) {
            *pos++ = '\0';
            QString value = QString(pos);
            if (strcmp(start, "bssid") == 0 && value != bssid) {
                bssid_updated = true;
                bssid = value;
            } else if (strcmp(start, "ssid") == 0 && value != ssid) {
                ssid_updated = true;
                ssid = value;
            } else if (strcmp(start, "ip_address") == 0 && value != ipAddress) {
                ipaddr_updated = true;
                ipAddress = value;
            } else if (strcmp(start, "wpa_state") == 0) {
                value = wpaStateTranslate(pos);
                if(value != wpaState) {
                    status_updated = true;
                    wpaState = value;
                }
            } else if (strcmp(start, "key_mgmt") == 0 && value != wpaAuth) {
                auth_updated = true;
                wpaAuth = value;
                /* TODO: could add EAP status to this */
            } else if (strcmp(start, "pairwiseCipher") == 0 && value != pairwiseCipher) {
                pairwiseCipher = value;
            } else if (strcmp(start, "groupCipher") == 0 && value != groupCipher) {
                groupCipher = value;
            } else if (strcmp(start, "mode") == 0 && value != wpaMode) {
                wpaMode = value;
            }
        }

        if (last) {
            break;
        }
        start = end + 1;
    }

    if(auth_updated || ssid_updated || bssid_updated ||
       ipaddr_updated || status_updated) {

        QString encr;
        if (pairwiseCipher != "" || groupCipher != "") {
            if (pairwiseCipher != "" && groupCipher != "" &&
                pairwiseCipher != groupCipher) {
                encr.append(pairwiseCipher);
                encr.append(" + ");
                encr.append(groupCipher);
            } else if (pairwiseCipher != "") {
                encr.append(pairwiseCipher);
            } else {
                encr.append(groupCipher);
                encr.append(" [group key only]");
            }
        }

        qCDebug(wifiWPAAdapter,
                "Get status from wpa_supplicant :\n"
                "[Status            ] = %s\n"
                "[Authentication    ] = %s\n"
                "[Encryption        ] = %s\n"
                "[SSID              ] = %s\n"
                "[BSSID             ] = %s\n"
                "[IP Address        ] = %s\n",
                qPrintable(wpaState + " (" + wpaMode + ")" + (status_updated ? " [*]" : "")),
                qPrintable(wpaAuth + (auth_updated ? " [*]" : "")),
                qPrintable(encr),
                qPrintable(ssid + (ssid_updated ? " [*]" : "")),
                qPrintable(bssid + (bssid_updated ? " [*]" : "")),
                qPrintable(ipAddress + (ipaddr_updated ? " [*]" : "")));
        Q_EMIT q_func()->statusChanged();
    }

    if (signalMeterInterval) {
        /*
         * Handle signal meter service. When network is not associated,
         * deactivate timer, otherwise keep it going. Tray icon has to
         * be initialized here, because of the initial delay of the
         * timer.
         */
        if (ssid != "") {
            if (!signalMeterTimer->isActive()) {
                signalMeterTimer->start();
            }
        } else {
            signalMeterTimer->stop();
        }
    }
}

void WifiWPAAdapterPrivate::updateNetworks()
{
    char buf[4096], *start, *end, *id, *_ssid, *_bssid, *flags;
    size_t len;
    //    int first_active = -1;
    //    int was_selected = -1;
    //    bool current = false;

    if (!networkMayHaveChanged) {
        return;
    }

    //    if (networkList->currentRow() >= 0) {
    //        was_selected = networkList->currentRow();
    //    }

    //    networkSelect->clear();
    //    networkList->clear();

    if (wpaConnection == NULL) {
        return;
    }

    len = sizeof(buf) - 1;
    if (ctrlRequest("LIST_NETWORKS", buf, &len) < 0) {
        return;
    }

    buf[len] = '\0';
    start = strchr(buf, '\n');
    if (start == NULL) {
        return;
    }
    start++;

    while (*start) {
        bool last = false;
        end = strchr(start, '\n');
        if (end == NULL) {
            last = true;
            end = start;
            while (end[0] && end[1]) {
                end++;
            }
        }
        *end = '\0';

        id = start;
        _ssid = strchr(id, '\t');
        if (_ssid == NULL) {
            break;
        }
        *_ssid++ = '\0';
        _bssid = strchr(_ssid, '\t');
        if (_bssid == NULL) {
            break;
        }
        *_bssid++ = '\0';
        flags = strchr(_bssid, '\t');
        if (flags == NULL) {
            break;
        }
        *flags++ = '\0';

        if (strstr(flags, "[DISABLED][P2P-PERSISTENT]")) {
            if (last) {
                break;
            }
            start = end + 1;
            continue;
        }
        /*
                QString network(id);
                network.append(": ");
                network.append(_ssid);
                networkSelect->addItem(network);
                networkList->addItem(network);

                if (strstr(flags, "[CURRENT]")) {
                    networkSelect->setCurrentIndex(networkSelect->count() - 1);
                    current = true;
                } else if (first_active < 0 &&
                           strstr(flags, "[DISABLED]") == NULL) {
                    first_active = networkSelect->count() - 1;
                }
        */
        if (last) {
            break;
        }
        start = end + 1;
    }
    /*
        if (networkSelect->count() > 1) {
            networkSelect->addItem(tr("Select any network"));
        }

        if (!current && first_active >= 0) {
            networkSelect->setCurrentIndex(first_active);
        }

        if (was_selected >= 0 && networkList->count() > 0) {
            if (was_selected < networkList->count()) {
                networkList->setCurrentRow(was_selected);
            } else {
                networkList->setCurrentRow(networkList->count() - 1);
            }
        } else {
            networkList->setCurrentRow(networkSelect->currentIndex());
        }
    */
    networkMayHaveChanged = false;
}

void WifiWPAAdapterPrivate::receiveMsgs()
{
    char buf[256];
    size_t len;

    while (wpaMonitor && wpa_ctrl_pending(wpaMonitor) > 0) {
        len = sizeof(buf) - 1;
        if (wpa_ctrl_recv(wpaMonitor, buf, &len) == 0) {
            buf[len] = '\0';
            processMsg(buf);
        }
    }
}

void WifiWPAAdapterPrivate::processMsg(char *msg)
{
    char *pos = msg, *pos2;
    //    int priority = 2;

    if (*pos == '<') {
        /* skip priority */
        pos++;
        //        priority = atoi(pos);
        pos = strchr(pos, '>');
        if (pos) {
            pos++;
        } else {
            pos = msg;
        }
    }
    /*
        WpaMsg wm(pos, priority);
        if (eh) {
            eh->addEvent(wm);
        }
        if (peers) {
            peers->event_notify(wm);
        }
        msgs.append(wm);
        while (msgs.count() > 100) {
            msgs.pop_front();
        }
    */
    /* Update last message with truncated version of the event */
    if (strncmp(pos, "CTRL-", 5) == 0) {
        pos2 = strchr(pos, str_match(pos, WPA_CTRL_REQ) ? ':' : ' ');
        if (pos2) {
            pos2++;
        } else {
            pos2 = pos;
        }
    } else {
        pos2 = pos;
    }

    /*
    QString lastmsg = pos2;
    lastmsg.truncate(40);
    textLastMessage->setText(lastmsg);
    */

    pingsToStatusUpdate = 0;
    networkMayHaveChanged = true;

    if (str_match(pos, WPA_CTRL_REQ)) {
        //        processCtrlReq(pos + strlen(WPA_CTRL_REQ));
    } else if (str_match(pos, WPA_EVENT_SCAN_RESULTS)) {
        //        scanres->updateResults();
    } else if (str_match(pos, WPA_EVENT_DISCONNECTED)) {
        //        showTrayMessage(QSystemTrayIcon::Information, 3,
        //                        tr("Disconnected from network."));
    } else if (str_match(pos, WPA_EVENT_CONNECTED)) {
        //        showTrayMessage(QSystemTrayIcon::Information, 3,
        //                        tr("Connection to network established."));
        //        QTimer::singleShot(5 * 1000, this, SLOT(showTrayStatus()));
        //        stopWpsRun(true);
    } else if (str_match(pos, WPS_EVENT_AP_AVAILABLE_PBC)) {
        //        wpsStatusText->setText(tr("WPS AP in active PBC mode found"));
        //        if (textStatus->text() == "INACTIVE" ||
        //            textStatus->text() == "DISCONNECTED") {
        //            wpaguiTab->setCurrentWidget(wpsTab);
        //        }
        //        wpsInstructions->setText(tr("Press the PBC button on the "
        //                                    "screen to start registration"));
    } else if (str_match(pos, WPS_EVENT_AP_AVAILABLE_PIN)) {
        //        wpsStatusText->setText(tr("WPS AP with recently selected "
        //                                  "registrar"));
        //        if (textStatus->text() == "INACTIVE" ||
        //            textStatus->text() == "DISCONNECTED") {
        //            wpaguiTab->setCurrentWidget(wpsTab);
        //        }
    } else if (str_match(pos, WPS_EVENT_AP_AVAILABLE_AUTH)) {
        //        showTrayMessage(QSystemTrayIcon::Information, 3,
        //                        "Wi-Fi Protected Setup (WPS) AP\n"
        //                        "indicating this client is authorized.");
        //        wpsStatusText->setText("WPS AP indicating this client is "
        //                               "authorized");
        //        if (textStatus->text() == "INACTIVE" ||
        //            textStatus->text() == "DISCONNECTED") {
        //            wpaguiTab->setCurrentWidget(wpsTab);
        //        }
    } else if (str_match(pos, WPS_EVENT_AP_AVAILABLE)) {
        //        wpsStatusText->setText(tr("WPS AP detected"));
    } else if (str_match(pos, WPS_EVENT_OVERLAP)) {
        //        wpsStatusText->setText(tr("PBC mode overlap detected"));
        //        wpsInstructions->setText(tr("More than one AP is currently in "
        //                                    "active WPS PBC mode. Wait couple "
        //                                    "of minutes and try again"));
        //        wpaguiTab->setCurrentWidget(wpsTab);
    } else if (str_match(pos, WPS_EVENT_CRED_RECEIVED)) {
        //        wpsStatusText->setText(tr("Network configuration received"));
        //        wpaguiTab->setCurrentWidget(wpsTab);
    } else if (str_match(pos, WPA_EVENT_EAP_METHOD)) {
        //        if (strstr(pos, "(WSC)")) {
        //            wpsStatusText->setText(tr("Registration started"));
        //        }
    } else if (str_match(pos, WPS_EVENT_M2D)) {
        //        wpsStatusText->setText(tr("Registrar does not yet know PIN"));
    } else if (str_match(pos, WPS_EVENT_FAIL)) {
        //        wpsStatusText->setText(tr("Registration failed"));
    } else if (str_match(pos, WPS_EVENT_SUCCESS)) {
        //        wpsStatusText->setText(tr("Registration succeeded"));
    }
}

int WifiWPAAdapterPrivate::ctrlRequest(const char *cmd, char *buf,
                                       size_t *buflen)
{
    int ret;
    if (wpaConnection == NULL) {
        return -3;
    }
    ret = wpa_ctrl_request(wpaConnection, cmd, strlen(cmd), buf, buflen, NULL);
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

    if (wpaConnection) {
        wpa_ctrl_close(wpaConnection);
        wpaConnection = NULL;
    }

    if (wpaMonitor) {
        //        delete msgNotifier;
        //        msgNotifier = NULL;
        wpa_ctrl_detach(wpaMonitor);
        wpa_ctrl_close(wpaMonitor);
        wpaMonitor = NULL;
    }

    currentIface = iface;

    qCDebug(wifiWPAAdapter, "Trying to connect to '%s'",
            qUtf8Printable(currentIface));

    const char *ctrl_path = currentIface.toLocal8Bit().constData();
    wpaConnection = wpa_ctrl_open(ctrl_path);
    if (wpaConnection == NULL) {
        qCCritical(wifiWPAAdapter, "Failed to open connection!\n%s",
                   qUtf8Printable(currentIface));
        return false;
    }
    qCDebug(wifiWPAAdapter, "Successed to open connection.\n%s",
            qUtf8Printable(currentIface));

    wpaMonitor = wpa_ctrl_open(ctrl_path);
    if (wpaMonitor == NULL) {
        wpa_ctrl_close(wpaConnection);
        wpaConnection = NULL;
        qCCritical(wifiWPAAdapter, "Failed to monitor connection!\n%s",
                   qUtf8Printable(currentIface));
        return false;
    }
    qCDebug(wifiWPAAdapter, "Successed to monitor connection.\n%s",
            qUtf8Printable(currentIface));

    if (wpa_ctrl_attach(wpaMonitor)) {
        qCCritical(wifiWPAAdapter, "Failed to attach to wpa_supplicant!\n%s",
                   qUtf8Printable(currentIface));
        wpa_ctrl_close(wpaMonitor);
        wpaMonitor = NULL;
        wpa_ctrl_close(wpaConnection);
        wpaConnection = NULL;
        return false;
    }
    qCDebug(wifiWPAAdapter, "Successed to attach to wpa_supplicant.\n%s",
            qUtf8Printable(currentIface));

#if defined(CONFIG_CTRL_IFACE_UNIX) || defined(CONFIG_CTRL_IFACE_UDP)
    msgNotifier = new QSocketNotifier(wpa_ctrl_get_fd(wpaMonitor),
                                      QSocketNotifier::Read, q_func());
    QObjectPrivate::connect(msgNotifier, &QSocketNotifier::activated, this,
                            &WifiWPAAdapterPrivate::receiveMsgs);
#endif

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

void WifiWPAAdapterPrivate::saveConfig()
{
    char buf[10];
    size_t len;

    len = sizeof(buf) - 1;
    ctrlRequest("SAVE_CONFIG", buf, &len);

    buf[len] = '\0';

    if (QString(buf) == QLatin1String("FAIL"))
        qCWarning(wifiWPAAdapter, "Failed to save configuration :\n%s",
                  "The configuration could not be saved.\n"
                  "The update_config=1 configuration option "
                  "must be used for configuration saving to "
                  "be permitted.");
    else
        qCDebug(wifiWPAAdapter, "Saved configuration :\n%s",
                "The current configuration was saved.");
}

void WifiWPAAdapterPrivate::ping()
{
    char buf[10];
    size_t len;

#ifdef CONFIG_CTRL_IFACE_NAMED_PIPE
    /*
     * QSocketNotifier cannot be used with Windows named pipes, so use a
     * timer to check for received messages for now. This could be
     * optimized be doing something specific to named pipes or Windows
     * events, but it is not clear what would be the best way of doing that
     * in Qt.
     */
    receiveMsgs();
#endif /* CONFIG_CTRL_IFACE_NAMED_PIPE */

    len = sizeof(buf) - 1;
    if (ctrlRequest("PING", buf, &len) < 0) {
        qCWarning(wifiWPAAdapter, "PING failed - trying to reconnect.");
        if (select(currentIface)) {
            qCDebug(wifiWPAAdapter, "Reconnected successfully by PING.");
            pingsToStatusUpdate = 0;
        }
    }

    pingsToStatusUpdate--;
    if (pingsToStatusUpdate <= 0) {
        updateStatus();
        updateNetworks();
    }

#ifndef CONFIG_CTRL_IFACE_NAMED_PIPE
    /* Use less frequent pings and status updates when the main window is
     * hidden (running in taskbar). */
    //    int interval = isHidden() ? 5000 : 1000;
    int interval = 5000;
    if (timer->interval() != interval) {
        timer->setInterval(interval);
    }
#endif /* CONFIG_CTRL_IFACE_NAMED_PIPE */

}

void WifiWPAAdapterPrivate::scan()
{

}

WifiWPAAdapter::WifiWPAAdapter(QObject *parent)
    : QObject(*(new WifiWPAAdapterPrivate), parent)
{
}

WifiWPAAdapter::~WifiWPAAdapter()
{
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
