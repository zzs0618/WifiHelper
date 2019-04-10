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
#include "wifiaccesspoint.h"

#include <private/qobject_p.h>
#include <QSocketNotifier>
#include <QTimer>
#include <QDir>
#include <QList>

extern "C"
{
#include "common/wpa_ctrl.h"
#include "utils/os.h"
#include "utils/common.h"
}

// in one source file
Q_LOGGING_CATEGORY(wifiWPAAdapter, "wifi.helper.wpa.adapter")

// The number of update status triggered by the PING
#define NUMBER_PING_UPDATE_STATUS 3
// Signal strength refresh interval in milliseconds
#define INTERVAL_SIGNAL_UPDATE 10000

const static QString WPACtrlIfaceDir = QLatin1String("/var/run/wpa_supplicant");

static int str_match(const char *a, const char *b)
{
    return strncmp(a, b, strlen(b)) == 0;
}

static int wpa_cli_exec(const char *program, const char *arg1,
                        const char *arg2)
{
    char *arg;
    size_t len;
    int res;

    /* If no interface is specified, set the global */
    if (!arg1) {
        arg1 = "global";
    }

    len = os_strlen(arg1) + os_strlen(arg2) + 2;
    arg = (char*)os_malloc(len);
    if (arg == NULL) {
        return -1;
    }
    os_snprintf(arg, len, "%s %s", arg1, arg2);
    res = os_exec(program, arg, 1);
    os_free(arg);

    return res;
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
    void scanRequest();
    void updateScanResults();

    QFileInfoList allInterfaces;
    QFileInfo interfaceFilePath;

    int pingsToStatusUpdate = NUMBER_PING_UPDATE_STATUS;
    QSocketNotifier *msgNotifier = NULL;
    QTimer *timer = NULL;
    QTimer *signalMeterTimer = NULL;
    int signalMeterInterval = INTERVAL_SIGNAL_UPDATE;
    bool networkMayHaveChanged = false;
    int wpa_cli_last_id = 0;
    int wpa_cli_connected = -1;
    const QByteArray action_dhcp;

    struct wpa_ctrl *wpaConnection = NULL;
    struct wpa_ctrl *wpaMonitor = NULL;


    QString bssid;
    QString ssid;
    QString ipAddress;
    QString wpaMode;
    QString wpaState;
    QString wpaSecurity;
    QString pairwiseCipher;
    QString groupCipher;
    QList<WifiAccessPoint *> wifiPoints;

protected:
    int ctrlRequest(const char *cmd, char *buf, size_t *buflen);
};

WifiWPAAdapterPrivate::WifiWPAAdapterPrivate()
    : QObjectPrivate()
    , action_dhcp(qgetenv("WIFI_HELPER_ACTION_DHCP"))
{
    // Get All interfaces from the path /var/run/wpa_supplicant
    QDir dir(WPACtrlIfaceDir);
    if(dir.exists()) {
        dir.setFilter(QDir::System);
        QFileInfoList list = dir.entryInfoList();
        QStringList ifaces;
        allInterfaces.clear();
        for(const QFileInfo &iface : list) {
            allInterfaces << iface;
            ifaces << iface.fileName();
        }
        qCDebug(wifiWPAAdapter, "Get All interfaces from the path("
                "/var/run/wpa_supplicant) :\n%s",
                qUtf8Printable(ifaces.join("\n")));
    }

}

WifiWPAAdapterPrivate::~WifiWPAAdapterPrivate()
{
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

    pingsToStatusUpdate = NUMBER_PING_UPDATE_STATUS;

    len = sizeof(buf) - 1;
    if (wpaConnection == NULL || ctrlRequest("STATUS", buf, &len) < 0) {
        qCDebug(wifiWPAAdapter, "Could not get status from wpa_supplicant.");

        signalMeterTimer->stop();
        return;
    }

    buf[len] = '\0';

    QString _bssid;
    QString _ssid;
    QString _ipAddress;
    QString _wpaMode;
    QString _wpaState;
    QString _wpaSecurity;
    QString _pairwiseCipher;
    QString _groupCipher;
    bool security_updated = false, ssid_updated = false;
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
            if (strcmp(start, "bssid") == 0) {
                bssid_updated = true;
                _bssid = QString(pos);
            } else if (strcmp(start, "ssid") == 0) {
                ssid_updated = true;
                _ssid = QString(pos);
            } else if (strcmp(start, "ip_address") == 0) {
                ipaddr_updated = true;
                _ipAddress = QString(pos);
            } else if (strcmp(start, "wpa_state") == 0) {
                status_updated = true;
                _wpaState = wpaStateTranslate(pos);
            } else if (strcmp(start, "key_mgmt") == 0 ) {
                security_updated = true;
                _wpaSecurity = QString(pos);
                /* TODO: could add EAP status to this */
            } else if (strcmp(start, "pairwiseCipher") == 0 ) {
                _pairwiseCipher = QString(pos);
            } else if (strcmp(start, "groupCipher") == 0) {
                _groupCipher = QString(pos);
            } else if (strcmp(start, "mode") == 0 ) {
                _wpaMode = QString(pos);
            }
        }

        if (last) {
            break;
        }
        start = end + 1;
    }

    if(security_updated || ssid_updated || bssid_updated ||
       ipaddr_updated || status_updated) {

        QString encr;
        if (_pairwiseCipher != "" || _groupCipher != "") {
            if (_pairwiseCipher != "" && _groupCipher != "" &&
                _pairwiseCipher != _groupCipher) {
                encr.append(_pairwiseCipher);
                encr.append(" + ");
                encr.append(_groupCipher);
            } else if (_pairwiseCipher != "") {
                encr.append(_pairwiseCipher);
            } else {
                encr.append(_groupCipher);
                encr.append(" [group key only]");
            }
        }

        qCDebug(wifiWPAAdapter,
                "Get status from wpa_supplicant :\n"
                "[Status        ] = %s\n"
                "[Security      ] = %s\n"
                "[Encryption    ] = %s\n"
                "[SSID          ] = %s\n"
                "[BSSID         ] = %s\n"
                "[IP Address    ] = %s\n",
                qPrintable(_wpaState + " (" + _wpaMode + ")" + (status_updated ? " [*]" : "")),
                qPrintable(_wpaSecurity + (security_updated ? " [*]" : "")),
                qPrintable(encr),
                qPrintable(_ssid + (ssid_updated ? " [*]" : "")),
                qPrintable(_bssid + (bssid_updated ? " [*]" : "")),
                qPrintable(_ipAddress + (ipaddr_updated ? " [*]" : "")));
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
    char *copy = NULL, *id, *pos2;
    char *pos = msg;
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
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPA_CTRL_REQ");
        //        processCtrlReq(pos + strlen(WPA_CTRL_REQ));
    } else if (str_match(pos, WPA_EVENT_SCAN_RESULTS)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPA_EVENT_SCAN_RESULTS\n%s",
                "Update the scan results.");
        updateScanResults();
    } else if (str_match(pos, WPA_EVENT_DISCONNECTED)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPA_EVENT_DISCONNECTED\n%s",
                "Disconnected from network.");
        if (wpa_cli_connected) {
            wpa_cli_connected = 0;
            wpa_cli_exec(action_dhcp.constData(), qPrintable(interfaceFilePath.fileName()),
                         "DISCONNECTED");
        }
        //        showTrayMessage(QSystemTrayIcon::Information, 3,
        //                        tr("Disconnected from network."));
    } else if (str_match(pos, WPA_EVENT_CONNECTED)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPA_EVENT_CONNECTED\n%s",
                "Connection to network established.");

        int new_id = -1;
        os_unsetenv("WPA_ID");
        os_unsetenv("WPA_ID_STR");
        os_unsetenv("WPA_CTRL_DIR");

        pos = os_strstr(pos, "[id=");
        if (pos) {
            copy = os_strdup(pos + 4);
        }

        if (copy) {
            pos2 = id = copy;
            while (*pos2 && *pos2 != ' ') {
                pos2++;
            }
            *pos2++ = '\0';
            new_id = atoi(id);
            os_setenv("WPA_ID", id, 1);
            while (*pos2 && *pos2 != '=') {
                pos2++;
            }
            if (*pos2 == '=') {
                pos2++;
            }
            id = pos2;
            while (*pos2 && *pos2 != ']') {
                pos2++;
            }
            *pos2 = '\0';
            os_setenv("WPA_ID_STR", id, 1);
            os_free(copy);
        }

        //        os_setenv("WPA_CTRL_DIR", ctrl_iface_dir, 1);

        if (wpa_cli_connected <= 0 || new_id != wpa_cli_last_id) {
            wpa_cli_connected = 1;
            wpa_cli_last_id = new_id;
            wpa_cli_exec(action_dhcp.constData(), qPrintable(interfaceFilePath.fileName()),
                         "CONNECTED");
        }
        //        showTrayMessage(QSystemTrayIcon::Information, 3,
        //                        tr("Connection to network established."));
        //        QTimer::singleShot(5 * 1000, this, SLOT(showTrayStatus()));
        //        stopWpsRun(true);
    } else if (str_match(pos, WPS_EVENT_AP_AVAILABLE_PBC)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPS_EVENT_AP_AVAILABLE_PBC\n%s",
                "WPS AP in active PBC mode found\n"
                "Press the PBC button on the screen to start registration");
        //        wpsStatusText->setText(tr("WPS AP in active PBC mode found"));
        //        if (textStatus->text() == "INACTIVE" ||
        //            textStatus->text() == "DISCONNECTED") {
        //            wpaguiTab->setCurrentWidget(wpsTab);
        //        }
        //        wpsInstructions->setText(tr("Press the PBC button on the "
        //                                    "screen to start registration"));
    } else if (str_match(pos, WPS_EVENT_AP_AVAILABLE_PIN)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPS_EVENT_AP_AVAILABLE_PIN\n%s",
                "WPS AP with recently selected registrar");
        //        wpsStatusText->setText(tr("WPS AP with recently selected "
        //                                  "registrar"));
        //        if (textStatus->text() == "INACTIVE" ||
        //            textStatus->text() == "DISCONNECTED") {
        //            wpaguiTab->setCurrentWidget(wpsTab);
        //        }
    } else if (str_match(pos, WPS_EVENT_AP_AVAILABLE_AUTH)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPS_EVENT_AP_AVAILABLE_AUTH\n%s",
                "WPS AP indicating this client is authorized");
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
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPS_EVENT_AP_AVAILABLE\n%s",
                "WPS AP detected");
        //        wpsStatusText->setText(tr("WPS AP detected"));
    } else if (str_match(pos, WPS_EVENT_OVERLAP)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPS_EVENT_OVERLAP\n%s",
                "PBC mode overlap detected");
        //        wpsStatusText->setText(tr("PBC mode overlap detected"));
        //        wpsInstructions->setText(tr("More than one AP is currently in "
        //                                    "active WPS PBC mode. Wait couple "
        //                                    "of minutes and try again"));
        //        wpaguiTab->setCurrentWidget(wpsTab);
    } else if (str_match(pos, WPS_EVENT_CRED_RECEIVED)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPS_EVENT_CRED_RECEIVED\n%s",
                "Network configuration received");
        //        wpsStatusText->setText(tr("Network configuration received"));
        //        wpaguiTab->setCurrentWidget(wpsTab);
    } else if (str_match(pos, WPA_EVENT_EAP_METHOD)) {
        if (strstr(pos, "(WSC)")) {
            qCDebug(wifiWPAAdapter, "[ MSG ] = WPA_EVENT_EAP_METHOD\n%s",
                    "Registration started");
            //            wpsStatusText->setText(tr("Registration started"));
        }
    } else if (str_match(pos, WPS_EVENT_M2D)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPS_EVENT_M2D\n%s",
                "Registrar does not yet know PIN");
        //        wpsStatusText->setText(tr("Registrar does not yet know PIN"));
    } else if (str_match(pos, WPS_EVENT_FAIL)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPS_EVENT_FAIL\n%s", "Registration failed");
        //        wpsStatusText->setText(tr("Registration failed"));
    } else if (str_match(pos, WPS_EVENT_SUCCESS)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPS_EVENT_SUCCESS\n%s",
                "Registration succeeded");
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
    QFileInfo iFile;
    for(int i = 0; i < allInterfaces.length(); ++i) {
        iFile = allInterfaces.at(i);
        if(iFile.filePath().endsWith(interface)) {
            break;
        }
    }

    if(interfaceFilePath == iFile) {
        return true;
    }

    QString iface = iFile.fileName();

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

    qCDebug(wifiWPAAdapter, "Trying to connect to '%s'",
            qUtf8Printable(iface));

    wpaConnection = wpa_ctrl_open(qUtf8Printable(iFile.filePath()));
    if (wpaConnection == NULL) {
        qCCritical(wifiWPAAdapter, "Failed to open connection! '%s'",
                   qUtf8Printable(iface));
        return false;
    }
    qCDebug(wifiWPAAdapter, "Successed to open connection. '%s'",
            qUtf8Printable(iface));

    wpaMonitor = wpa_ctrl_open(qUtf8Printable(iFile.filePath()));
    if (wpaMonitor == NULL) {
        wpa_ctrl_close(wpaConnection);
        wpaConnection = NULL;
        qCCritical(wifiWPAAdapter, "Failed to monitor connection! '%s'",
                   qUtf8Printable(iface));
        return false;
    }
    qCDebug(wifiWPAAdapter, "Successed to monitor connection. '%s'",
            qUtf8Printable(iface));

    if (wpa_ctrl_attach(wpaMonitor)) {
        qCCritical(wifiWPAAdapter, "Failed to attach to wpa_supplicant! '%s'",
                   qUtf8Printable(iface));
        wpa_ctrl_close(wpaMonitor);
        wpaMonitor = NULL;
        wpa_ctrl_close(wpaConnection);
        wpaConnection = NULL;
        return false;
    }
    qCDebug(wifiWPAAdapter, "Successed to attach to wpa_supplicant. '%s'",
            qUtf8Printable(iface));

#if defined(CONFIG_CTRL_IFACE_UNIX) || defined(CONFIG_CTRL_IFACE_UDP)
    msgNotifier = new QSocketNotifier(wpa_ctrl_get_fd(wpaMonitor),
                                      QSocketNotifier::Read, q_func());
    QObjectPrivate::connect(msgNotifier, &QSocketNotifier::activated, this,
                            &WifiWPAAdapterPrivate::receiveMsgs);
#endif

    interfaceFilePath = iFile;

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
        if (select(interfaceFilePath.filePath())) {
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

void WifiWPAAdapterPrivate::scanRequest()
{
    char reply[10];
    size_t reply_len = sizeof(reply);

    if (wpaConnection == NULL) {
        return;
    }

    ctrlRequest("SCAN", reply, &reply_len);
}

void WifiWPAAdapterPrivate::updateScanResults()
{
    char reply[2048];
    char reply_decode[2048];
    size_t reply_len;
    int index;
    char cmd[20];
    QString printable;
    QTextStream text(&printable);

    wifiPoints.clear();

    index = 0;

    qCDebug(wifiWPAAdapter, "GET_SCAN_RESULTS [ Start ].");
    text << qSetFieldWidth(20) << left << QStringLiteral("SSID")
         << qSetFieldWidth(20) << left << QStringLiteral("BSSID")
         << qSetFieldWidth(8) << left << QStringLiteral("Freq")
         << qSetFieldWidth(8) << left << QStringLiteral("Signal")
         << qSetFieldWidth(20) << left << QStringLiteral("Security")
         << qSetFieldWidth(1) << endl;

    for(index = 0; index < 1000; ++index) {
        snprintf(cmd, sizeof(cmd), "BSS %d", index);

        reply_len = sizeof(reply) - 1;
        if (ctrlRequest(cmd, reply, &reply_len) < 0) {
            qCCritical(wifiWPAAdapter, "GET_SCAN_RESULTS [ Failed ].");
            break;
        }
        reply[reply_len] = '\0';

        printf_decode((u8 *)reply_decode, sizeof(reply_decode), reply);
        QString bss = QString(reply_decode);
        if (bss.startsWith("FAIL")) {
            qCCritical(wifiWPAAdapter, "GET_SCAN_RESULTS [ Failed ].\n%s",
                       qPrintable(bss));
            break;
        }

        QString ssid, bssid, freq, signal, flags;

        QStringList lines = bss.split(QRegExp("\\n"));
        for (QStringList::Iterator it = lines.begin();
             it != lines.end(); it++) {
            int pos = (*it).indexOf('=') + 1;
            if (pos < 1) {
                continue;
            }

            if ((*it).startsWith("bssid=")) {
                bssid = (*it).mid(pos);
            } else if ((*it).startsWith("freq=")) {
                freq = (*it).mid(pos);
            } else if ((*it).startsWith("level=")) {
                signal = (*it).mid(pos);
            } else if ((*it).startsWith("flags=")) {
                flags = (*it).mid(pos);
            } else if ((*it).startsWith("ssid=")) {
                ssid = (*it).mid(pos);
            }
        }

        if (bssid.isEmpty()) {
            qCDebug(wifiWPAAdapter, "GET_SCAN_RESULTS [ Debug ].\n%s",
                    qUtf8Printable(printable));
            qCDebug(wifiWPAAdapter, "GET_SCAN_RESULTS [ End ].");
            break;
        }

        Wifi::Securitys auths = Wifi::NoneOpen;
        Wifi::Encrytions encrs = Wifi::None;
        if (flags.indexOf("WPA2-EAP") >= 0) {
            auths.setFlag(Wifi::WPA2_EAP);
        }
        if (flags.indexOf("WPA-EAP") >= 0) {
            auths.setFlag(Wifi::WPA_EAP);
        }
        if (flags.indexOf("WPA2-PSK") >= 0) {
            auths.setFlag(Wifi::WPA2_PSK);
        }
        if (flags.indexOf("WPA-PSK") >= 0) {
            auths.setFlag(Wifi::WPA_PSK);
        }

        if (flags.indexOf("CCMP") >= 0) {
            encrs.setFlag(Wifi::CCMP);
        }
        if (flags.indexOf("TKIP") >= 0) {
            encrs.setFlag(Wifi::TKIP);
        }
        if (flags.indexOf("WEP") >= 0) {
            encrs.setFlag(Wifi::WEP);
            if (auths == Wifi::NoneOpen) {
                auths = Wifi::NoneWEP;
            }
        }


        WifiAccessPoint *point = new WifiAccessPoint(bssid, q_func());
        point->setSsid(ssid);
        point->setFrequency(freq.toInt());
        point->setStrength(signal.toInt());
        point->setSecuritys(auths);
        point->setEncrytions(encrs);

        wifiPoints.append(point);

        text << qSetFieldWidth(20) << left << ssid
             << qSetFieldWidth(20) << left << bssid
             << qSetFieldWidth(8) << left << freq
             << qSetFieldWidth(8) << left << signal
             << qSetFieldWidth(20) << left << Wifi::toString(auths)
             << qSetFieldWidth(1) << endl;
    }
}

WifiWPAAdapter::WifiWPAAdapter(QObject *parent)
    : QObject(*(new WifiWPAAdapterPrivate), parent)
{
    Q_D(WifiWPAAdapter);

    d->timer = new QTimer(this);
    QObjectPrivate::connect(d->timer, &QTimer::timeout, d,
                            &WifiWPAAdapterPrivate::ping);
    d->timer->setSingleShot(false);
    d->timer->start(1000);

    d->signalMeterTimer = new QTimer;
    d->signalMeterTimer->setInterval(d->signalMeterInterval);
    QObjectPrivate::connect(d->signalMeterTimer, &QTimer::timeout, d,
                            &WifiWPAAdapterPrivate::signalMeterUpdate);

    d->updateStatus();
    d->networkMayHaveChanged = true;
    d->updateNetworks();
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
    Q_D(WifiWPAAdapter);
    d->scanRequest();
}
