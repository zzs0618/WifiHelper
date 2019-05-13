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
#include <QProcess>
#include <QTimer>
#include <QList>

extern "C"
{
#include "common/wpa_ctrl.h"
#include "utils/os.h"
#include "utils/common.h"
}

// in one source file
Q_LOGGING_CATEGORY(wifiWPAAdapter, "wifi.helper.wpa.adapter")
Q_LOGGING_CATEGORY(wifiWPAP2P, "wifi.helper.wpa.p2p")

// The number of update status triggered by the PING
#define NUMBER_PING_UPDATE_STATUS 5
// Signal strength refresh interval in milliseconds
#define INTERVAL_SIGNAL_UPDATE 5000

const static QString WPACtrlIfaceDir = QLatin1String("/var/run/wpa_supplicant");
static QByteArray WPAInterface = "wlan0";
static QByteArray WPACommand = "wpa_supplicant -c /etc/p2p_supplicant.conf";
static QByteArray WPAActionDHCPClient = "/sbin/dhcpc_action.sh";
static QByteArray WPAActionDHCPDeamon = "/sbin/dhcpd_action.sh";

static int str_match(const char *a, const char *b)
{
    return strncmp(a, b, strlen(b)) == 0;
}

static int key_value_isset(const char *reply, size_t reply_len)
{
    return reply_len > 0 && (reply_len < 4 || memcmp(reply, "FAIL", 4) != 0);
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
    void paramsFromConfig(WifiNetwork *network);
    void updateNetworks();
    void receiveMsgs();
    void p2p_event_notify(QString msg);
    void processMsg(char *msg);
    WifiAccessPoint *getAccessPointBySSID(const QString &ssid);
    WifiNetwork *getNetworkBySSID(const QString &ssid);
    WifiNetwork *getNetworkById(int id);

    void open();
    void close();

    bool openWPAConnection(const QString &iface);
    bool connect();
    bool disconnect();
    void saveConfig();
    void ping();
    void scanRequest();
    void updateScanResults();
    void triggerUpdate();

    void p2p_start();
    void p2p_stop();
    void p2p_connectPBC(const QString &address);

    int addNetwork(const QString &ssid, const QString &password);
    void selectNetwork(const QString &ssid);
    void selectNetwork(int id);
    void removeNetwork(const QString &ssid);
    void removeNetwork(int id);

    int pingsToStatusUpdate = NUMBER_PING_UPDATE_STATUS;
    QSocketNotifier *msgNotifier = NULL;
    QTimer *timer = NULL;
    QTimer *signalMeterTimer = NULL;
    int signalMeterInterval = INTERVAL_SIGNAL_UPDATE;
    bool networkMayHaveChanged = false;

    QProcess *app_wpa = NULL;

    struct wpa_ctrl *ctrl_conn = NULL;
    struct wpa_ctrl *monitor_conn = NULL;
    int wpa_cli_last_id = 0;
    int wpa_cli_connected = -1;

    QString m_bssid;
    QString m_ssid;
    QString m_ipAddress;
    QString m_mode;
    QString m_state;
    QString m_security;
    QString m_pairwiseCipher;
    QString m_groupCipher;
    int m_rssiValue = -100;
    QList<WifiAccessPoint *> m_accessPoints;
    QList<WifiNetwork *> m_networks;
    QList<WifiP2PDevice *> m_p2pDevcies;
    QString m_interface;

protected:
    int ctrlRequest(const char *cmd, char *buf, size_t *buflen);
    int setNetworkParam(int id, const char *field, const char *value, bool quote);
};

WifiWPAAdapterPrivate::WifiWPAAdapterPrivate()
    : QObjectPrivate()
{
    if(!qEnvironmentVariableIsEmpty("WIFI_HELPER_INTERFACE")) {
        WPAInterface = qgetenv("WIFI_HELPER_INTERFACE");
    }
    if(!qEnvironmentVariableIsEmpty("WIFI_HELPER_CMD_WPA")) {
        WPACommand = qgetenv("WIFI_HELPER_CMD_WPA");
    }
    if(!qEnvironmentVariableIsEmpty("WIFI_HELPER_ACTION_DHCPC")) {
        WPAActionDHCPClient = qgetenv("WIFI_HELPER_ACTION_DHCPC");
    }
    if(!qEnvironmentVariableIsEmpty("WIFI_HELPER_ACTION_DHCPD")) {
        WPAActionDHCPDeamon = qgetenv("WIFI_HELPER_ACTION_DHCPD");
    }
}

WifiWPAAdapterPrivate::~WifiWPAAdapterPrivate()
{
    this->close();
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
    char reply[128];
    size_t reply_len = sizeof(reply);
    char *rssi;
    int rssi_value = -100;

    ctrlRequest("SIGNAL_POLL", reply, &reply_len); // RSSI

    /* In order to eliminate signal strength fluctuations, try
     * to obtain averaged RSSI value in the first place. */
    if ((rssi = strstr(reply, "AVG_RSSI=")) != NULL) {
        rssi_value = atoi(&rssi[sizeof("AVG_RSSI")]);
    } else if ((rssi = strstr(reply, "RSSI=")) != NULL) {
        rssi_value = atoi(&rssi[sizeof("RSSI")]);
    } else {
        qCCritical(wifiWPAAdapter, "Failed to get RSSI value of '%s'!",
                   qUtf8Printable(m_ssid));
        return;
    }

    if(m_rssiValue != rssi_value) {
        qCInfo(wifiWPAAdapter, "RSSI value: %d of '%s'.", rssi_value,
               qUtf8Printable(m_ssid));
        m_rssiValue = rssi_value;
    }
}

void WifiWPAAdapterPrivate::updateStatus()
{
    char buf[2048], *start, *end, *pos;
    char decode[2048];
    size_t len;

    pingsToStatusUpdate = NUMBER_PING_UPDATE_STATUS;

    len = sizeof(buf) - 1;
    if (ctrl_conn == NULL || ctrlRequest("STATUS", buf, &len) < 0) {
        qCCritical(wifiWPAAdapter, "Could not get status from wpa_supplicant.");
        signalMeterTimer->stop();
        m_rssiValue = -100;
        return;
    }

    buf[len] = '\0';
    printf_decode((u8 *)decode, sizeof(decode), buf);

    QString _bssid, _ssid, _ipAddress, _wpaMode, _wpaState, _wpaSecurity,
            _pairwiseCipher, _groupCipher;
    bool security_updated = false, ssid_updated = false;
    bool bssid_updated = false, ipaddr_updated = false;
    bool status_updated = false;

    start = decode;
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
                _bssid = QString(pos);
            } else if (strcmp(start, "ssid") == 0) {
                _ssid = QString(pos);
            } else if (strcmp(start, "ip_address") == 0) {
                _ipAddress = QString(pos);
            } else if (strcmp(start, "wpa_state") == 0) {
                _wpaState = wpaStateTranslate(pos);
            } else if (strcmp(start, "key_mgmt") == 0 ) {
                _wpaSecurity = QString(pos);
                /* TODO: could add EAP status to this */
            } else if (strcmp(start, "pairwise_cipher") == 0 ) {
                _pairwiseCipher = QString(pos);
            } else if (strcmp(start, "group_cipher") == 0) {
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

    if(m_ssid != _ssid) {
        ssid_updated = true;
        m_ssid = _ssid;
    }
    if(m_bssid != _bssid) {
        bssid_updated = true;
        m_bssid = _bssid;
    }
    if(m_security != _wpaSecurity) {
        security_updated = true;
        m_security = _wpaSecurity;
    }
    if(m_ipAddress != _ipAddress) {
        ipaddr_updated = true;
        m_ipAddress = _ipAddress;
    }
    if(m_state != _wpaState) {
        status_updated = true;
        m_state = _wpaState;
    }
    if(m_pairwiseCipher != _pairwiseCipher) {
        m_pairwiseCipher = _pairwiseCipher;
    }
    if(m_groupCipher != _groupCipher) {
        m_groupCipher = _groupCipher;
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

        qCInfo(wifiWPAAdapter,
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
        if (m_ssid != "") {
            if (!signalMeterTimer->isActive()) {
                signalMeterTimer->start();
            }
        } else {
            signalMeterTimer->stop();
            m_rssiValue = -100;
        }
    }

    scanRequest();
}

void WifiWPAAdapterPrivate::paramsFromConfig(WifiNetwork *network)
{
    int network_id = network->id();
    int res;

    char reply[1024], cmd[256], *pos;
    size_t reply_len;

    snprintf(cmd, sizeof(cmd), "GET_NETWORK %d proto", network_id);
    reply_len = sizeof(reply) - 1;
    int wpa = 0;
    if (this->ctrlRequest(cmd, reply, &reply_len) >= 0) {
        reply[reply_len] = '\0';
        if (strstr(reply, "RSN") || strstr(reply, "WPA2")) {
            wpa = 2;
        } else if (strstr(reply, "WPA")) {
            wpa = 1;
        }
    }

    enum {
        AUTH_NONE_OPEN,
        AUTH_NONE_WEP,
        AUTH_NONE_WEP_SHARED,
        AUTH_IEEE8021X,
        AUTH_WPA_PSK,
        AUTH_WPA_EAP,
        AUTH_WPA2_PSK,
        AUTH_WPA2_EAP
    };
    Wifi::Security auth = Wifi::NoneOpen;
    Wifi::Encrytion encr = Wifi::None;
    snprintf(cmd, sizeof(cmd), "GET_NETWORK %d key_mgmt", network_id);
    reply_len = sizeof(reply) - 1;
    if (this->ctrlRequest(cmd, reply, &reply_len) >= 0) {
        reply[reply_len] = '\0';
        if (strstr(reply, "WPA-EAP")) {
            auth = wpa & 2 ? Wifi::WPA2_EAP : Wifi::WPA_EAP;
        } else if (strstr(reply, "WPA-PSK")) {
            auth = wpa & 2 ? Wifi::WPA2_PSK : Wifi::WPA_PSK;
        } else if (strstr(reply, "IEEE8021X")) {
            auth = Wifi::IEEE8021X;
            encr = Wifi::WEP;
        }
    }

    snprintf(cmd, sizeof(cmd), "GET_NETWORK %d pairwise", network_id);
    reply_len = sizeof(reply) - 1;
    if (this->ctrlRequest(cmd, reply, &reply_len) >= 0) {
        reply[reply_len] = '\0';
        if (strstr(reply, "CCMP") && auth != Wifi::NoneOpen &&
            auth != Wifi::NoneWEP && auth != Wifi::NoneWEPShared) {
            encr = Wifi::CCMP;
        } else if (strstr(reply, "TKIP")) {
            encr = Wifi::TKIP;
        } else if (strstr(reply, "WEP")) {
            encr = Wifi::WEP;
        } else {
            encr = Wifi::None;
        }
    }

    snprintf(cmd, sizeof(cmd), "GET_NETWORK %d psk", network_id);
    reply_len = sizeof(reply) - 1;
    res = this->ctrlRequest(cmd, reply, &reply_len);
    if (res >= 0 && reply_len >= 2 && reply[0] == '"') {
        reply[reply_len] = '\0';
        pos = strchr(reply + 1, '"');
        if (pos) {
            *pos = '\0';
        }
        network->setPsk(QString(reply + 1));
        //        pskEdit->setText(reply + 1);
    } else if (res >= 0 && key_value_isset(reply, reply_len)) {
        network->setPsk(QStringLiteral("[key is configured]"));
        //        pskEdit->setText(WPA_GUI_KEY_DATA);
    }

    snprintf(cmd, sizeof(cmd), "GET_NETWORK %d identity", network_id);
    reply_len = sizeof(reply) - 1;
    if (this->ctrlRequest(cmd, reply, &reply_len) >= 0 &&
        reply_len >= 2 && reply[0] == '"') {
        reply[reply_len] = '\0';
        pos = strchr(reply + 1, '"');
        if (pos) {
            *pos = '\0';
        }
        //        identityEdit->setText(reply + 1);
    }

    snprintf(cmd, sizeof(cmd), "GET_NETWORK %d password", network_id);
    reply_len = sizeof(reply) - 1;
    res = this->ctrlRequest(cmd, reply, &reply_len);
    if (res >= 0 && reply_len >= 2 && reply[0] == '"') {
        reply[reply_len] = '\0';
        pos = strchr(reply + 1, '"');
        if (pos) {
            *pos = '\0';
        }
        //        passwordEdit->setText(reply + 1);
    } else if (res >= 0 && key_value_isset(reply, reply_len)) {
        //        passwordEdit->setText(WPA_GUI_KEY_DATA);
    }

    snprintf(cmd, sizeof(cmd), "GET_NETWORK %d ca_cert", network_id);
    reply_len = sizeof(reply) - 1;
    if (this->ctrlRequest(cmd, reply, &reply_len) >= 0 &&
        reply_len >= 2 && reply[0] == '"') {
        reply[reply_len] = '\0';
        pos = strchr(reply + 1, '"');
        if (pos) {
            *pos = '\0';
        }
        //        cacertEdit->setText(reply + 1);
    }

    enum { NO_INNER, PEAP_INNER, TTLS_INNER, FAST_INNER } eap = NO_INNER;
    //    snprintf(cmd, sizeof(cmd), "GET_NETWORK %d eap", network_id);
    //    reply_len = sizeof(reply) - 1;
    //    if (this->ctrlRequest(cmd, reply, &reply_len) >= 0 &&
    //        reply_len >= 1) {
    //        reply[reply_len] = '\0';
    //        for (i = 0; i < eapSelect->count(); i++) {
    //            if (eapSelect->itemText(i).compare(reply) == 0) {
    //                eapSelect->setCurrentIndex(i);
    //                if (strcmp(reply, "PEAP") == 0) {
    //                    eap = PEAP_INNER;
    //                } else if (strcmp(reply, "TTLS") == 0) {
    //                    eap = TTLS_INNER;
    //                } else if (strcmp(reply, "FAST") == 0) {
    //                    eap = FAST_INNER;
    //                }
    //                break;
    //            }
    //        }
    //    }

    if (eap != NO_INNER) {
        snprintf(cmd, sizeof(cmd), "GET_NETWORK %d phase2",
                 network_id);
        reply_len = sizeof(reply) - 1;
        if (this->ctrlRequest(cmd, reply, &reply_len) >= 0 &&
            reply_len >= 1) {
            reply[reply_len] = '\0';
            //            eapChanged(eapSelect->currentIndex());
        } else {
            eap = NO_INNER;
        }
    }

    char *val;
    val = reply + 1;
    while (*(val + 1)) {
        val++;
    }
    if (*val == '"') {
        *val = '\0';
    }

    switch (eap) {
        case PEAP_INNER:
            if (strncmp(reply, "\"auth=", 6)) {
                break;
            }
            val = reply + 2;
            memcpy(val, "EAP-", 4);
            break;
        case TTLS_INNER:
            if (strncmp(reply, "\"autheap=", 9) == 0) {
                val = reply + 5;
                memcpy(val, "EAP-", 4);
            } else if (strncmp(reply, "\"auth=", 6) == 0) {
                val = reply + 6;
            }
            break;
        case FAST_INNER:
            if (strncmp(reply, "\"auth=", 6)) {
                break;
            }
            if (strcmp(reply + 6, "GTC auth=MSCHAPV2") == 0) {
                val = (char *) "GTC(auth) + MSCHAPv2(prov)";
                break;
            }
            val = reply + 2;
            memcpy(val, "EAP-", 4);
            break;
        case NO_INNER:
            break;
    }

    //    for (i = 0; i < phase2Select->count(); i++) {
    //        if (phase2Select->itemText(i).compare(val) == 0) {
    //            phase2Select->setCurrentIndex(i);
    //            break;
    //        }
    //    }

    //    for (i = 0; i < 4; i++) {
    //        QLineEdit *wepEdit;
    //        switch (i) {
    //            default:
    //            case 0:
    //                wepEdit = wep0Edit;
    //                break;
    //            case 1:
    //                wepEdit = wep1Edit;
    //                break;
    //            case 2:
    //                wepEdit = wep2Edit;
    //                break;
    //            case 3:
    //                wepEdit = wep3Edit;
    //                break;
    //        }
    //        snprintf(cmd, sizeof(cmd), "GET_NETWORK %d wep_key%d",
    //                 network_id, i);
    //        reply_len = sizeof(reply) - 1;
    //        res = this->ctrlRequest(cmd, reply, &reply_len);
    //        if (res >= 0 && reply_len >= 2 && reply[0] == '"') {
    //            reply[reply_len] = '\0';
    //            pos = strchr(reply + 1, '"');
    //            if (pos) {
    //                *pos = '\0';
    //            }
    //            if (auth == AUTH_NONE_OPEN || auth == AUTH_IEEE8021X) {
    //                if (auth == AUTH_NONE_OPEN) {
    //                    auth = AUTH_NONE_WEP;
    //                }
    //                encr = Wifi::WEP;
    //            }

    //            wepEdit->setText(reply + 1);
    //        } else if (res >= 0 && key_value_isset(reply, reply_len)) {
    //            if (auth == AUTH_NONE_OPEN || auth == AUTH_IEEE8021X) {
    //                if (auth == AUTH_NONE_OPEN) {
    //                    auth = AUTH_NONE_WEP;
    //                }
    //                encr = Wifi::WEP;
    //            }
    //            wepEdit->setText(WPA_GUI_KEY_DATA);
    //        }
    //    }

    if (auth == Wifi::NoneWEP) {
        snprintf(cmd, sizeof(cmd), "GET_NETWORK %d auth_alg",
                 network_id);
        reply_len = sizeof(reply) - 1;
        if (this->ctrlRequest(cmd, reply, &reply_len) >= 0) {
            reply[reply_len] = '\0';
            if (strcmp(reply, "SHARED") == 0) {
                auth = Wifi::NoneWEPShared;
            }
        }
    }

    //    snprintf(cmd, sizeof(cmd), "GET_NETWORK %d wep_tx_keyidx", network_id);
    //    reply_len = sizeof(reply) - 1;
    //    if (this->ctrlRequest(cmd, reply, &reply_len) >= 0 && reply_len >= 1) {
    //        reply[reply_len] = '\0';
    //        switch (atoi(reply)) {
    //            case 0:
    //                wep0Radio->setChecked(true);
    //                break;
    //            case 1:
    //                wep1Radio->setChecked(true);
    //                break;
    //            case 2:
    //                wep2Radio->setChecked(true);
    //                break;
    //            case 3:
    //                wep3Radio->setChecked(true);
    //                break;
    //        }
    //    }

    //    snprintf(cmd, sizeof(cmd), "GET_NETWORK %d id_str", network_id);
    //    reply_len = sizeof(reply) - 1;
    //    if (this->ctrlRequest(cmd, reply, &reply_len) >= 0 &&
    //        reply_len >= 2 && reply[0] == '"') {
    //        reply[reply_len] = '\0';
    //        pos = strchr(reply + 1, '"');
    //        if (pos) {
    //            *pos = '\0';
    //        }
    //        idstrEdit->setText(reply + 1);
    //    }

    //    snprintf(cmd, sizeof(cmd), "GET_NETWORK %d priority", network_id);
    //    reply_len = sizeof(reply) - 1;
    //    if (this->ctrlRequest(cmd, reply, &reply_len) >= 0 && reply_len >= 1) {
    //        reply[reply_len] = '\0';
    //        prioritySpinBox->setValue(atoi(reply));
    //    }

    network->setSecurity(auth);
    network->setEncrytion(encr);
    //    authSelect->setCurrentIndex(auth);
    //    authChanged(auth);
    //    encrSelect->setCurrentIndex(encr);
    //    wepEnabled(auth == AUTH_NONE_WEP || auth == AUTH_NONE_WEP_SHARED);

}

void WifiWPAAdapterPrivate::updateNetworks()
{
    char buf[4096], *start, *end, *id, *_ssid, *_bssid, *flags;
    size_t len;
    int first_active = -1;
    //    int was_selected = -1;

    if (!networkMayHaveChanged) {
        return;
    }

    //    if (networkList->currentRow() >= 0) {
    //        was_selected = networkList->currentRow();
    //    }

    //    networkSelect->clear();
    //    networkList->clear();

    if (ctrl_conn == NULL) {
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

    qDeleteAll(m_networks);
    m_networks.clear();

    QString printable;
    QTextStream text(&printable);
    qCDebug(wifiWPAAdapter, "LIST_NETWORKS [ Start ].");
    text << qSetFieldWidth(5) << left << QStringLiteral("ID")
         << qSetFieldWidth(20) << left << QStringLiteral("BSSID")
         << qSetFieldWidth(20) << left << QStringLiteral("SSID")
         << qSetFieldWidth(1) << endl;

    while (*start) {
        bool current = false;
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

        if (strstr(flags, "[CURRENT]")) {
            //            networkSelect->setCurrentIndex(networkSelect->count() - 1);
            current = true;
        } else if (first_active < 0 &&
                   strstr(flags, "[DISABLED]") == NULL) {
            //            first_active = networkSelect->count() - 1;
        }

        WifiNetwork *network = new WifiNetwork(QString(id).toInt());
        network->setBssid(_bssid);
        network->setSsid(_ssid);

        paramsFromConfig(network);

        m_networks.append(network);

        text << qSetFieldWidth(1) << (current ? "@" : "")
             << qSetFieldWidth(4) << left << id
             << qSetFieldWidth(20) << left << _bssid
             << qSetFieldWidth(20) << left << _ssid
             << qSetFieldWidth(1) << endl;

        if (last) {
            break;
        }
        start = end + 1;
    }
    //    if (networkSelect->count() > 1) {
    //        networkSelect->addItem(tr("Select any network"));
    //    }

    //    if (!current && first_active >= 0) {
    //        networkSelect->setCurrentIndex(first_active);
    //    }

    //    if (was_selected >= 0 && networkList->count() > 0) {
    //        if (was_selected < networkList->count()) {
    //            networkList->setCurrentRow(was_selected);
    //        } else {
    //            networkList->setCurrentRow(networkList->count() - 1);
    //        }
    //    } else {
    //        networkList->setCurrentRow(networkSelect->currentIndex());
    //    }
    networkMayHaveChanged = false;

    qCDebug(wifiWPAAdapter, "LIST_NETWORKS [ Debug ].\n%s",
            qUtf8Printable(printable));
    qCDebug(wifiWPAAdapter, "LIST_NETWORKS [ End ].");
    Q_EMIT q_func()->networksChanged();
}

void WifiWPAAdapterPrivate::receiveMsgs()
{
    char buf[256];
    size_t len;

    while (monitor_conn && wpa_ctrl_pending(monitor_conn) > 0) {
        len = sizeof(buf) - 1;
        if (wpa_ctrl_recv(monitor_conn, buf, &len) == 0) {
            buf[len] = '\0';
            processMsg(buf);
        }
    }
}

void WifiWPAAdapterPrivate::p2p_event_notify(QString msg)
{
    QString text = msg;

    if (text.startsWith(P2P_EVENT_DEVICE_FOUND)) {
        /*
         * P2P-DEVICE-FOUND 02:b5:64:63:30:63
         * p2p_dev_addr=02:b5:64:63:30:63 pri_dev_type=1-0050f204-1
         * name='Wireless Client' config_methods=0x84 dev_capab=0x21
         * group_capab=0x0
         */
        QStringList items = text.split(QRegExp(" (?=[^']*('[^']*'[^']*)*$)"));
        QString addr = items[1];
        QString name = "";
        QString pri_dev_type;
        int config_methods = 0;
        for (int i = 0; i < items.size(); i++) {
            QString str = items.at(i);
            if (str.startsWith("name='")) {
                name = str.section('\'', 1, -2);
            } else if (str.startsWith("config_methods=")) {
                config_methods = str.section('=', 1).toInt(0, 0);
            } else if (str.startsWith("pri_dev_type=")) {
                pri_dev_type = str.section('=', 1);
            }
        }
        Wifi::DeviceType type = Wifi::DeviceUnknown;
        QString dev_type = pri_dev_type.split('-')[0];
        if(dev_type == "1") {
            type = Wifi::DevicePC;
        } else if(dev_type == "10") {
            type = Wifi::DevicePhone;
        }
        qCDebug(wifiWPAP2P) << text << config_methods;

        WifiP2PDevice *device = new WifiP2PDevice(name, addr, type);
        m_p2pDevcies << device;
        Q_EMIT q_func()->p2pDeviceFound(m_p2pDevcies.indexOf(device));
    } else if (text.startsWith(P2P_EVENT_GROUP_STARTED)) {
        /* P2P-GROUP-STARTED wlan0-p2p-0 GO ssid="DIRECT-3F"
         * passphrase="YOyTkxID" go_dev_addr=02:40:61:c2:f3:b7
         * [PERSISTENT] */
        QStringList items = text.split(' ');
        if (items.size() < 4) {
            return;
        }

        int pos = text.indexOf(" ssid=\"");
        if (pos < 0) {
            return;
        }
        QString ssid = text.mid(pos + 7);
        pos = ssid.indexOf(" passphrase=\"");
        if (pos < 0) {
            pos = ssid.indexOf(" psk=");
        }
        if (pos >= 0) {
            ssid.truncate(pos);
        }
        pos = ssid.lastIndexOf('"');
        if (pos >= 0) {
            ssid.truncate(pos);
        }

        QString group = items[1];
        QString type = items[2];

        qCDebug(wifiWPAP2P) << text;
        qCDebug(wifiWPAP2P) << "P2P_EVENT_GROUP_STARTED" << group << type;
    } else if (text.startsWith(P2P_EVENT_GROUP_REMOVED)) {
        /* P2P-GROUP-REMOVED wlan0-p2p-0 GO */
        QStringList items = text.split(' ');
        if (items.size() < 2) {
            return;
        }

        QString group = items[1];
        QString type = items[2];
        qCDebug(wifiWPAP2P) << text;
        qCDebug(wifiWPAP2P) << "P2P_EVENT_GROUP_REMOVED" << group << type;
        return;
    } else if (text.startsWith(P2P_EVENT_PROV_DISC_SHOW_PIN)) {
        /* P2P-PROV-DISC-SHOW-PIN 02:40:61:c2:f3:b7 12345670 */
        QStringList items = text.split(' ');
        if (items.size() < 3) {
            return;
        }

        QString addr = items[1];
        QString pin = items[2];
        qCDebug(wifiWPAP2P) << text;
        qCDebug(wifiWPAP2P) << "P2P_EVENT_PROV_DISC_SHOW_PIN" << addr << pin;
        return;
    } else if (text.startsWith(P2P_EVENT_PROV_DISC_ENTER_PIN)) {
        /* P2P-PROV-DISC-ENTER-PIN 02:40:61:c2:f3:b7 */
        QStringList items = text.split(' ');
        if (items.size() < 2) {
            return;
        }
        QString addr = items[1];
        qCDebug(wifiWPAAdapter) << text;
        qCDebug(wifiWPAP2P) << "P2P_EVENT_PROV_DISC_ENTER_PIN" << addr;
        return;
    } else if (text.startsWith(P2P_EVENT_INVITATION_RECEIVED)) {
        /* P2P-INVITATION-RECEIVED sa=02:f0:bc:44:87:62 persistent=4 */
        QStringList items = text.split(' ');
        if (items.size() < 3) {
            return;
        }
        if (!items[1].startsWith("sa=") ||
            !items[2].startsWith("persistent=")) {
            return;
        }
        QString addr = items[1].mid(3);
        int id = items[2].mid(11).toInt();

        char cmd[100];
        char reply[100];
        size_t reply_len;

        snprintf(cmd, sizeof(cmd), "GET_NETWORK %d ssid", id);
        reply_len = sizeof(reply) - 1;
        if (this->ctrlRequest(cmd, reply, &reply_len) < 0) {
            return;
        }
        reply[reply_len] = '\0';
        QString name;
        char *pos = strrchr(reply, '"');
        if (pos && reply[0] == '"') {
            *pos = '\0';
            name = reply + 1;
        } else {
            name = reply;
        }
        qCDebug(wifiWPAP2P) << text;
        qCDebug(wifiWPAP2P) << "P2P_EVENT_INVITATION_RECEIVED" << addr << name;
        return;
    } else if (text.startsWith(P2P_EVENT_INVITATION_RESULT)) {
        /* P2P-INVITATION-RESULT status=1 */
        /* TODO */
        qCDebug(wifiWPAP2P) << text;
        return;
    } else if (text.startsWith(AP_STA_CONNECTED)) {
        qCDebug(wifiWPAP2P) << text;
        return;
    } else if (text.startsWith(AP_STA_DISCONNECTED)) {
        qCDebug(wifiWPAP2P) << text;
        return;
    } else if (text.startsWith("P2P")) {
        qCDebug(wifiWPAP2P) << text;
        return;
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

    this->p2p_event_notify(QString(pos));

    /*
        WpaMsg wm(pos, priority);
        if (eh) {
            eh->addEvent(wm);
        }
        if (peers) {
            this->event_notify(wm);
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
        qCInfo(wifiWPAAdapter, "[ MSG ] = WPA_EVENT_DISCONNECTED\n%s",
               "Disconnected from network.");
        if (wpa_cli_connected) {
            wpa_cli_connected = 0;
            // Release DHCP
            wpa_cli_exec(WPAActionDHCPClient.constData(),
                         qPrintable(m_interface),
                         "DISCONNECTED");
        }
        //        showTrayMessage(QSystemTrayIcon::Information, 3,
        //                        tr("Disconnected from network."));
    } else if (str_match(pos, WPA_EVENT_CONNECTED)) {
        qCInfo(wifiWPAAdapter, "[ MSG ] = WPA_EVENT_CONNECTED\n%s",
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

        os_setenv("WPA_CTRL_DIR", qUtf8Printable(WPACtrlIfaceDir), 1);

        if (wpa_cli_connected <= 0 || new_id != wpa_cli_last_id) {
            wpa_cli_connected = 1;
            wpa_cli_last_id = new_id;
            // Request DHCP
            wpa_cli_exec(WPAActionDHCPClient.constData(),
                         qPrintable(m_interface),
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
    } else if (str_starts(pos, P2P_EVENT_GROUP_STARTED)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = P2P_EVENT_GROUP_STARTED\n%s",
                pos);
        wpa_cli_exec(WPAActionDHCPDeamon.constData(),
                     qPrintable(m_interface),
                     pos);
    } else if (str_starts(pos, P2P_EVENT_GROUP_REMOVED)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = P2P_EVENT_GROUP_REMOVED\n%s",
                pos);
        wpa_cli_exec(WPAActionDHCPDeamon.constData(),
                     qPrintable(m_interface),
                     pos);
    } else if (str_starts(pos, P2P_EVENT_CROSS_CONNECT_ENABLE)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = P2P_EVENT_CROSS_CONNECT_ENABLE\n%s",
                pos);
    } else if (str_starts(pos, P2P_EVENT_CROSS_CONNECT_DISABLE)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = P2P_EVENT_CROSS_CONNECT_DISABLE\n%s",
                pos);
    } else if (str_starts(pos, P2P_EVENT_GO_NEG_REQUEST)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = P2P_EVENT_GO_NEG_REQUEST\n%s",
                pos);
    } else if (str_starts(pos, P2P_EVENT_GO_NEG_SUCCESS)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = P2P_EVENT_GO_NEG_SUCCESS\n%s",
                pos);
    } else if (str_starts(pos, P2P_EVENT_GO_NEG_FAILURE)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = P2P_EVENT_GO_NEG_FAILURE\n%s",
                pos);
    } else if (str_starts(pos, AP_STA_CONNECTED)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = AP_STA_CONNECTED\n%s",
                pos);
    } else if (str_starts(pos, AP_STA_DISCONNECTED)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = AP_STA_DISCONNECTED\n%s",
                pos);
    } else if (str_starts(pos, WPA_EVENT_TERMINATING)) {
        qCDebug(wifiWPAAdapter, "[ MSG ] = WPA_EVENT_TERMINATING\n%s",
                pos);
    } else {
        //        qCDebug(wifiWPAAdapter, "[ MSG ] = OTHER\n%s",
        //                pos);
    }
}

WifiAccessPoint *WifiWPAAdapterPrivate::getAccessPointBySSID(
                const QString &ssid)
{
    for(WifiAccessPoint *ap : this->m_accessPoints) {
        if(ap->ssid() == ssid) {
            return ap;
        }
    }
    return NULL;
}

WifiNetwork *WifiWPAAdapterPrivate::getNetworkBySSID(const QString &ssid)
{
    for(WifiNetwork *net : this->m_networks) {
        if(net->ssid() == ssid) {
            return net;
        }
    }
    return NULL;
}

WifiNetwork *WifiWPAAdapterPrivate::getNetworkById(int id)
{
    for(WifiNetwork *net : this->m_networks) {
        if(net->id() == id) {
            return net;
        }
    }
    return NULL;
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
        qCCritical(wifiWPAAdapter, "'%s' command timed out.", cmd);
    } else if (ret < 0) {
        qCCritical(wifiWPAAdapter, "'%s' command failed.", cmd);
    }
    return ret;
}

int WifiWPAAdapterPrivate::setNetworkParam(int id, const char *field,
        const char *value, bool quote)
{
    char reply[10], cmd[256];
    size_t reply_len;
    snprintf(cmd, sizeof(cmd), "SET_NETWORK %d %s %s%s%s",
             id, field, quote ? "\"" : "", value, quote ? "\"" : "");
    reply_len = sizeof(reply);
    ctrlRequest(cmd, reply, &reply_len);
    return strncmp(reply, "OK", 2) == 0 ? 0 : -1;
}

void WifiWPAAdapterPrivate::open()
{
    if(app_wpa == NULL) {
        qCInfo(wifiWPAAdapter, "Open WIFI [ First ].");
        app_wpa = new QProcess();
    }

    qCInfo(wifiWPAAdapter, "Open WIFI [ Start ].");
    if(app_wpa->state() == QProcess::NotRunning) {
        QStringList command = QString::fromLocal8Bit(WPACommand).split(
                                              QLatin1Char(' '));
        QString interface = QString::fromLocal8Bit(WPAInterface);
        QString program = command[0];
        QStringList arguments = command.mid(1);
        arguments << "-i" << interface;
        app_wpa->start(program, arguments);
        bool success = app_wpa->waitForStarted(5000);

        if(success) {
            app_wpa->waitForReadyRead(5000);
            qCDebug(wifiWPAAdapter) << app_wpa->readAll();

            timer->start(1000);
            networkMayHaveChanged = true;
            qCInfo(wifiWPAAdapter, "Open WIFI [ Success ].");
        } else {
            qCCritical(wifiWPAAdapter, "Open WIFI [ Failed ].\n%s",
                       qPrintable(app_wpa->errorString()));
        }

        Q_EMIT q_func()->isOpenChanged();
    } else {
        qCInfo(wifiWPAAdapter, "Open WIFI [ Running ].");
    }
    qCInfo(wifiWPAAdapter, "Open WIFI [ End ].");
}

void WifiWPAAdapterPrivate::close()
{
    qCInfo(wifiWPAAdapter, "Close WIFI [ Start ].");
    if(app_wpa == NULL) {
        qCInfo(wifiWPAAdapter, "Close WIFI [ NULL ].");
        qCInfo(wifiWPAAdapter, "Close WIFI [ End ].");
        return;
    }
    if(app_wpa->state() != QProcess::NotRunning) {
        this->disconnect();
        timer->stop();
        signalMeterTimer->stop();
        if (monitor_conn) {
            msgNotifier->setEnabled(false);
            msgNotifier->deleteLater();
            msgNotifier = NULL;
            wpa_ctrl_detach(monitor_conn);
            wpa_ctrl_close(monitor_conn);
            monitor_conn = NULL;
        }
        if (ctrl_conn) {
            wpa_ctrl_close(ctrl_conn);
            ctrl_conn = NULL;
        }

        qDeleteAll(m_accessPoints);
        m_accessPoints.clear();
        Q_EMIT q_func()->accessPointsChanged();

        qDeleteAll(m_p2pDevcies);
        m_p2pDevcies.clear();
        Q_EMIT q_func()->p2pDeviceCleared();

        //        // TODO: Release DHCP, 比较耗时
        //        if (wpa_cli_connected) {
        //            wpa_cli_connected = 0;
        //            // Release DHCP
        //            wpa_cli_exec(WPAActionDHCPClient.constData(),
        //                         qPrintable(m_interface),
        //                         "DISCONNECTED");
        //        }

        app_wpa->kill();
        bool success = app_wpa->waitForFinished(5000);
        if(success) {
            qCInfo(wifiWPAAdapter, "Close WIFI [ Success ].");
        } else {
            qCCritical(wifiWPAAdapter, "Close WIFI [ Failed ].\n%s",
                       qPrintable(app_wpa->errorString()));
        }
        Q_EMIT q_func()->isOpenChanged();
    } else {
        qCInfo(wifiWPAAdapter, "Close WIFI [ NotRunning ].");
    }
    qCInfo(wifiWPAAdapter, "Close WIFI [ End ].");
}

bool WifiWPAAdapterPrivate::openWPAConnection(const QString &iface)
{
    QString ifile = WPACtrlIfaceDir + "/" + iface;

    if(ctrl_conn && m_interface == iface) {
        return true;
    }

    m_interface = iface;

    if (ctrl_conn) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
    }

    if (monitor_conn) {
        msgNotifier->setEnabled(false);
        msgNotifier->deleteLater();
        msgNotifier = NULL;
        wpa_ctrl_detach(monitor_conn);
        wpa_ctrl_close(monitor_conn);
        monitor_conn = NULL;
    }

    qCInfo(wifiWPAAdapter, "Open Connection '%s'.[ Start ]",
           qUtf8Printable(iface));

    ctrl_conn = wpa_ctrl_open(qUtf8Printable(ifile));
    if (ctrl_conn == NULL) {
        qCCritical(wifiWPAAdapter, "Open Connection '%s'.[ Failed ]",
                   qUtf8Printable(iface));
        return false;
    }
    qCInfo(wifiWPAAdapter, "Open Connection '%s'.[ End ]",
           qUtf8Printable(iface));

    qCInfo(wifiWPAAdapter, "Open Monitor '%s'.[ Start ]",
           qUtf8Printable(iface));
    monitor_conn = wpa_ctrl_open(qUtf8Printable(ifile));
    if (monitor_conn == NULL) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
        qCCritical(wifiWPAAdapter, "Open Monitor '%s'.[ Failed ]",
                   qUtf8Printable(iface));
        return false;
    }
    qCInfo(wifiWPAAdapter,  "Open Monitor '%s'.[ End ]",
           qUtf8Printable(iface));

    qCInfo(wifiWPAAdapter, "Attach '%s' to wpa_supplicant.[ Start ]",
           qUtf8Printable(iface));
    if (wpa_ctrl_attach(monitor_conn)) {
        qCCritical(wifiWPAAdapter, "Attach '%s' to wpa_supplicant.[ Failed ]",
                   qUtf8Printable(iface));
        wpa_ctrl_close(monitor_conn);
        monitor_conn = NULL;
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
        return false;
    }
    qCInfo(wifiWPAAdapter, "Attach '%s' to wpa_supplicant.[ End ]",
           qUtf8Printable(iface));

#if defined(CONFIG_CTRL_IFACE_UNIX) || defined(CONFIG_CTRL_IFACE_UDP)
    msgNotifier = new QSocketNotifier(wpa_ctrl_get_fd(monitor_conn),
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
    qCInfo(wifiWPAAdapter, "Saved configuration.[ Start ]");
    ctrlRequest("SAVE_CONFIG", buf, &len);
    buf[len] = '\0';
    if (QString(buf) == QLatin1String("FAIL"))
        qCCritical(wifiWPAAdapter,  "Saved configuration.[ Failed ]\n%s",
                   "The configuration could not be saved.\n"
                   "The update_config=1 configuration option "
                   "must be used for configuration saving to "
                   "be permitted.");
    else
        qCInfo(wifiWPAAdapter, "Saved configuration.[ End ]\n%s",
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
        qCCritical(wifiWPAAdapter, "PING [ Failed ]");
        QString interface = QString::fromLocal8Bit(WPAInterface);
        if (openWPAConnection(interface)) {
            pingsToStatusUpdate = 0;
        }
    } else {
        qCDebug(wifiWPAAdapter, "PING [ Success ]");
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

    if (ctrl_conn == NULL) {
        return;
    }

    ctrlRequest("SCAN", reply, &reply_len);
}

void WifiWPAAdapterPrivate::updateScanResults()
{
    char reply[2048];
    char decode[2048];
    size_t reply_len;
    int index;
    char cmd[20];

    qDeleteAll(m_accessPoints);
    m_accessPoints.clear();

    index = 0;

    QString printable;
    QTextStream text(&printable);
    qCDebug(wifiWPAAdapter, "GET_SCAN_RESULTS [ Start ].");
    text << qSetFieldWidth(20) << left << QStringLiteral("BSSID")
         << qSetFieldWidth(8) << left << QStringLiteral("Freq")
         << qSetFieldWidth(8) << left << QStringLiteral("Signal")
         << qSetFieldWidth(20) << left << QStringLiteral("Security")
         << qSetFieldWidth(20) << left << QStringLiteral("SSID")
         << qSetFieldWidth(1) << endl;

    for(index = 0; index < 1000; ++index) {
        snprintf(cmd, sizeof(cmd), "BSS %d", index);

        reply_len = sizeof(reply) - 1;
        if (ctrlRequest(cmd, reply, &reply_len) < 0) {
            qCCritical(wifiWPAAdapter, "GET_SCAN_RESULTS [ Failed ].");
            break;
        }
        reply[reply_len] = '\0';

        printf_decode((u8 *)decode, sizeof(decode), reply);
        QString bss = QString(decode);
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


        WifiAccessPoint *point = new WifiAccessPoint(bssid);
        point->setSsid(ssid);
        point->setFrequency(freq.toInt());
        point->setStrength(signal.toInt());
        point->setSecuritys(auths);
        point->setEncrytions(encrs);

        m_accessPoints.append(point);

        text << qSetFieldWidth(20) << left << bssid
             << qSetFieldWidth(8) << left << freq
             << qSetFieldWidth(8) << left << signal
             << qSetFieldWidth(20) << left << Wifi::toString(auths)
             << qSetFieldWidth(20) << left << ssid
             << qSetFieldWidth(1) << endl;
    }

    Q_EMIT q_func()->accessPointsChanged();
}

void WifiWPAAdapterPrivate::triggerUpdate()
{
    updateStatus();
    networkMayHaveChanged = true;
    updateNetworks();
}

void WifiWPAAdapterPrivate::p2p_start()
{
    char reply[20];
    size_t reply_len;
    reply_len = sizeof(reply) - 1;
    qDeleteAll(m_p2pDevcies);
    m_p2pDevcies.clear();
    Q_EMIT q_func()->p2pDeviceCleared();
    qCInfo(wifiWPAP2P, "P2P_FIND [ Start ]");
    if (this->ctrlRequest("P2P_FIND", reply, &reply_len) < 0 ||
        memcmp(reply, "FAIL", 4) == 0) {
        qCCritical(wifiWPAP2P, "P2P_FIND [ Failed ]\n%s",
                   reply);
    }
    qCInfo(wifiWPAP2P, "P2P_FIND [ End ]");
}

void WifiWPAAdapterPrivate::p2p_stop()
{
    char reply[20];
    size_t reply_len;
    reply_len = sizeof(reply) - 1;
    qCInfo(wifiWPAP2P, "P2P_STOP_FIND [ Start ]");
    this->ctrlRequest("P2P_STOP_FIND", reply, &reply_len);
    qCInfo(wifiWPAP2P, "P2P_STOP_FIND [ End ]");
    qDeleteAll(m_p2pDevcies);
    m_p2pDevcies.clear();
    Q_EMIT q_func()->p2pDeviceCleared();
}

void WifiWPAAdapterPrivate::p2p_connectPBC(const QString &address)
{
    char cmd[100];
    char reply[100];
    size_t reply_len;

    snprintf(cmd, sizeof(cmd), "P2P_CONNECT %s pbc",
             address.toLocal8Bit().constData());

    reply_len = sizeof(reply) - 1;
    qCInfo(wifiWPAP2P, "P2P_CONNECT %s pbc [ Start ]",
           qUtf8Printable(address));
    if (this->ctrlRequest(cmd, reply, &reply_len) < 0) {
        qCCritical(wifiWPAP2P, "P2P_CONNECT %s pbc [ Failed ].\n%s",
                   qUtf8Printable(address),
                   reply);
    }
    qCInfo(wifiWPAP2P, "P2P_CONNECT %s pbc [ End ]",
           qUtf8Printable(address));
}

int WifiWPAAdapterPrivate::addNetwork(const QString &ssid,
                                      const QString &password)
{
    char reply[10], cmd[256];
    size_t reply_len;
    int id = -1, edit_network_id = 0;
    bool new_network = true;

    WifiAccessPoint *ap = getAccessPointBySSID(ssid);

    if(ap == NULL) {
        qCCritical(wifiWPAAdapter,
                   "Failed to add network to wpa_supplicant configuration.\n"
                   "The AP '%s' has not been found.",
                   qUtf8Printable(ssid));
        return id;
    }

    WifiNetwork *net = getNetworkBySSID(ssid);
    if(net) {
        edit_network_id = net->id();
        new_network = false;
    }

    memset(reply, 0, sizeof(reply));
    reply_len = sizeof(reply) - 1;

    if (new_network) {
        ctrlRequest("ADD_NETWORK", reply, &reply_len);
        if (reply[0] == 'F') {
            qCCritical(wifiWPAAdapter,
                       "Failed to add network to wpa_supplicant configuration.\n%s",
                       reply);
            return id;
        }
        id = QString(reply).toInt();
        qCInfo(wifiWPAAdapter,
               "ADD_NETWORK [ Start ]\n%d %s", id, qUtf8Printable(ssid));
    } else {
        id = edit_network_id;
        qCInfo(wifiWPAAdapter,
               "EDIT_NETWORK [ Start ]\n%d %s", id, qUtf8Printable(ssid));
    }

    setNetworkParam(id, "ssid", qUtf8Printable(ssid), true);

    Wifi::Securitys auth = ap->securitys();
    if(auth.testFlag(Wifi::NoneWEPShared)) {
        setNetworkParam(id, "auth_alg", "SHARED", false);
    } else {
        setNetworkParam(id, "auth_alg", "OPEN", false);
    }

    const char *key_mgmt = NULL, *proto = NULL, *pairwise = NULL;
    if(auth.testFlag(Wifi::NoneOpen) || auth.testFlag(Wifi::NoneWEP) ||
       auth.testFlag(Wifi::NoneWEPShared)) {
        key_mgmt = "NONE";
    }
    if(auth.testFlag(Wifi::IEEE8021X)) {
        key_mgmt = "IEEE8021X";
    }
    if(auth.testFlag(Wifi::WPA_PSK)) {
        key_mgmt = "WPA-PSK";
        proto = "WPA";
    }
    if(auth.testFlag(Wifi::WPA_EAP)) {
        key_mgmt = "WPA-EAP";
        proto = "WPA";
    }
    if(auth.testFlag(Wifi::WPA2_PSK)) {
        key_mgmt = "WPA-PSK";
        proto = "WPA2";
    }
    if(auth.testFlag(Wifi::WPA2_EAP)) {
        key_mgmt = "WPA-EAP";
        proto = "WPA2";
    }

    if (auth.testFlag(Wifi::WPA_PSK) || auth.testFlag(Wifi::WPA_EAP) ||
        auth.testFlag(Wifi::WPA2_PSK) || auth.testFlag(Wifi::WPA2_EAP)) {
        int encr = (auth.testFlag(Wifi::WPA_PSK) ||
                    auth.testFlag(Wifi::WPA_EAP)) ? 0 : 1;
        if (encr == 0) {
            pairwise = "TKIP";
        } else {
            pairwise = "CCMP";
        }
    }

    if (proto) {
        setNetworkParam(id, "proto", proto, false);
    }
    if (key_mgmt) {
        setNetworkParam(id, "key_mgmt", key_mgmt, false);
    }
    if (pairwise) {
        setNetworkParam(id, "pairwise", pairwise, false);
        setNetworkParam(id, "group", "TKIP CCMP WEP104 WEP40", false);
    }

    if(auth.testFlag(Wifi::WPA_PSK) || auth.testFlag(Wifi::WPA2_PSK)) {
        setNetworkParam(id, "psk", qUtf8Printable(password), true);
    } else if(auth.testFlag(Wifi::WPA_EAP) || auth.testFlag(Wifi::WPA2_EAP)) {
        const char *eap = "MD5";
        setNetworkParam(id, "eap", eap, false);
        if (strcmp(eap, "SIM") == 0 || strcmp(eap, "AKA") == 0) {
            setNetworkParam(id, "pcsc", "", true);
        } else {
            setNetworkParam(id, "pcsc", "NULL", false);
        }

        setNetworkParam(id, "identity", "NULL", false);
        setNetworkParam(id, "ca_cert", "NULL", false);

        if(password == "") {
            setNetworkParam(id, "password", "NULL", false);
        } else {
            setNetworkParam(id, "password", qUtf8Printable(password), true);
        }
    }

    setNetworkParam(id, "phase2", "NULL", false);
    setNetworkParam(id, "id_str", "NULL", false);


    snprintf(cmd, sizeof(cmd), "ENABLE_NETWORK %d", id);
    reply_len = sizeof(reply);
    ctrlRequest(cmd, reply, &reply_len);
    if (strncmp(reply, "OK", 2) != 0) {
        qCCritical(wifiWPAAdapter,
                   "Failed to enable network in wpa_supplicant configuration.\n%s",
                   reply);
        /* Network was added, so continue anyway */
    }

    triggerUpdate();
    ctrlRequest("SAVE_CONFIG", reply, &reply_len);

    if (new_network) {
        qCInfo(wifiWPAAdapter,
               "ADD_NETWORK [ End ]\n%d %s", id, qUtf8Printable(ssid));
    } else {
        qCInfo(wifiWPAAdapter,
               "EDIT_NETWORK [ End ]\n%d %s", id, qUtf8Printable(ssid));
    }

    return id;
}

void WifiWPAAdapterPrivate::selectNetwork(const QString &ssid)
{
    WifiAccessPoint *ap = getAccessPointBySSID(ssid);

    if(ap == NULL) {
        qCCritical(wifiWPAAdapter,
                   "Failed to select network.\n"
                   "The AP '%s' has not been found.",
                   qUtf8Printable(ssid));
        return;
    }

    WifiNetwork *net = getNetworkBySSID(ssid);
    if(net == NULL) {
        qCCritical(wifiWPAAdapter,
                   "Failed to select network.\n"
                   "The Network '%s' has not been found.",
                   qUtf8Printable(ssid));
        return;
    }

    qCInfo(wifiWPAAdapter,
           "SELECT_NETWORK [ Start ]\n%s", qUtf8Printable(ssid));
    selectNetwork(net->id());
    qCInfo(wifiWPAAdapter,
           "SELECT_NETWORK [ End ]\n%s", qUtf8Printable(ssid));
}

void WifiWPAAdapterPrivate::selectNetwork(int id)
{

    char reply[10];
    size_t reply_len = sizeof(reply);

    WifiNetwork *net = getNetworkById(id);
    if(net == NULL) {
        qCCritical(wifiWPAAdapter,
                   "Failed to select network.\n"
                   "The Network Id '%d' has not been found.",
                   id);
        return;
    }
    QString ssid = net->ssid();

    qCInfo(wifiWPAAdapter,
           "SELECT_NETWORK [ Start ]\n%d %s", id, qUtf8Printable(ssid));

    QString cmd = QString::number(id);
    cmd.prepend("SELECT_NETWORK ");
    ctrlRequest(cmd.toLocal8Bit().constData(), reply, &reply_len);
    triggerUpdate();
    //  stopWpsRun(false);

    qCInfo(wifiWPAAdapter,
           "SELECT_NETWORK [ End ]\n%d %s", id, qUtf8Printable(ssid));
}

void WifiWPAAdapterPrivate::removeNetwork(const QString &ssid)
{
    WifiAccessPoint *ap = getAccessPointBySSID(ssid);

    if(ap == NULL) {
        qCCritical(wifiWPAAdapter,
                   "Failed to remove network from wpa_supplicant configuration.\n"
                   "The AP '%s' has not been found.",
                   qUtf8Printable(ssid));
        return;
    }

    WifiNetwork *net = getNetworkBySSID(ssid);
    if(net == NULL) {
        qCCritical(wifiWPAAdapter,
                   "Failed to remove network from wpa_supplicant configuration.\n"
                   "The Network '%s' has not been found.",
                   qUtf8Printable(ssid));
        return;
    }

    qCInfo(wifiWPAAdapter,
           "REMOVE_NETWORK [ Start ]\n%s", qUtf8Printable(ssid));
    removeNetwork(net->id());
    qCInfo(wifiWPAAdapter,
           "REMOVE_NETWORK [ End ]\n%s", qUtf8Printable(ssid));
}

void WifiWPAAdapterPrivate::removeNetwork(int id)
{
    char reply[10], cmd[256];
    size_t reply_len;

    WifiNetwork *net = getNetworkById(id);
    if(net == NULL) {
        qCCritical(wifiWPAAdapter,
                   "Failed to remove network from wpa_supplicant configuration.\n"
                   "The Network Id '%d' has not been found.",
                   id);
        return;
    }
    QString ssid = net->ssid();

    qCInfo(wifiWPAAdapter,
           "REMOVE_NETWORK [ Start ]\n%d %s", id, qUtf8Printable(ssid));

    snprintf(cmd, sizeof(cmd), "REMOVE_NETWORK %d", id);
    reply_len = sizeof(reply);
    this->ctrlRequest(cmd, reply, &reply_len);
    if (strncmp(reply, "OK", 2) != 0) {
        qCCritical(wifiWPAAdapter,
                   "Failed to remove network from wpa_supplicant configuration.\n%s",
                   reply);
    } else {
        this->triggerUpdate();
        this->ctrlRequest("SAVE_CONFIG", reply, &reply_len);
    }

    qCInfo(wifiWPAAdapter,
           "REMOVE_NETWORK [ End ]\n%d %s", id, qUtf8Printable(ssid));
}

WifiWPAAdapter::WifiWPAAdapter(QObject *parent)
    : QObject(*(new WifiWPAAdapterPrivate), parent)
{
    Q_D(WifiWPAAdapter);

    d->timer = new QTimer(this);
    QObjectPrivate::connect(d->timer, &QTimer::timeout, d,
                            &WifiWPAAdapterPrivate::ping);
    d->timer->setSingleShot(false);

    d->signalMeterTimer = new QTimer(this);
    d->signalMeterTimer->setInterval(d->signalMeterInterval);
    QObjectPrivate::connect(d->signalMeterTimer, &QTimer::timeout, d,
                            &WifiWPAAdapterPrivate::signalMeterUpdate);
}

WifiWPAAdapter::~WifiWPAAdapter()
{
}
void WifiWPAAdapter::open()
{
    Q_D(WifiWPAAdapter);
    d->open();
}
void WifiWPAAdapter::close()
{
    Q_D(WifiWPAAdapter);
    d->close();
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
    Q_D(WifiWPAAdapter);
    d->saveConfig();
}

void WifiWPAAdapter::scan()
{
    Q_D(WifiWPAAdapter);
    d->scanRequest();
}

void WifiWPAAdapter::p2p_start()
{
    Q_D(WifiWPAAdapter);
    d->p2p_start();
}
void WifiWPAAdapter::p2p_stop()
{
    Q_D(WifiWPAAdapter);
    d->p2p_stop();
}

void WifiWPAAdapter::p2p_connectPBC(const QString &address)
{
    Q_D(WifiWPAAdapter);
    d->p2p_connectPBC(address);
}

int WifiWPAAdapter::addNetwork(const QString &ssid, const QString &password)
{
    Q_D(WifiWPAAdapter);
    return d->addNetwork(ssid, password);
}

void WifiWPAAdapter::selectNetwork(const QString &ssid)
{
    Q_D(WifiWPAAdapter);
    d->selectNetwork(ssid);
}

void WifiWPAAdapter::selectNetwork(int id)
{
    Q_D(WifiWPAAdapter);
    d->selectNetwork(id);
}

void WifiWPAAdapter::removeNetwork(int id)
{
    Q_D(WifiWPAAdapter);
    d->removeNetwork(id);
}

bool WifiWPAAdapter::isOpen() const
{
    Q_D(const WifiWPAAdapter);
    return d->app_wpa != NULL && d->app_wpa->state() == QProcess::Running;
}

// 已连接WIFI的SSID
QString WifiWPAAdapter::ssid() const
{
    Q_D(const WifiWPAAdapter);
    return d->m_ssid;
}
// 已连接WIFI的SSID
QString WifiWPAAdapter::bssid() const
{
    Q_D(const WifiWPAAdapter);
    return d->m_bssid;
}
// 已连接WIFI的SSID
QString WifiWPAAdapter::ipAddress() const
{
    Q_D(const WifiWPAAdapter);
    return d->m_ipAddress;
}
// 已连接WIFI的状态
QString WifiWPAAdapter::state()
{
    Q_D(const WifiWPAAdapter);
    return d->m_state;
}
// 已连接WIFI的安全认证
QString WifiWPAAdapter::security()
{
    Q_D(const WifiWPAAdapter);
    return d->m_security;
}
// 已连接WIFI的信号强度
int WifiWPAAdapter::rssiValue()
{
    Q_D(WifiWPAAdapter);
    return d->m_rssiValue;
}

// 获取当前WiFi接入点
QList<WifiAccessPoint *> WifiWPAAdapter::accessPoints()
{
    Q_D(WifiWPAAdapter);
    return d->m_accessPoints;
}

// 获取当前WiFi网络列表
QList<WifiNetwork *> WifiWPAAdapter::networks()
{
    Q_D(WifiWPAAdapter);
    return d->m_networks;
}

// 获取当前P2P列表
QList<WifiP2PDevice *> WifiWPAAdapter::p2pDevcies()
{
    Q_D(WifiWPAAdapter);
    return d->m_p2pDevcies;
}
