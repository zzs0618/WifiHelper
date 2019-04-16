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

#ifndef WIFINETWORK_H
#define WIFINETWORK_H

#include "wifi.h"

class WifiNetwork : public QObject
{
    Q_OBJECT
    Q_PROPERTY(int id READ id CONSTANT)
    Q_PROPERTY(QString bssid READ bssid WRITE setBssid NOTIFY bssidChanged)
    Q_PROPERTY(QString ssid READ ssid WRITE setSsid NOTIFY ssidChanged)
    Q_PROPERTY(Wifi::Security security READ security WRITE setSecurity NOTIFY
               securityChanged)
    Q_PROPERTY(Wifi::Encrytion encrytion READ encrytion WRITE setEncrytion NOTIFY
               encrytionChanged)
    Q_PROPERTY(QString psk READ psk WRITE setPsk NOTIFY pskChanged)
    Q_PROPERTY(bool enabled READ enabled WRITE setEnabled NOTIFY enabledChanged)
    //    Q_PROPERTY(QString eapMethod READ eapMethod WRITE setEapMethod NOTIFY
    //               eapMethodChanged)
    //    Q_PROPERTY(QString identity READ identity WRITE setIdentity NOTIFY
    //               identityChanged)
    //    Q_PROPERTY(QString password READ password WRITE setPassword NOTIFY
    //               passwordChanged)
    //    Q_PROPERTY(QString caCertificate READ caCertificate WRITE setCaCertificate
    //               NOTIFY caCertificateChanged)
    //    Q_PROPERTY(QString wepKey0 READ wepKey0 WRITE setWepKey0 NOTIFY wepKey0Changed)
    //    Q_PROPERTY(QString wepKey1 READ wepKey1 WRITE setWepKey1 NOTIFY wepKey1Changed)
    //    Q_PROPERTY(QString wepKey2 READ wepKey2 WRITE setWepKey2 NOTIFY wepKey2Changed)
    //    Q_PROPERTY(QStirng wepKey3 READ wepKey3 WRITE setWepKey3 NOTIFY wepKey3Changed)
public:
    explicit WifiNetwork(int id, QObject *parent = nullptr);

    int id();

    QString bssid() const;
    void setBssid(const QString &id);

    QString ssid() const;
    void setSsid(const QString &id);

    Wifi::Security security();
    void setSecurity(Wifi::Security auth);

    Wifi::Encrytion encrytion();
    void setEncrytion(Wifi::Encrytion ancr);

    QString psk() const;
    void setPsk(const QString &key);

    bool enabled();
    void setEnabled(bool enable);

signals:
    void bssidChanged();
    void ssidChanged();
    void securityChanged();
    void encrytionChanged();
    void pskChanged();
    void enabledChanged();

private:
    int m_id;
    QString m_bssid;
    QString m_ssid;
    Wifi::Security m_security = Wifi::NoneOpen;
    Wifi::Encrytion m_encrytion = Wifi::None;
    QString m_psk;
    bool m_enabled = true;
};

#endif // WIFINETWORK_H
