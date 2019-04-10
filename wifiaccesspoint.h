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

#ifndef WIFIACCESSPOINT_H
#define WIFIACCESSPOINT_H

#include "wifi.h"


class WifiAccessPoint : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString bssid READ bssid CONSTANT)
    Q_PROPERTY(QString ssid READ ssid WRITE setSsid NOTIFY ssidChanged)
    Q_PROPERTY(int frequency READ frequency WRITE setFrequency NOTIFY
               frequencyChanged)
    Q_PROPERTY(int strength READ strength WRITE setStrength NOTIFY strengthChanged)
    Q_PROPERTY(Wifi::Securitys securitys READ securitys WRITE setSecuritys NOTIFY
               securitysChanged)
    Q_PROPERTY(Wifi::Encrytions encrytions READ encrytions WRITE setEncrytions
               NOTIFY encrytionsChanged)
public:
    explicit WifiAccessPoint(const QString &bid, QObject *parent = nullptr);

    QString bssid() const;

    QString ssid() const;
    void setSsid(const QString &id);

    int frequency();
    void setFrequency(int freq);

    int strength();
    void setStrength(int level);

    Wifi::Securitys securitys();
    void setSecuritys(Wifi::Securitys auths);

    Wifi::Encrytions encrytions();
    void setEncrytions(Wifi::Encrytions ancrs);

signals:
    void ssidChanged();
    void frequencyChanged();
    void strengthChanged();
    void securitysChanged();
    void encrytionsChanged();

private:
    QString m_bssid;
    QString m_ssid;
    int m_freq = 0;
    int m_strength = -100;
    Wifi::Securitys m_securitys = Wifi::NoneOpen;
    Wifi::Encrytions m_encrytions = Wifi::None;
};

#endif // WIFIACCESSPOINT_H
