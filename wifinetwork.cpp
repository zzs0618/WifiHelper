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

#include "wifinetwork.h"

WifiNetwork::WifiNetwork(const QString &bid, QObject *parent) : QObject(parent)
    , m_bssid(bid)
{

}

QString WifiNetwork::bssid() const
{
    return m_bssid;
}

QString WifiNetwork::ssid() const
{
    return m_ssid;
}
void WifiNetwork::setSsid(const QString &id)
{
    if(id != m_ssid) {
        m_ssid = id;
        emit ssidChanged();
    }
}

Wifi::Security WifiNetwork::security()
{
    return m_security;
}
void WifiNetwork::setSecurity(Wifi::Security auth)
{
    if(auth != m_security) {
        m_security = auth;
        emit securityChanged();
    }
}

Wifi::Encrytion WifiNetwork::encrytion()
{
    return m_encrytion;
}
void WifiNetwork::setEncrytion(Wifi::Encrytion ancr)
{
    if(ancr != m_encrytion) {
        m_encrytion = ancr;
        emit encrytionChanged();
    }
}

QString WifiNetwork::psk() const
{
    return m_psk;
}

void WifiNetwork::setPsk(const QString &key)
{
    if(key != m_psk) {
        m_psk = key;
        emit pskChanged();
    }
}

