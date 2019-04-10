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

#include "wifiaccesspoint.h"

WifiAccessPoint::WifiAccessPoint(const QString &bid,
                                 QObject *parent)
    : QObject(parent)
    , m_bssid(bid)
{
}

QString WifiAccessPoint::bssid() const
{
    return m_bssid;
}

QString WifiAccessPoint::ssid() const
{
    return m_ssid;
}
void WifiAccessPoint::setSsid(const QString &id)
{
    if(id != m_ssid) {
        m_ssid = id;
        emit ssidChanged();
    }
}

int WifiAccessPoint::frequency()
{
    return m_freq;
}
void WifiAccessPoint::setFrequency(int freq)
{
    if(freq != m_freq) {
        m_freq = freq;
        emit frequencyChanged();
    }
}

int WifiAccessPoint::strength()
{
    return m_strength;
}
void WifiAccessPoint::setStrength(int level)
{
    if(level != m_strength) {
        m_strength = level;
        emit strengthChanged();
    }
}

Wifi::Securitys WifiAccessPoint::securitys()
{
    return m_securitys;
}
void WifiAccessPoint::setSecuritys(Wifi::Securitys auths)
{
    if(auths != m_securitys) {
        m_securitys = auths;
        emit securitysChanged();
    }
}

Wifi::Encrytions WifiAccessPoint::encrytions()
{
    return m_encrytions;
}
void WifiAccessPoint::setEncrytions(Wifi::Encrytions ancrs)
{
    if(ancrs != m_encrytions) {
        m_encrytions = ancrs;
        emit encrytionsChanged();
    }
}
