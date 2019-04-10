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

#include "wifi.h"

QString Wifi::toString(Securitys auths)
{
    QString str;
    if(auths.testFlag(NoneWEP)) {
        str.append(QLatin1String("WEP/"));
    }
    if(auths.testFlag(NoneWEPShared)) {
        str.append(QLatin1String("WEP Shared/"));
    }
    if(auths.testFlag(IEEE8021X)) {
        str.append(QLatin1String("IEEE 802.1X/"));
    }
    if(auths.testFlag(WPA_PSK)) {
        str.append(QLatin1String("WPA-PSK/"));
    }
    if(auths.testFlag(WPA_EAP)) {
        str.append(QLatin1String("WPA-EAP/"));
    }
    if(auths.testFlag(WPA2_PSK)) {
        str.append(QLatin1String("WPA2-PSK/"));
    }
    if(auths.testFlag(WPA2_EAP)) {
        str.append(QLatin1String("WPA2-EAP/"));
    }
    if(str.isEmpty()) {
        str.append(QLatin1String("None"));
    } else {
        str.chop(1);
    }
    return str;
}

QString Wifi::toString(Encrytions encrs)
{
    QString str;
    if(encrs.testFlag(WEP)) {
        str.append(QLatin1String("WEP+"));
    }
    if(encrs.testFlag(TKIP)) {
        str.append(QLatin1String("TKIP+"));
    }
    if(encrs.testFlag(CCMP)) {
        str.append(QLatin1String("CCMP+"));
    }
    if(str.isEmpty()) {
        str.append(QLatin1String("None"));
    } else {
        str.chop(1);
    }
    return str;
}
