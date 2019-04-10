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

#ifndef WIFI_H
#define WIFI_H

#include <QObject>

namespace Wifi
{
    enum Security {
        NoneOpen        = 0x00,
        NoneWEP         = 0x01,
        NoneWEPShared   = 0x02,
        IEEE8021X       = 0x04,
        WPA_PSK         = 0x08,
        WPA_EAP         = 0x10,
        WPA2_PSK        = 0x20,
        WPA2_EAP        = 0x40
    };
    Q_DECLARE_FLAGS(Securitys, Security)

    enum Encrytion {
        None    = 0x00,
        WEP     = 0x01,
        TKIP    = 0x02,
        CCMP    = 0x04
    };
    Q_DECLARE_FLAGS(Encrytions, Encrytion)

    QString toString(Securitys auths);
    QString toString(Encrytions encrs);
}

Q_DECLARE_METATYPE(Wifi::Security)
Q_DECLARE_METATYPE(Wifi::Securitys)
Q_DECLARE_METATYPE(Wifi::Encrytion)
Q_DECLARE_METATYPE(Wifi::Encrytions)

#endif // WIFI_H
