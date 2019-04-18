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

#ifndef WIFIP2PDEVICE_H
#define WIFIP2PDEVICE_H

#include <QObject>
#include "wifi.h"

class WifiP2PDevice : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString address READ address CONSTANT)
    Q_PROPERTY(QString name READ name CONSTANT)
    Q_PROPERTY(Wifi::DeviceType type READ type CONSTANT)
public:
    explicit WifiP2PDevice(const QString &n, const QString &a, Wifi::DeviceType t,
                           QObject *parent = nullptr);

    QString address() const;
    QString name() const;
    Wifi::DeviceType type();

private:
    QString m_address;
    QString m_name;
    Wifi::DeviceType m_type = Wifi::DeviceUnknown;
};

#endif // WIFIP2PDEVICE_H
