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

#ifndef WIFIDBUSSTATIONSTUB_H
#define WIFIDBUSSTATIONSTUB_H

#include <QObject>
#include <QLoggingCategory>
#include "wifiwpaadapter.h"

// in a header
Q_DECLARE_LOGGING_CATEGORY(wifiDbus)

class WifiDbusStationStubPrivate;
class WifiDbusStationStub : public QObject
{
    Q_OBJECT
public:
    explicit WifiDbusStationStub(WifiWPAAdapter *wpa, QObject *parent = nullptr);

public: // PROPERTIES
    Q_PROPERTY(QString AccessPoints READ accessPoints)
    QString accessPoints() const;

    Q_PROPERTY(bool IsOpen READ isOpen)
    bool isOpen() const;

    Q_PROPERTY(QString Status READ status)
    QString status() const;

public Q_SLOTS: // METHODS
    void AddNetwork(const QString &ssid, const QString &password);
    void Close();
    void Open();
    void RemoveNetwork(int id);
    void SelectNetwork(int id);
Q_SIGNALS: // SIGNALS
    void AccessPointAdded(const QString &point);
    void AccessPointRemoved(const QString &point);
    void AccessPointUpdated(const QString &point);
    void IsOpenChanged(bool isOpen);
    void StatusChanged(const QString &status);

private:
    Q_DECLARE_PRIVATE(WifiDbusStationStub)
};

#endif // WIFIDBUSSTATIONSTUB_H
