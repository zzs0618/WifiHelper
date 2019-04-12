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

#include "wifidbusstationstub.h"

#include <private/qobject_p.h>
#include <QJsonDocument>
#include <QJsonObject>

// in one source file
Q_LOGGING_CATEGORY(wifiDbus, "wifi.helper.dbus.station")

class WifiDbusStationStubPrivate : public QObjectPrivate
{
    Q_DECLARE_PUBLIC(WifiDbusStationStub)
public:
    WifiDbusStationStubPrivate();
    ~WifiDbusStationStubPrivate();

    void onWPAStatusChanged();
    void onWPAAccessPointsChanged();

public:
    WifiWPAAdapter *m_wpa;
};

WifiDbusStationStubPrivate::WifiDbusStationStubPrivate()
    : QObjectPrivate()
{

}

WifiDbusStationStubPrivate::~WifiDbusStationStubPrivate()
{

}

void WifiDbusStationStubPrivate::onWPAStatusChanged()
{
    QVariantMap station;
    station.insert(QLatin1String("ssid"), m_wpa->ssid());
    station.insert(QLatin1String("bssid"), m_wpa->bssid());
    station.insert(QLatin1String("ipAddress"), m_wpa->ipAddress());
    station.insert(QLatin1String("state"), m_wpa->state());
    station.insert(QLatin1String("security"), m_wpa->security());
    station.insert(QLatin1String("rssi"), m_wpa->rssiValue());

    QJsonDocument doc = QJsonDocument::fromVariant(station);

    qCDebug(wifiDbus, "[ SIGNAL ] Notify WiFi status to client.\n%s",
            qUtf8Printable(doc.toJson()));

    Q_EMIT q_func()->StatusChanged(doc.toJson(QJsonDocument::Compact));
}

void WifiDbusStationStubPrivate::onWPAAccessPointsChanged()
{
    QVariantList list;
    for(WifiAccessPoint *ap : m_wpa->accessPoints()) {
        QVariantMap point;
        point.insert(QLatin1String("ssid"), ap->ssid());
        point.insert(QLatin1String("bssid"), ap->bssid());
        point.insert(QLatin1String("frequency"), ap->frequency());
        point.insert(QLatin1String("rssi"), ap->strength());
        point.insert(QLatin1String("securitys"), static_cast<int>(ap->securitys()));
        point.insert(QLatin1String("encrytions"), static_cast<int>(ap->encrytions()));
        list << point;
    }
    QJsonDocument doc = QJsonDocument::fromVariant(list);

    qCDebug(wifiDbus, "[ SIGNAL ] Notify WiFi AP List to client.\n%s",
            qUtf8Printable(doc.toJson()));

    Q_EMIT q_func()->AccessPointUpdate(doc.toJson(QJsonDocument::Compact));
}

WifiDbusStationStub::WifiDbusStationStub(WifiWPAAdapter *wpa, QObject *parent)
    : QObject(*(new WifiDbusStationStubPrivate), parent)
{
    Q_D(WifiDbusStationStub);
    d->m_wpa = wpa;
    QObjectPrivate::connect(d->m_wpa, &WifiWPAAdapter::statusChanged, d,
                            &WifiDbusStationStubPrivate::onWPAStatusChanged);
    QObjectPrivate::connect(d->m_wpa, &WifiWPAAdapter::accessPointsChanged, d,
                            &WifiDbusStationStubPrivate::onWPAAccessPointsChanged);
}

void WifiDbusStationStub::Connect()
{
    Q_D(WifiDbusStationStub);
    if(d->m_wpa) {
        d->m_wpa->connect();
    }
}

void WifiDbusStationStub::Disconnect()
{
    Q_D(WifiDbusStationStub);
    if(d->m_wpa) {
        d->m_wpa->disconnect();
    }
}

void WifiDbusStationStub::Save()
{
    Q_D(WifiDbusStationStub);
    if(d->m_wpa) {
        d->m_wpa->saveConfig();
    }
}

void WifiDbusStationStub::Scan()
{
    Q_D(WifiDbusStationStub);
    if(d->m_wpa) {
        d->m_wpa->scan();
    }
}

void WifiDbusStationStub::Select(const QString &iface)
{
    Q_D(WifiDbusStationStub);
    if(d->m_wpa) {
        d->m_wpa->selectInterface(iface);
    }
}
