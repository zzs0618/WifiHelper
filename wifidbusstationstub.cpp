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

    QStringList compareAccessPoint(const QVariantMap &a, const QVariantMap &b);

    void onWPAIsOpenChanged();
    void onWPAStatusChanged();
    void onWPAAccessPointsChanged();
    void onWPANetworksChanged();

public:
    WifiWPAAdapter *m_wpa;
    QHash<QString, QVariantMap> m_WifiPoints;
};

WifiDbusStationStubPrivate::WifiDbusStationStubPrivate()
    : QObjectPrivate()
{

}

WifiDbusStationStubPrivate::~WifiDbusStationStubPrivate()
{

}

QStringList WifiDbusStationStubPrivate::compareAccessPoint(const QVariantMap &a,
        const QVariantMap &b)
{
    QStringList list;
    for(const QString &key : b.keys()) {
        if(a[key] != b[key]) {
            list << key;
        }
    }
    return list;
}

void WifiDbusStationStubPrivate::onWPAIsOpenChanged()
{
    bool isOpen = q_func()->isOpen();
    Q_EMIT q_func()->IsOpenChanged(isOpen);
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

    qCDebug(wifiDbus, "[ SIGNAL ] Notify WiFi status to WiFiClient.\n%s",
            qUtf8Printable(doc.toJson()));

    Q_EMIT q_func()->StatusChanged(doc.toJson(QJsonDocument::Compact));
}

void WifiDbusStationStubPrivate::onWPAAccessPointsChanged()
{
    QHash<QString, QVariantMap> wifiPoints;
    for(WifiAccessPoint *ap : m_wpa->accessPoints()) {
        if(!wifiPoints.contains(ap->ssid())) {
            QVariantMap point;
            point.insert(QLatin1String("ssid"), ap->ssid());
            point.insert(QLatin1String("bssid"), ap->bssid());
            point.insert(QLatin1String("frequency"), ap->frequency());
            point.insert(QLatin1String("rssi"), ap->strength());
            point.insert(QLatin1String("securitys"), static_cast<int>(ap->securitys()));
            point.insert(QLatin1String("encrytions"), static_cast<int>(ap->encrytions()));
            wifiPoints.insert(ap->ssid(), point);
        }
    }
    QSet<QString> delKeys = m_WifiPoints.keys().toSet() - wifiPoints.keys().toSet();
    QSet<QString> newKeys = wifiPoints.keys().toSet() - m_WifiPoints.keys().toSet();
    QSet<QString> ediKeys = m_WifiPoints.keys().toSet().intersect(
                                            wifiPoints.keys().toSet());

    QVariantList removeList;
    for(const QString &key : delKeys) {
        m_WifiPoints.remove(key);
        QVariantMap point;
        point.insert(QLatin1String("ssid"), key);
        removeList << point;
    }
    if(!removeList.isEmpty()) {
        QJsonDocument doc = QJsonDocument::fromVariant(removeList);
        qCDebug(wifiDbus, "[ SIGNAL ] Removed WiFi AP List to WiFiClient .\n%s",
                qUtf8Printable(doc.toJson()));

        Q_EMIT q_func()->AccessPointRemoved(doc.toJson(QJsonDocument::Compact));
    }

    QVariantList addList;
    for(const QString &key : newKeys) {
        m_WifiPoints[key] = wifiPoints[key];
        m_WifiPoints[key][QLatin1String("type")] = 0;
        addList << m_WifiPoints[key];
    }
    if(!addList.isEmpty()) {
        QJsonDocument doc = QJsonDocument::fromVariant(addList);
        qCDebug(wifiDbus, "[ SIGNAL ] Added WiFi AP List to WiFiClient.\n%s",
                qUtf8Printable(doc.toJson()));

        Q_EMIT q_func()->AccessPointAdded(doc.toJson(QJsonDocument::Compact));
    }

    QVariantList editList;
    for(const QString &key : ediKeys) {
        QStringList diffs = compareAccessPoint(m_WifiPoints[key], wifiPoints[key]);
        if(!diffs.isEmpty()) {
            for(const QString &col : diffs) {
                m_WifiPoints[key][col] = wifiPoints[key][col];
            }
            editList << m_WifiPoints[key];
        }
    }
    if(!editList.isEmpty()) {
        QJsonDocument doc = QJsonDocument::fromVariant(editList);
        qCDebug(wifiDbus, "[ SIGNAL ] Updated WiFi AP List to WiFiClient.\n%s",
                qUtf8Printable(doc.toJson()));

        Q_EMIT q_func()->AccessPointUpdated(doc.toJson(QJsonDocument::Compact));
    }
}


void WifiDbusStationStubPrivate::onWPANetworksChanged()
{
    QVariantList editList;

    for(WifiNetwork *net : m_wpa->networks()) {
        QString key = net->ssid();
        if(m_WifiPoints.contains(key)) {
            QVariantMap point;
            point.insert(QLatin1String("id"), net->id());
            point.insert(QLatin1String("ssid"), net->ssid());
            point.insert(QLatin1String("bssid"), net->bssid());
            point.insert(QLatin1String("security"), static_cast<int>(net->security()));
            point.insert(QLatin1String("encrytion"), static_cast<int>(net->encrytion()));

            int type = (m_wpa->ssid() == net->ssid()) ? 2 : 1;
            point.insert(QLatin1String("type"), type);

            QStringList diffs = compareAccessPoint(m_WifiPoints[key], point);
            if(!diffs.isEmpty()) {
                for(const QString &col : diffs) {
                    m_WifiPoints[key][col] = point[col];
                }
                editList << m_WifiPoints[key];
            }
        }
    }
    if(!editList.isEmpty()) {
        QJsonDocument doc = QJsonDocument::fromVariant(editList);
        qCDebug(wifiDbus, "[ SIGNAL ] Updated WiFi Net List to WiFiClient.\n%s",
                qUtf8Printable(doc.toJson()));

        Q_EMIT q_func()->AccessPointUpdated(doc.toJson(QJsonDocument::Compact));
    }
}

WifiDbusStationStub::WifiDbusStationStub(WifiWPAAdapter *wpa, QObject *parent)
    : QObject(*(new WifiDbusStationStubPrivate), parent)
{
    Q_D(WifiDbusStationStub);
    d->m_wpa = wpa;
    QObjectPrivate::connect(d->m_wpa, &WifiWPAAdapter::isOpenChanged, d,
                            &WifiDbusStationStubPrivate::onWPAIsOpenChanged);
    QObjectPrivate::connect(d->m_wpa, &WifiWPAAdapter::statusChanged, d,
                            &WifiDbusStationStubPrivate::onWPAStatusChanged);
    QObjectPrivate::connect(d->m_wpa, &WifiWPAAdapter::accessPointsChanged, d,
                            &WifiDbusStationStubPrivate::onWPAAccessPointsChanged);
    QObjectPrivate::connect(d->m_wpa, &WifiWPAAdapter::networksChanged, d,
                            &WifiDbusStationStubPrivate::onWPANetworksChanged);
}

bool WifiDbusStationStub::isOpen() const
{
    Q_D(const WifiDbusStationStub);
    if(d->m_wpa) {
        return d->m_wpa->isOpen();
    }
    return false;
}

QString WifiDbusStationStub::accessPoints() const
{
    Q_D(const WifiDbusStationStub);

    QVariantList addList;
    for(const QString &key : d->m_WifiPoints.keys()) {
        addList << d->m_WifiPoints[key];
    }
    QJsonDocument doc = QJsonDocument::fromVariant(addList);
    return doc.toJson(QJsonDocument::Compact);
}

QString WifiDbusStationStub::status() const
{
    Q_D(const WifiDbusStationStub);
    QVariantMap station;
    station.insert(QLatin1String("ssid"), d->m_wpa->ssid());
    station.insert(QLatin1String("bssid"), d->m_wpa->bssid());
    station.insert(QLatin1String("ipAddress"), d->m_wpa->ipAddress());
    station.insert(QLatin1String("state"), d->m_wpa->state());
    station.insert(QLatin1String("security"), d->m_wpa->security());
    station.insert(QLatin1String("rssi"), d->m_wpa->rssiValue());

    QJsonDocument doc = QJsonDocument::fromVariant(station);
    return doc.toJson(QJsonDocument::Compact);
}

void WifiDbusStationStub::Open()
{
    Q_D(WifiDbusStationStub);
    qCDebug(wifiDbus, "[ METHOD ] Open WiFi. [ Start ]");
    if(d->m_wpa) {
        d->m_wpa->open();
    }
    qCDebug(wifiDbus, "[ METHOD ] Open WiFi. [ End ]");
}

void WifiDbusStationStub::Close()
{
    Q_D(WifiDbusStationStub);
    qCDebug(wifiDbus, "[ METHOD ] Close WiFi. [ Start ]");
    if(d->m_wpa) {
        d->m_wpa->close();
    }
    qCDebug(wifiDbus, "[ METHOD ] Close WiFi. [ End ]");
}

void WifiDbusStationStub::AddNetwork(const QString &ssid,
                                     const QString &password)
{
    Q_D(WifiDbusStationStub);
    qCDebug(wifiDbus, "[ METHOD ] Add WiFi Network. [ Start ]\n%s",
            qUtf8Printable(ssid));
    if(d->m_wpa) {
        int id = d->m_wpa->addNetwork(ssid, password);
        d->m_wpa->selectNetwork(id);
    }
    qCDebug(wifiDbus, "[ METHOD ] Add WiFi Network. [ End ]\n%s",
            qUtf8Printable(ssid));
}

void WifiDbusStationStub::RemoveNetwork(int id)
{
    Q_D(WifiDbusStationStub);
    qCDebug(wifiDbus, "[ METHOD ] Remove WiFi Network. [ Start ]\n%d", id);
    if(d->m_wpa) {
        d->m_wpa->removeNetwork(id);
    }
    qCDebug(wifiDbus, "[ METHOD ] Remove WiFi Network. [ End ]\n%d", id);
}

void WifiDbusStationStub::SelectNetwork(int id)
{
    Q_D(WifiDbusStationStub);
    qCDebug(wifiDbus, "[ METHOD ] Select WiFi Network. [ Start ]\n%d", id);
    if(d->m_wpa) {
        d->m_wpa->selectNetwork(id);
    }
    qCDebug(wifiDbus, "[ METHOD ] Select WiFi Network. [ End ]\n%d", id);
}
