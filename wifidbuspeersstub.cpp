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

#include "wifidbuspeersstub.h"

#include <private/qobject_p.h>
#include <QJsonDocument>
#include <QJsonObject>

// in one source file
Q_LOGGING_CATEGORY(wifiDbusPeers, "wifi.helper.dbus.peers")

class WifiDbusPeersStubPrivate : public QObjectPrivate
{
    Q_DECLARE_PUBLIC(WifiDbusPeersStub)
public:
    WifiDbusPeersStubPrivate();
    ~WifiDbusPeersStubPrivate();

    void onP2PDeviceFound(int index);

public:
    WifiWPAAdapter *m_wpa;
};

WifiDbusPeersStubPrivate::WifiDbusPeersStubPrivate()
    : QObjectPrivate()
{
}

WifiDbusPeersStubPrivate::~WifiDbusPeersStubPrivate()
{
}

void WifiDbusPeersStubPrivate::onP2PDeviceFound(int index)
{
    if(m_wpa) {
        WifiP2PDevice *p2p = m_wpa->p2pDevcies().value(index);
        if(p2p) {
            QVariantMap device;

            device.insert(QLatin1String("name"), p2p->name());
            device.insert(QLatin1String("address"), p2p->address());
            device.insert(QLatin1String("type"), p2p->type());

            QJsonDocument doc = QJsonDocument::fromVariant(device);

            qCDebug(wifiDbusPeers, "[ SIGNAL ] Notify P2P Device to WiFiClient.\n%s",
                    qUtf8Printable(doc.toJson()));

            Q_EMIT q_func()->DeviceFound(doc.toJson(QJsonDocument::Compact));
        }
    }
}

WifiDbusPeersStub::WifiDbusPeersStub(WifiWPAAdapter *wpa, QObject *parent)
    : QObject(*(new WifiDbusPeersStubPrivate), parent)
{
    Q_D(WifiDbusPeersStub);
    d->m_wpa = wpa;
    QObjectPrivate::connect(d->m_wpa, &WifiWPAAdapter::p2pDeviceFound, d,
                            &WifiDbusPeersStubPrivate::onP2PDeviceFound);
}

void WifiDbusPeersStub::Connect(const QString &param)
{
    Q_D(WifiDbusPeersStub);
    QJsonDocument doc = QJsonDocument::fromJson(param.toUtf8());
    QVariantMap paramMap = doc.toVariant().toMap();
    QString method = paramMap[QLatin1String("method")].toString();
    QString address = paramMap[QLatin1String("address")].toString();

    if(method.toLower() == "pbc" && d->m_wpa) {
        d->m_wpa->p2p_connectPBC(address);
    }
}

void WifiDbusPeersStub::Start()
{
    Q_D(WifiDbusPeersStub);
    if(d->m_wpa) {
        d->m_wpa->p2p_start();
    }
}

void WifiDbusPeersStub::Stop()
{
    Q_D(WifiDbusPeersStub);
    if(d->m_wpa) {
        d->m_wpa->p2p_stop();
    }
}
