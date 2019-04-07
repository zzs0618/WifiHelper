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

#ifndef WIFIWPAADAPTER_H
#define WIFIWPAADAPTER_H

#include <QObject>
#include <QLoggingCategory>

// in a header
Q_DECLARE_LOGGING_CATEGORY(wifiWPAAdapter)

class WifiWPAAdapterPrivate;
class WifiWPAAdapter : public QObject
{
    Q_OBJECT
public:
    explicit WifiWPAAdapter(QObject *parent = nullptr);
    ~WifiWPAAdapter();

signals:

public slots:
    bool select(const QString &iface);
    bool connect();
    bool disconnect();
    void saveConfig();
    void ping();
    void scan();

private:
    Q_DECLARE_PRIVATE(WifiWPAAdapter)
    WifiWPAAdapterPrivate *d_ptr;

};

#endif // WIFIWPAADAPTER_H
