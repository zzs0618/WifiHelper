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

#ifndef WIFIDBUSSERVICE_H
#define WIFIDBUSSERVICE_H

#include <QThread>

class WifiDbusService : public QThread
{
    Q_OBJECT
public:
    explicit WifiDbusService(QObject *parent = nullptr);

public slots:
    virtual void run() Q_DECL_OVERRIDE;
};

#endif // WIFIDBUSSERVICE_H
