/* $Id$ */
/*
** Copyright (C) 2001-2010 Fyodor Yarochkin <fygrave@o0o.nu>,
**                    Ofir Arkin       <ofir@sys-security.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "packettor.h"


using namespace std;
using namespace tthread;
using namespace usipp;


Packettor Packettor::_instance;

Packettor &Packettor::instance() {
    return _instance;
}
Packettor::Packettor(void) {
    cout << "Packettor constructed\n";
}
void Packettor::init(void) {
   cout << "Packet capture thread started\n";
    done = false;
    initialized = false;
    max_data_len = 1500;
    //tr.startThread(this);
}

Packettor::~Packettor(void) {
    stop();
}
void Packettor::stop(void) {
    cout << "Deinitialzing packet capture\n";
    mDataMutex.lock();
    done = true;
    mDataMutex.unlock();
    cout << "joining threads\n";
    tr.join();
}

int Packettor::add_interface(char *iface) {
    mDataMutex.lock();
    pcap = Pcap();
    cout << "Adding interface " << iface << "\n";
    pcap.init_device(iface, 1, max_data_len);
    initialized = true;
    mDataMutex.unlock();
    return 0;
}
void Packettor::run(void) {
    char buf[1500];
    cout << "Run thread started\n";
    while (!done) {
        if (initialized == true) {
            cout << "got sniff packet\n";
            //pcap.sniffpack(buf, sizeof(buf));
        }
        cout << "sleeping\n";
        if (initialized == true) {
            cout << "initialized true\n";
        } else {
            cout << "initialized false\n";
        }
        sleep(1);

    }
    cout << "run thread done\n";

}
