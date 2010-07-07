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

void run_packettor (void *arg) {
Packettor *p = (Packettor *)arg;

p->run();

}
Packettor::Packettor(void) {
printf("Initializing packet capture\n");
done = false;
max_data_len = 1500;
t =thread(run_packettor, this);

}

Packettor::~Packettor(void) {
printf("Deinitialzing packet capture\n");
t.join();
}

int Packettor::add_interface(char *iface) {
    pcap = Pcap();
    pcap.init_device(iface, 1, max_data_len);

}
void Packettor::run(void) {

    while (!done) {

    }

}