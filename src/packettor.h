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

/*
 * This is our packet capture engine. it runs in parallel thread and uses usi++'s datalink singleton
 *
 */
#ifndef PAKETTOR_H
#define PAKETTOR_H

#include "xprobe.h"
#include "usi++/tinythread.h"
#include "usi++/datalink.h"

using namespace tthread;
using namespace usipp;

class Packettor:public Runable {
private:
    /* singleton */
    Packettor(void);
    mutable bool initialized;
    mutable bool done;
    int max_data_len;
    Pcap pcap;
    ThreadRunner tr;
    mutable mutex mDataMutex; // serialize access to data
    static Packettor _instance;

public:
    ~Packettor(void);
    static Packettor &instance();
    void run(void);
    void init(void);
    int add_interface(char *);
    void stop(void);


};

#endif
